package admin

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"embyproxy/internal/auth"
	"embyproxy/internal/buildinfo"
	"embyproxy/internal/storage"
	"embyproxy/internal/validators"

	"golang.org/x/crypto/argon2"
)

// Multi-instance sync pushes only local nodes to other
// EmbyProxy instances through their admin API. Targets with enforced 2FA are not supported.

const (
	syncMaxTargets        = 20
	syncNameMaxRunes      = 32
	syncURLMaxLength      = 255
	syncTokenMaxLength    = 512
	syncRequestTimeout    = 20 * time.Second
	syncTargetTimeout     = 50 * time.Second
	syncLogoutTimeout     = 5 * time.Second
	syncMaxRequestBytes   = 4 << 20 // matches the admin API request body limit on targets
	syncMaxResponseBytes  = 32 << 20
	syncImportBatchSize   = 100
	syncTokenEnvelopeV1   = 1
	syncTokenAAD          = "embyproxy:sync-target-token:v1:"
	syncTokenSaltSize     = 16
	syncArgonIterations   = 2
	syncArgonMemoryKiB    = 32 * 1024
	syncArgonParallelism  = 2
	syncEncryptionKeySize = 32
)

type syncTargetView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	TokenReadable bool   `json:"tokenReadable"`
}

type syncOptions struct {
	Apply bool
	Prune bool
}

// syncSource is the local snapshot pushed to every target, in the same generic JSON form
// that decoding a remote response produces, so values compare directly.
type syncSource struct {
	order []string
	nodes map[string]map[string]any
}

type syncNodeUpdate struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

type syncImportFailure struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

// Plans and confirmed operations are separate: a response lost in transit may
// leave an operation unconfirmed even if the target performed it.
type syncCompleted struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Deleted int `json:"deleted"`
}

var (
	errInvalidSyncResponse = errors.New("目标同步响应不完整或格式无效")
	errSyncImportFailed    = errors.New("目标存在节点导入失败")
	errSyncRequestTooLarge = errors.New("请求体超过目标 4MiB 的限制")
)

type syncTargetResult struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	OK             bool                `json:"ok"`
	Error          string              `json:"error,omitempty"`
	Added          []string            `json:"added"`
	Updated        []syncNodeUpdate    `json:"updated"`
	Deleted        []string            `json:"deleted"`
	Unchanged      int                 `json:"unchanged"`
	Completed      syncCompleted       `json:"completed"`
	ImportFailures []syncImportFailure `json:"importFailures,omitempty"`
	PruneSkipped   bool                `json:"pruneSkipped,omitempty"`
}

func (h *Handler) listSyncTargets(ctx context.Context) map[string]any {
	targets, err := h.store.GetSyncTargets(ctx)
	if err != nil {
		return fail(err.Error())
	}
	views := make([]syncTargetView, 0, len(targets))
	for _, target := range targets {
		_, err := openSyncToken(h.cfg.AdminToken, target)
		views = append(views, syncTargetView{ID: target.ID, Name: target.Name, URL: target.URL, TokenReadable: err == nil})
	}
	return map[string]any{"ok": true, "targets": views}
}

func (h *Handler) saveSyncTarget(ctx context.Context, body map[string]any) map[string]any {
	if errText := auth.ValidateAdminToken(h.cfg.AdminToken); errText != "" {
		return fail(errText)
	}
	input := mapFromAny(body["target"])
	if input == nil {
		input = body
	}
	id := strings.TrimSpace(asString(input["id"]))
	name, errText := normalizeSyncTargetName(asString(input["name"]))
	if errText != "" {
		return fail(errText)
	}
	baseURL, errText := normalizeSyncTargetURL(asString(input["url"]))
	if errText != "" {
		return fail(errText)
	}
	token := strings.TrimSpace(asString(input["token"]))
	if len(token) > syncTokenMaxLength {
		return fail("Token 过长")
	}

	h.syncTargetsMu.Lock()
	defer h.syncTargetsMu.Unlock()
	targets, err := h.store.GetSyncTargets(ctx)
	if err != nil {
		return fail(err.Error())
	}
	index := -1
	for i, target := range targets {
		if id != "" && target.ID == id {
			index = i
			continue
		}
		if strings.EqualFold(target.Name, name) {
			return fail("目标名称已存在")
		}
	}
	if id != "" && index < 0 {
		return fail("目标不存在，请刷新后重试")
	}
	if index < 0 {
		if len(targets) >= syncMaxTargets {
			return fail(fmt.Sprintf("最多只能添加 %d 个同步目标", syncMaxTargets))
		}
		if token == "" {
			return fail("请填写目标实例的 ADMIN_TOKEN")
		}
		newID, err := randomSyncTargetID()
		if err != nil {
			return fail(err.Error())
		}
		targets = append(targets, storage.SyncTarget{ID: newID})
		index = len(targets) - 1
	}
	target := &targets[index]
	target.Name = name
	target.URL = baseURL
	// An empty token while editing keeps the stored one; tokens are never sent back to the page.
	if token != "" {
		if err := sealSyncToken(h.cfg.AdminToken, token, target); err != nil {
			return fail(err.Error())
		}
	}
	if err := h.store.SaveSyncTargets(ctx, targets); err != nil {
		return fail(err.Error())
	}
	_, openErr := openSyncToken(h.cfg.AdminToken, *target)
	return map[string]any{"ok": true, "target": syncTargetView{ID: target.ID, Name: target.Name, URL: target.URL, TokenReadable: openErr == nil}}
}

func (h *Handler) deleteSyncTarget(ctx context.Context, body map[string]any) map[string]any {
	id := strings.TrimSpace(asString(body["id"]))
	h.syncTargetsMu.Lock()
	defer h.syncTargetsMu.Unlock()
	targets, err := h.store.GetSyncTargets(ctx)
	if err != nil {
		return fail(err.Error())
	}
	kept := make([]storage.SyncTarget, 0, len(targets))
	for _, target := range targets {
		if target.ID != id {
			kept = append(kept, target)
		}
	}
	if len(kept) == len(targets) {
		return fail("目标不存在，请刷新后重试")
	}
	if err := h.store.SaveSyncTargets(ctx, kept); err != nil {
		return fail(err.Error())
	}
	return ok()
}

func normalizeSyncTargetName(value string) (string, string) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", "请填写目标名称"
	}
	if utf8.RuneCountInString(name) > syncNameMaxRunes {
		return "", fmt.Sprintf("目标名称不能超过 %d 个字符", syncNameMaxRunes)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", "目标名称不能包含控制字符"
	}
	return name, ""
}

func normalizeSyncTargetURL(value string) (string, string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", "请填写目标地址"
	}
	if len(raw) > syncURLMaxLength {
		return "", "目标地址过长"
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "目标地址需以 http:// 或 https:// 开头"
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", "目标地址不能包含账号、查询参数或锚点"
	}
	// Accept the admin page URL that users usually copy from the browser.
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/admin")
	u.RawPath = ""
	return u.String(), ""
}

func randomSyncTargetID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// syncTokenCipher derives the token encryption key from ADMIN_TOKEN, so a leaked database
// alone does not reveal remote tokens. Rotating ADMIN_TOKEN makes stored tokens unreadable.
func syncTokenCipher(adminToken string, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(strings.TrimSpace(adminToken)), salt, syncArgonIterations, syncArgonMemoryKiB, syncArgonParallelism, syncEncryptionKeySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealSyncToken(adminToken, token string, target *storage.SyncTarget) error {
	salt := make([]byte, syncTokenSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := syncTokenCipher(adminToken, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// Binding the target ID prevents moving a ciphertext to another target.
	ciphertext := aead.Seal(nil, nonce, []byte(token), []byte(syncTokenAAD+target.ID))
	target.TokenVersion = syncTokenEnvelopeV1
	target.TokenSalt = base64.RawStdEncoding.EncodeToString(salt)
	target.TokenNonce = base64.RawStdEncoding.EncodeToString(nonce)
	target.TokenCiphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
	return nil
}

func openSyncToken(adminToken string, target storage.SyncTarget) (string, error) {
	if target.TokenVersion != syncTokenEnvelopeV1 {
		return "", errors.New("unsupported token envelope")
	}
	salt, err := base64.RawStdEncoding.DecodeString(target.TokenSalt)
	if err != nil || len(salt) != syncTokenSaltSize {
		return "", errors.New("invalid token salt")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(target.TokenNonce)
	if err != nil {
		return "", errors.New("invalid token nonce")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(target.TokenCiphertext)
	if err != nil || len(ciphertext) == 0 {
		return "", errors.New("invalid token ciphertext")
	}
	aead, err := syncTokenCipher(adminToken, salt)
	if err != nil {
		return "", err
	}
	if len(nonce) != aead.NonceSize() {
		return "", errors.New("invalid token nonce size")
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(syncTokenAAD+target.ID))
	if err != nil {
		return "", errors.New("decrypt token failed")
	}
	return string(plain), nil
}

// runInstanceSync previews (apply=false) or applies the sync to the selected targets.
func (h *Handler) runInstanceSync(ctx context.Context, uid string, body map[string]any, apply bool) map[string]any {
	if !h.syncRunMu.TryLock() {
		return fail("已有同步任务正在进行，请稍后再试")
	}
	defer h.syncRunMu.Unlock()
	if errText := auth.ValidateAdminToken(h.cfg.AdminToken); errText != "" {
		return fail(errText)
	}
	opts := syncOptions{
		Apply: apply,
		Prune: validators.ToBool(body["prune"]),
	}
	targets, err := h.store.GetSyncTargets(ctx)
	if err != nil {
		return fail(err.Error())
	}
	wanted := map[string]bool{}
	for _, id := range arrayStrings(body["ids"]) {
		wanted[id] = true
	}
	selected := make([]storage.SyncTarget, 0, len(targets))
	for _, target := range targets {
		if wanted[target.ID] {
			selected = append(selected, target)
		}
	}
	if len(selected) == 0 {
		return fail("请至少选择一个同步目标")
	}
	src, err := h.buildSyncSource(ctx, uid)
	if err != nil {
		return fail(err.Error())
	}
	if opts.Prune && len(src.order) == 0 {
		return fail("本机没有节点，不能删除目标上的节点")
	}
	if apply {
		// Finish an applied sync even if the browser disconnects; per-target timeouts still apply.
		ctx = context.WithoutCancel(ctx)
	}

	results := make([]syncTargetResult, len(selected))
	var wg sync.WaitGroup
	for i, target := range selected {
		// Decrypt sequentially: every key derivation allocates 32 MiB.
		token, err := openSyncToken(h.cfg.AdminToken, target)
		if err != nil {
			results[i] = newSyncTargetResult(target)
			results[i].Error = "Token 无法解密（ADMIN_TOKEN 可能已更换），请重新填写"
			continue
		}
		wg.Go(func() {
			results[i] = syncToTarget(ctx, target, token, src, opts)
		})
	}
	wg.Wait()
	if apply && h.log != nil {
		for _, result := range results {
			h.log.Info("sync", "instance sync applied", map[string]any{
				"target": result.Name, "ok": result.OK, "error": result.Error,
				"added": result.Completed.Added, "updated": result.Completed.Updated, "deleted": result.Completed.Deleted,
				"plannedAdded": len(result.Added), "plannedUpdated": len(result.Updated), "plannedDeleted": len(result.Deleted),
				"pruneSkipped": result.PruneSkipped,
			})
		}
	}
	return map[string]any{"ok": true, "applied": apply, "results": results}
}

func (h *Handler) buildSyncSource(ctx context.Context, uid string) (syncSource, error) {
	nodes, err := h.store.ListNodesSnapshot(ctx, uid)
	if err != nil {
		return syncSource{}, err
	}
	src := syncSource{nodes: map[string]map[string]any{}}
	for _, node := range nodes {
		obj, err := jsonObject(exportNode(node))
		if err != nil {
			return syncSource{}, err
		}
		if validated := validators.ValidateNodeInput(obj); validated.Error != "" {
			return syncSource{}, fmt.Errorf("%w: %s: %s", storage.ErrInvalidNodeSnapshot, node.Name, validated.Error)
		}
		name := node.Name
		src.order = append(src.order, name)
		src.nodes[name] = obj
	}
	return src, nil
}

// jsonObject converts a value into the generic form produced by decoding JSON.
func jsonObject(value any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func newSyncTargetResult(target storage.SyncTarget) syncTargetResult {
	return syncTargetResult{ID: target.ID, Name: target.Name, Added: []string{}, Updated: []syncNodeUpdate{}, Deleted: []string{}}
}

func syncToTarget(ctx context.Context, target storage.SyncTarget, token string, src syncSource, opts syncOptions) syncTargetResult {
	result := newSyncTargetResult(target)
	ctx, cancel := context.WithTimeout(ctx, syncTargetTimeout)
	defer cancel()
	remote := newSyncRemote(target)
	defer remote.client.CloseIdleConnections()
	if err := remote.login(ctx, token); err != nil {
		result.Error = err.Error()
		return result
	}
	defer remote.logout(ctx)

	if err := remote.syncNodes(ctx, src, opts, &result); err != nil {
		result.Error = err.Error()
		return result
	}
	result.OK = true
	return result
}

// changedSyncKeys returns the sorted node keys whose values differ on either side.
func changedSyncKeys(local, remote map[string]any) []string {
	keys := map[string]bool{}
	for key := range local {
		keys[key] = true
	}
	for key := range remote {
		keys[key] = true
	}
	changed := []string{}
	for key := range keys {
		if !reflect.DeepEqual(local[key], remote[key]) {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	return changed
}

type syncRemote struct {
	baseURL string
	client  *http.Client
}

func newSyncRemote(target storage.SyncTarget) *syncRemote {
	// cookiejar.New only fails for invalid options; nil options are always valid.
	jar, _ := cookiejar.New(nil)
	return &syncRemote{baseURL: target.URL, client: &http.Client{
		Jar:     jar,
		Timeout: syncRequestTimeout,
		// Target addresses are selected by the administrator; use normal DNS and dialing.
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: syncRequestTimeout}).DialContext,
			TLSHandshakeTimeout: syncRequestTimeout,
			IdleConnTimeout:     syncTargetTimeout,
			MaxIdleConnsPerHost: 1,
		},
		// Never follow redirects: a POST would turn into a GET or leave the configured host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (r *syncRemote) post(ctx context.Context, path string, payload map[string]any) (int, map[string]any, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	if len(raw) > syncMaxRequestBytes {
		return 0, nil, errSyncRequestTooLarge
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "EmbyProxy-Sync/"+buildinfo.Current().Version)
	res, err := r.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("连接失败：%w", err)
	}
	defer res.Body.Close()
	// A prefix-stripping proxy may leave the session's Path=/admin unchanged.
	// Map both login and logout cookies, removing the unprefixed entry that
	// http.Client already stored. Cookies rewritten by the proxy are left alone.
	if prefix := strings.TrimSuffix(req.URL.Path, path); prefix != "" && r.client.Jar != nil {
		for _, cookie := range res.Cookies() {
			if cookie.Name != auth.SessionCookieName || cookie.Path != "/admin" {
				continue
			}
			unprefixed := *cookie
			unprefixed.MaxAge = -1
			cookie.Path = prefix + "/admin"
			r.client.Jar.SetCookies(req.URL, []*http.Cookie{&unprefixed, cookie})
		}
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return res.StatusCode, nil, fmt.Errorf("目标返回重定向（HTTP %d），请检查地址是否正确（如 http 与 https）", res.StatusCode)
	}
	responseBody, err := io.ReadAll(io.LimitReader(res.Body, syncMaxResponseBytes+1))
	if err != nil {
		return res.StatusCode, nil, fmt.Errorf("read sync response: %w", err)
	}
	if len(responseBody) > syncMaxResponseBytes {
		return res.StatusCode, nil, fmt.Errorf("%w: 响应超过大小限制", errInvalidSyncResponse)
	}
	var data map[string]any
	if err := json.Unmarshal(responseBody, &data); err != nil {
		return res.StatusCode, nil, fmt.Errorf("%w (HTTP %d): %w", errInvalidSyncResponse, res.StatusCode, err)
	}
	if data == nil {
		return res.StatusCode, nil, errInvalidSyncResponse
	}
	return res.StatusCode, data, nil
}

func (r *syncRemote) login(ctx context.Context, token string) error {
	status, data, err := r.post(ctx, "/admin/auth/login", map[string]any{"token": token, "code": ""})
	if err != nil {
		return err
	}
	if status == http.StatusOK && data["ok"] == true {
		return nil
	}
	switch asString(data["error"]) {
	case auth.ErrorTOTPRequired:
		return errors.New("目标已启用 2FA，暂不支持同步")
	case auth.ErrorInvalidCredentials:
		return errors.New("Token 错误")
	case auth.ErrorTooManyRequests:
		return errors.New("目标认证失败次数过多，请稍后再试")
	}
	return fmt.Errorf("登录失败（HTTP %d）：%s", status, asString(data["error"]))
}

func (r *syncRemote) logout(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), syncLogoutTimeout)
	defer cancel()
	// Sessions expire on their own, so a failed logout is not reported.
	_, _, _ = r.post(ctx, "/admin/auth/logout", map[string]any{})
}

func (r *syncRemote) action(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	payload := map[string]any{"action": action}
	maps.Copy(payload, params)
	status, data, err := r.post(ctx, "/admin/api", payload)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || data["ok"] != true {
		return nil, fmt.Errorf("目标执行 %s 失败（HTTP %d）：%s", action, status, asString(data["error"]))
	}
	return data, nil
}

// syncImportBatches validates every node before any import is sent. Sizes include
// the request envelope, JSON escaping and separators, matching action/post encoding.
func syncImportBatches(nodes []map[string]any) ([][]map[string]any, error) {
	const envelopeBytes = len(`{"action":"import","nodes":[]}`)
	var batches [][]map[string]any
	start, size := 0, envelopeBytes
	for i, node := range nodes {
		raw, err := json.Marshal(node)
		if err != nil {
			return nil, fmt.Errorf("encode sync node %s: %w", asString(node["name"]), err)
		}
		if envelopeBytes+len(raw) > syncMaxRequestBytes {
			return nil, fmt.Errorf("%w: 节点 %s", errSyncRequestTooLarge, asString(node["name"]))
		}
		nextSize := size + len(raw)
		if i > start {
			nextSize++ // Comma between nodes.
		}
		if i-start == syncImportBatchSize || nextSize > syncMaxRequestBytes {
			batches = append(batches, nodes[start:i])
			start = i
			nextSize = envelopeBytes + len(raw)
		}
		size = nextSize
	}
	if start < len(nodes) {
		batches = append(batches, nodes[start:])
	}
	return batches, nil
}

func (r *syncRemote) syncNodes(ctx context.Context, src syncSource, opts syncOptions, result *syncTargetResult) error {
	data, err := r.action(ctx, "export", nil)
	if err != nil {
		return err
	}
	remoteNodes, err := syncExportNodes(data)
	if err != nil {
		return err
	}
	changed := []map[string]any{}
	for _, name := range src.order {
		local := src.nodes[name]
		remote, exists := remoteNodes[name]
		if !exists {
			result.Added = append(result.Added, name)
			changed = append(changed, local)
			continue
		}
		if fields := changedSyncKeys(local, remote); len(fields) > 0 {
			result.Updated = append(result.Updated, syncNodeUpdate{Name: name, Fields: fields})
			changed = append(changed, local)
			continue
		}
		result.Unchanged++
	}
	if opts.Prune {
		for name := range remoteNodes {
			if _, exists := src.nodes[name]; !exists {
				result.Deleted = append(result.Deleted, name)
			}
		}
		sort.Strings(result.Deleted)
	}
	if !opts.Apply {
		return nil
	}

	// Keep this set on every import error, including incomplete acknowledgements.
	result.PruneSkipped = len(result.Deleted) > 0
	batches, err := syncImportBatches(changed)
	if err != nil {
		return err
	}
	for _, batch := range batches {
		data, err := r.action(ctx, "import", map[string]any{"nodes": batch})
		if err != nil {
			return err
		}
		if err := acknowledgeSyncImports(data, batch, remoteNodes, result); err != nil {
			return err
		}
	}
	result.PruneSkipped = false
	// batchDelete in older targets ignores storage errors. The single delete API
	// propagates them, allowing us to count only confirmed successful deletions.
	for _, name := range result.Deleted {
		if _, err := r.action(ctx, "delete", map[string]any{"name": name}); err != nil {
			return err
		}
		result.Completed.Deleted++
	}
	return nil
}
