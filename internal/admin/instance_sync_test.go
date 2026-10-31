package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

const (
	syncTestSourceToken = "source-admin-token-123456"
	syncTestRemoteToken = "remote-admin-token-123456"
)

func newSyncTestRemote(t *testing.T) (*Handler, string) {
	t.Helper()
	remote := newAuthTestHandler(t, config.Config{AdminToken: syncTestRemoteToken})
	server := httptest.NewServer(remote)
	t.Cleanup(server.Close)
	return remote, server.URL
}

func mustDispatch(t *testing.T, h *Handler, action string, body map[string]any) map[string]any {
	t.Helper()
	result, _ := h.dispatch(context.Background(), "admin", action, body)
	if result["ok"] != true {
		t.Fatalf("%s failed: %v", action, result)
	}
	return result
}

func addSyncTestTarget(t *testing.T, source *Handler, name, url, token string) string {
	t.Helper()
	result := mustDispatch(t, source, "sync.target.save", map[string]any{"target": map[string]any{"name": name, "url": url, "token": token}})
	return result["target"].(syncTargetView).ID
}

func syncTestResult(t *testing.T, source *Handler, action string, body map[string]any) syncTargetResult {
	t.Helper()
	result := mustDispatch(t, source, action, body)
	results := result["results"].([]syncTargetResult)
	if len(results) != 1 {
		t.Fatalf("results = %+v, want one target", results)
	}
	return results[0]
}

func remoteNodeNames(t *testing.T, remote *Handler) []string {
	t.Helper()
	nodes, err := remote.store.ListNodes(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, node := range nodes {
		names = append(names, node.Name)
	}
	slices.Sort(names)
	return names
}

func TestInstanceSyncPreviewAndApply(t *testing.T) {
	ctx := context.Background()
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	remote, remoteURL := newSyncTestRemote(t)

	mustDispatch(t, source, "import", map[string]any{"nodes": []any{
		map[string]any{"name": "n1", "target": "https://a.example.com", "note": "中文备注"},
		map[string]any{"name": "n2", "target": "https://b.example.com", "secret": "sec2"},
		map[string]any{"name": "n3", "target": "https://c.example.com", "impersonate": true},
	}})
	mustDispatch(t, remote, "import", map[string]any{"nodes": []any{
		map[string]any{"name": "n1", "target": "https://a.example.com", "note": "中文备注"},
		map[string]any{"name": "n2", "target": "https://old.example.com", "secret": "sec2"},
		map[string]any{"name": "x9", "target": "https://x.example.com"},
	}})
	mustDispatch(t, source, "config.set", map[string]any{"config": map[string]any{"logLevel": "debug", "trustProxy": true, "imageCacheEnabled": true}})
	mustDispatch(t, remote, "config.set", map[string]any{"config": map[string]any{"trustProxy": false}})
	mustDispatch(t, source, "tg.set", map[string]any{"config": map[string]any{"enabled": true, "token": "123:abc", "chat": "42", "serverRemark": "A", "reportTime": "08:30"}})
	mustDispatch(t, remote, "tg.set", map[string]any{"config": map[string]any{"serverRemark": "B"}})
	wantConfig, err := remote.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantTG, err := remote.store.GetTGConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}

	id := addSyncTestTarget(t, source, "remote", remoteURL+"/admin/", syncTestRemoteToken)
	// Stale clients may still send these flags; they must never enable settings synchronization.
	body := map[string]any{"ids": []any{id}, "prune": true, "includeConfig": true, "includeTelegram": true}

	preview := syncTestResult(t, source, "sync.preview", body)
	if !preview.OK || !slices.Equal(preview.Added, []string{"n3"}) || !slices.Equal(preview.Deleted, []string{"x9"}) || preview.Unchanged != 1 {
		t.Fatalf("preview = %+v", preview)
	}
	if preview.Completed != (syncCompleted{}) {
		t.Fatalf("preview claims completed operations: %+v", preview.Completed)
	}
	if len(preview.Updated) != 1 || preview.Updated[0].Name != "n2" || !slices.Equal(preview.Updated[0].Fields, []string{"target"}) {
		t.Fatalf("preview updated = %+v", preview.Updated)
	}
	if got := remoteNodeNames(t, remote); !slices.Equal(got, []string{"n1", "n2", "x9"}) {
		t.Fatalf("preview changed remote nodes: %v", got)
	}

	applied := syncTestResult(t, source, "sync.run", body)
	if !applied.OK || applied.Completed != (syncCompleted{Added: 1, Updated: 1, Deleted: 1}) {
		t.Fatalf("run = %+v", applied)
	}
	if got := remoteNodeNames(t, remote); !slices.Equal(got, []string{"n1", "n2", "n3"}) {
		t.Fatalf("remote nodes = %v", got)
	}
	n2, err := remote.store.GetNode(ctx, "admin", "n2")
	if err != nil || n2 == nil || n2.Target != "https://b.example.com" {
		t.Fatalf("remote n2 = %+v, %v", n2, err)
	}
	cfg, err := remote.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
	if err != nil || cfg != wantConfig {
		t.Fatalf("remote system config = %+v, %v", cfg, err)
	}
	tg, err := remote.store.GetTGConfig(ctx)
	if err != nil || tg != wantTG {
		t.Fatalf("remote telegram = %+v, %v", tg, err)
	}

	again := syncTestResult(t, source, "sync.preview", body)
	if !again.OK || len(again.Added)+len(again.Updated)+len(again.Deleted) != 0 || again.Unchanged != 3 {
		t.Fatalf("second preview = %+v", again)
	}
}

func TestInstanceSyncUnconfiguredSourcePreservesRemoteSettings(t *testing.T) {
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	remote, remoteURL := newSyncTestRemote(t)
	mustDispatch(t, remote, "config.set", map[string]any{"config": map[string]any{"logLevel": "debug", "imageCacheEnabled": true}})
	mustDispatch(t, remote, "tg.set", map[string]any{"config": map[string]any{"enabled": true, "token": "target-bot-token", "chat": "42", "serverRemark": "B", "reportTime": "08:30"}})
	ctx := context.Background()
	wantConfig, err := remote.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantTG, err := remote.store.GetTGConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := addSyncTestTarget(t, source, "remote", remoteURL, syncTestRemoteToken)
	for _, action := range []string{"sync.preview", "sync.run"} {
		result := syncTestResult(t, source, action, map[string]any{"ids": []any{id}, "includeConfig": true, "includeTelegram": true})
		if !result.OK {
			t.Fatalf("%s = %+v", action, result)
		}
		gotConfig, err := remote.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
		if err != nil || gotConfig != wantConfig {
			t.Fatalf("%s changed target system config: %+v, %v", action, gotConfig, err)
		}
		gotTG, err := remote.store.GetTGConfig(ctx)
		if err != nil || gotTG != wantTG {
			t.Fatalf("%s changed target notifications: %+v, %v", action, gotTG, err)
		}
	}
}

func TestInstanceSyncAbortsBeforeRemoteCallsOnIncompleteSource(t *testing.T) {
	for _, corrupt := range []bool{true, false} {
		t.Run(fmt.Sprint(corrupt), func(t *testing.T) {
			ctx := context.Background()
			source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
			remote, remoteURL := newSyncTestRemote(t)
			for _, h := range []*Handler{source, remote} {
				mustDispatch(t, h, "import", map[string]any{"nodes": []any{
					map[string]any{"name": "healthy", "target": "https://a.example.com"},
					map[string]any{"name": "broken", "target": "https://b.example.com"},
				}})
			}
			// Warm the best-effort cache; sync must still read and validate storage.
			if _, err := source.store.ListNodes(ctx, "admin"); err != nil {
				t.Fatal(err)
			}
			id := addSyncTestTarget(t, source, "remote", remoteURL, syncTestRemoteToken)
			if corrupt {
				if err := source.store.KV().Put(ctx, "u:admin:node:broken", `{broken`); err != nil {
					t.Fatal(err)
				}
				if _, err := source.buildSyncSource(ctx, "admin"); !errors.Is(err, storage.ErrInvalidNodeSnapshot) {
					t.Fatalf("error = %v", err)
				}
			} else {
				if _, err := source.store.DB().Exec(`ALTER TABLE proxy_kv RENAME TO unreadable`); err != nil {
					t.Fatal(err)
				}
			}
			for _, action := range []string{"sync.preview", "sync.run"} {
				result, _ := source.dispatch(ctx, "admin", action, map[string]any{"ids": []any{id}, "prune": true})
				if result["ok"] == true {
					t.Fatalf("%s accepted incomplete source", action)
				}
			}
			if got := remoteNodeNames(t, remote); !slices.Equal(got, []string{"broken", "healthy"}) {
				t.Fatalf("remote nodes = %v", got)
			}
		})
	}
}

func TestInstanceSyncReportsAuthenticationProblems(t *testing.T) {
	ctx := context.Background()
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	mustDispatch(t, source, "import", map[string]any{"nodes": []any{map[string]any{"name": "n1", "target": "https://a.example.com"}}})

	_, wrongTokenURL := newSyncTestRemote(t)
	twoFactorRemote, twoFactorURL := newSyncTestRemote(t)
	// Only the presence of a 2FA config matters: an empty code is rejected before decryption.
	if err := twoFactorRemote.store.SaveAdmin2FAConfig(ctx, storage.Admin2FAConfig{Version: 1}); err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewServer(http.RedirectHandler("https://elsewhere.example/", http.StatusMovedPermanently))
	t.Cleanup(redirect.Close)

	tests := []struct {
		name  string
		url   string
		token string
		want  string
	}{
		{name: "wrong token", url: wrongTokenURL, token: "not-the-remote-token", want: "Token 错误"},
		{name: "two factor", url: twoFactorURL, token: syncTestRemoteToken, want: "2FA"},
		{name: "redirect", url: redirect.URL, token: syncTestRemoteToken, want: "重定向"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := addSyncTestTarget(t, source, tt.name, tt.url, tt.token)
			result := syncTestResult(t, source, "sync.preview", map[string]any{"ids": []any{id}})
			if result.OK || !strings.Contains(result.Error, tt.want) {
				t.Fatalf("result = %+v, want error containing %q", result, tt.want)
			}
		})
	}
}

func TestSyncTargetTokenStorage(t *testing.T) {
	ctx := context.Background()
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	id := addSyncTestTarget(t, source, "remote", "https://remote.example.com", syncTestRemoteToken)

	raw, _, err := source.store.KV().Get(ctx, "sync:targets")
	if err != nil || strings.Contains(raw, syncTestRemoteToken) {
		t.Fatalf("stored targets expose the token: %s, %v", raw, err)
	}
	list := mustDispatch(t, source, "sync.targets", nil)
	views := list["targets"].([]syncTargetView)
	if len(views) != 1 || !views[0].TokenReadable || views[0].URL != "https://remote.example.com" {
		t.Fatalf("targets = %+v", views)
	}

	// Editing without a token keeps the stored one.
	mustDispatch(t, source, "sync.target.save", map[string]any{"target": map[string]any{"id": id, "name": "renamed", "url": "https://remote.example.com"}})
	targets, err := source.store.GetSyncTargets(ctx)
	if err != nil || len(targets) != 1 || targets[0].Name != "renamed" {
		t.Fatalf("targets = %+v, %v", targets, err)
	}
	if token, err := openSyncToken(syncTestSourceToken, targets[0]); err != nil || token != syncTestRemoteToken {
		t.Fatalf("token = %q, %v", token, err)
	}

	if result, _ := source.dispatch(ctx, "admin", "sync.target.save", map[string]any{"target": map[string]any{"name": "RENAMED", "url": "https://x.example.com", "token": "t"}}); result["ok"] == true {
		t.Fatal("duplicate target name accepted")
	}

	// A rotated ADMIN_TOKEN cannot decrypt the stored token.
	rotated := New(config.Config{AdminToken: "rotated-admin-token-123456"}, source.store, nil, nil, nil, nil)
	views = mustDispatch(t, rotated, "sync.targets", nil)["targets"].([]syncTargetView)
	if len(views) != 1 || views[0].TokenReadable {
		t.Fatalf("rotated targets = %+v", views)
	}
	result := syncTestResult(t, rotated, "sync.preview", map[string]any{"ids": []any{id}})
	if result.OK || !strings.Contains(result.Error, "无法解密") {
		t.Fatalf("rotated preview = %+v", result)
	}

	mustDispatch(t, source, "sync.target.delete", map[string]any{"id": id})
	if targets, _ := source.store.GetSyncTargets(ctx); len(targets) != 0 {
		t.Fatalf("targets after delete = %+v", targets)
	}
}

func TestInstanceSyncLocalHostnameWithoutAuthorization(t *testing.T) {
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	remote, remoteURL := newSyncTestRemote(t)
	mustDispatch(t, source, "import", map[string]any{"nodes": []any{map[string]any{"name": "n1", "target": "https://media.example.com"}}})
	id := addSyncTestTarget(t, source, "local", strings.Replace(remoteURL, "127.0.0.1", "localhost", 1), syncTestRemoteToken)
	for _, action := range []string{"sync.preview", "sync.run"} {
		if result := syncTestResult(t, source, action, map[string]any{"ids": []any{id}}); !result.OK {
			t.Fatalf("%s to localhost failed: %+v", action, result)
		}
	}
	if got := remoteNodeNames(t, remote); !slices.Equal(got, []string{"n1"}) {
		t.Fatalf("remote nodes = %v", got)
	}
}

func TestNormalizeSyncTargetURL(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{in: "https://ep.example.com", want: "https://ep.example.com", ok: true},
		{in: " https://ep.example.com/admin/ ", want: "https://ep.example.com", ok: true},
		{in: "http://192.168.1.2:8787/", want: "http://192.168.1.2:8787", ok: true},
		{in: "https://ep.example.com/prefix/admin", want: "https://ep.example.com/prefix", ok: true},
		{in: "ep.example.com"},
		{in: "ftp://ep.example.com"},
		{in: "https://user:pass@ep.example.com"},
		{in: "https://ep.example.com/?a=1"},
		{in: ""},
	}
	for _, tt := range tests {
		got, errText := normalizeSyncTargetURL(tt.in)
		if (errText == "") != tt.ok || got != tt.want {
			t.Errorf("normalizeSyncTargetURL(%q) = %q, %q", tt.in, got, errText)
		}
	}
}

func TestInstanceSyncUI(t *testing.T) {
	node, err := exec.LookPath("node")
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("Node.js is required for UI tests")
	}
	if err != nil {
		t.Fatal(err)
	}
	// Stat the script so Go's test cache invalidates when it changes; node reads it in a subprocess.
	const script = "testdata/instance_sync_test.cjs"
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, node, "--test", script).CombinedOutput(); err != nil {
		t.Fatalf("UI tests failed: %v\n%s", err, output)
	}
}

func TestInstanceSyncRequiresSelectedTarget(t *testing.T) {
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	result, _ := source.dispatch(context.Background(), "admin", "sync.preview", map[string]any{"ids": []any{"missing"}})
	if result["ok"] == true {
		t.Fatalf("result = %+v, want failure without targets", result)
	}
}
