package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"embyproxy/internal/auth"
	"embyproxy/internal/config"
)

func TestInstanceSyncSubpathPreviewApplyAndLogout(t *testing.T) {
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	target := newAuthTestHandler(t, config.Config{AdminToken: syncTestRemoteToken})
	const prefix = "/services/embyproxy"
	sessions := make(chan *http.Cookie, 2)
	stripped := http.StripPrefix(prefix, target)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == prefix+"/admin/auth/logout" {
			cookie, err := r.Cookie(auth.SessionCookieName)
			if err != nil {
				t.Error("logout is missing its session cookie")
			} else {
				sessions <- cookie
			}
		}
		stripped.ServeHTTP(w, r)
	}))
	defer server.Close()
	mustDispatch(t, source, "import", map[string]any{"node": map[string]any{"name": "n1", "target": "https://media.example.com"}})
	mustDispatch(t, target, "import", map[string]any{"node": map[string]any{"name": "extra", "target": "https://extra.example.com"}})
	id := addSyncTestTarget(t, source, "subpath", server.URL+prefix+"/admin/", syncTestRemoteToken)
	body := map[string]any{"ids": []any{id}, "prune": true}

	preview := syncTestResult(t, source, "sync.preview", body)
	if !preview.OK || !slices.Equal(preview.Added, []string{"n1"}) || !slices.Equal(preview.Deleted, []string{"extra"}) {
		t.Fatalf("preview = %+v", preview)
	}
	if got := remoteNodeNames(t, target); !slices.Equal(got, []string{"extra"}) {
		t.Fatalf("preview changed target: %v", got)
	}
	applied := syncTestResult(t, source, "sync.run", body)
	if !applied.OK || applied.Completed != (syncCompleted{Added: 1, Deleted: 1}) {
		t.Fatalf("run = %+v", applied)
	}
	if got := remoteNodeNames(t, target); !slices.Equal(got, []string{"n1"}) {
		t.Fatalf("target nodes = %v", got)
	}
	for range 2 {
		select {
		case cookie := <-sessions:
			req := httptest.NewRequest(http.MethodGet, "/admin/auth/status", nil)
			req.AddCookie(cookie)
			if target.checker.Check(req).OK {
				t.Fatal("sync session remains active after logout")
			}
		default:
			t.Fatal("sync did not log out with its session")
		}
	}
}

func TestInstanceSyncLargeValidNodesUseByteLimitedBatches(t *testing.T) {
	source := newAuthTestHandler(t, config.Config{AdminToken: syncTestSourceToken})
	target := newAuthTestHandler(t, config.Config{AdminToken: syncTestRemoteToken})
	imports := make(chan int, syncImportBatchSize)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/api" {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if body["action"] == "import" {
				if len(raw) > syncMaxRequestBytes || len(body["nodes"].([]any)) > syncImportBatchSize {
					t.Errorf("oversized import: %d bytes", len(raw))
				}
				imports <- len(raw)
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		target.ServeHTTP(w, r)
	}))
	defer server.Close()

	urls := make([]string, 20)
	for i := range urls {
		base := fmt.Sprintf("https://media%d.example.com/path?", i)
		query := strings.Repeat("x=y&", 25)
		urls[i] = base + query + "token=" + strings.Repeat("a", 2048-len(base)-len(query)-len("token="))
	}
	items := make([]any, syncImportBatchSize)
	for i := range items {
		items[i] = map[string]any{"name": fmt.Sprintf("n%d", i), "target": strings.Join(urls, "\n")}
	}
	for _, raw := range mustDispatch(t, source, "import", map[string]any{"nodes": items})["results"].([]map[string]any) {
		if raw["ok"] != true {
			t.Fatalf("source node was not valid: %v", raw)
		}
	}
	src, err := source.buildSyncSource(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	all := make([]map[string]any, 0, len(src.order))
	for _, name := range src.order {
		all = append(all, src.nodes[name])
	}
	raw, err := json.Marshal(map[string]any{"action": "import", "nodes": all})
	if err != nil || len(raw) <= syncMaxRequestBytes {
		t.Fatalf("regression fixture must exceed one request: bytes=%d, error=%v", len(raw), err)
	}
	mustDispatch(t, target, "import", map[string]any{"node": map[string]any{"name": "extra", "target": "https://extra.example.com"}})
	id := addSyncTestTarget(t, source, "large", server.URL, syncTestRemoteToken)
	body := map[string]any{"ids": []any{id}, "prune": true}
	applied := syncTestResult(t, source, "sync.run", body)
	if !applied.OK || applied.Completed != (syncCompleted{Added: len(items), Deleted: 1}) || len(imports) != 2 {
		t.Fatalf("run = %+v, import batches = %d", applied, len(imports))
	}
	if got := remoteNodeNames(t, target); len(got) != len(items) {
		t.Fatalf("target has %d nodes, want %d", len(got), len(items))
	}
	preview := syncTestResult(t, source, "sync.preview", body)
	if !preview.OK || preview.Unchanged != len(items) || len(preview.Added)+len(preview.Updated)+len(preview.Deleted) != 0 {
		t.Fatalf("synced data differs from source: %+v", preview)
	}
}
