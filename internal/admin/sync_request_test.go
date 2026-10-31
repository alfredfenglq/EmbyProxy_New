package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"embyproxy/internal/auth"
	"embyproxy/internal/storage"
)

func TestSyncRemoteSessionCookiePaths(t *testing.T) {
	for _, tt := range []struct {
		name, prefix, cookiePath string
		secure                   bool
	}{
		{name: "root", cookiePath: "/admin"},
		{name: "prefix", prefix: "/proxy", cookiePath: "/admin"},
		{name: "nested prefix", prefix: "/outer/proxy", cookiePath: "/admin"},
		{name: "overlapping prefix", prefix: "/admin/proxy", cookiePath: "/admin"},
		{name: "proxy rewrites path", prefix: "/proxy", cookiePath: "/proxy/admin"},
		{name: "secure prefix", prefix: "/proxy", cookiePath: "/admin", secure: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie := &http.Cookie{
					Name: auth.SessionCookieName, Value: "test-session", Path: tt.cookiePath,
					HttpOnly: true, Secure: tt.secure, SameSite: http.SameSiteStrictMode,
				}
				switch r.URL.Path {
				case tt.prefix + "/admin/auth/login":
					http.SetCookie(w, cookie)
				case tt.prefix + "/admin/api", tt.prefix + "/admin/auth/logout":
					cookies := r.CookiesNamed(auth.SessionCookieName)
					if len(cookies) != 1 || cookies[0].Value != "test-session" {
						t.Errorf("session cookies for %s = %v", r.URL.Path, cookies)
					}
					if strings.HasSuffix(r.URL.Path, "/logout") {
						cookie.Value = ""
						cookie.MaxAge = -1
						http.SetCookie(w, cookie)
					}
				default:
					t.Errorf("unexpected request path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeJSON(w, http.StatusOK, ok())
			})
			server := httptest.NewUnstartedServer(handler)
			if tt.secure {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			remote := newSyncRemote(storage.SyncTarget{URL: server.URL + tt.prefix})
			defer remote.client.CloseIdleConnections()
			if tt.secure {
				// Go treats loopback as secure even over HTTP. Use a test hostname
				// while dialing only the local server to check the Secure flag.
				base, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				transport := remote.client.Transport.(*http.Transport)
				transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				transport.TLSClientConfig.ServerName = base.Hostname()
				transport.Proxy = nil
				transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				}
				base.Host = net.JoinHostPort("sync.example", base.Port())
				remote.baseURL = base.String() + tt.prefix
			}
			ctx := context.Background()
			if err := remote.login(ctx, "test-token"); err != nil {
				t.Fatal(err)
			}
			apiURL, err := url.Parse(remote.baseURL + "/admin/api")
			if err != nil {
				t.Fatal(err)
			}
			outsidePaths := []string{"/", "/other/admin", tt.prefix + "/admin-other"}
			if tt.prefix != "" {
				outsidePaths = append(outsidePaths, "/admin/api")
			}
			for _, path := range outsidePaths {
				outside := *apiURL
				outside.Path = path
				if cookies := remote.client.Jar.Cookies(&outside); len(cookies) != 0 {
					t.Fatalf("session escaped its target path %s: %v", path, cookies)
				}
			}
			if tt.secure {
				insecure := *apiURL
				insecure.Scheme = "http"
				if cookies := remote.client.Jar.Cookies(&insecure); len(cookies) != 0 {
					t.Fatalf("secure session became available over HTTP: %v", cookies)
				}
			}
			if _, err := remote.action(ctx, "export", nil); err != nil {
				t.Fatal(err)
			}
			remote.logout(ctx)
			if cookies := remote.client.Jar.Cookies(apiURL); len(cookies) != 0 {
				t.Fatalf("logout did not clear the scoped session: %v", cookies)
			}
		})
	}
}

func TestSyncImportBatchesLimits(t *testing.T) {
	many := make([]map[string]any, syncImportBatchSize+1)
	for i := range many {
		many[i] = map[string]any{"name": fmt.Sprintf("n%d", i)}
	}
	// The encoded ampersands alone nearly fill half a request per node.
	escaped := strings.Repeat("&", syncMaxRequestBytes/12) + "\n中文<>"
	exact := map[string]any{"name": "exact", "note": ""}
	empty, err := json.Marshal(map[string]any{"action": "import", "nodes": []map[string]any{exact}})
	if err != nil {
		t.Fatal(err)
	}
	exact["note"] = strings.Repeat("x", syncMaxRequestBytes-len(empty))

	for _, tt := range []struct {
		name  string
		nodes []map[string]any
		want  int
	}{
		{name: "empty", want: 0},
		{name: "count limit", nodes: many, want: 2},
		{name: "escaped bytes", nodes: []map[string]any{
			{"name": "first", "note": escaped}, {"name": "second", "note": escaped},
		}, want: 2},
		{name: "exact byte limit", nodes: []map[string]any{exact, {"name": "small"}}, want: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			batches, err := syncImportBatches(tt.nodes)
			if err != nil || len(batches) != tt.want {
				t.Fatalf("batches = %d, error = %v, want %d", len(batches), err, tt.want)
			}
			seen := 0
			for _, batch := range batches {
				raw, err := json.Marshal(map[string]any{"action": "import", "nodes": batch})
				if err != nil {
					t.Fatal(err)
				}
				if len(batch) == 0 || len(batch) > syncImportBatchSize || len(raw) > syncMaxRequestBytes {
					t.Fatalf("invalid batch: nodes=%d, bytes=%d", len(batch), len(raw))
				}
				if tt.name == "exact byte limit" && seen == 0 && len(raw) != syncMaxRequestBytes {
					t.Fatalf("boundary payload has %d bytes", len(raw))
				}
				for _, node := range batch {
					if node["name"] != tt.nodes[seen]["name"] {
						t.Fatalf("node order changed at %d", seen)
					}
					seen++
				}
			}
			if seen != len(tt.nodes) {
				t.Fatalf("batched %d nodes, want %d", seen, len(tt.nodes))
			}
		})
	}
}

func TestSyncImportPreflightStopsAllWrites(t *testing.T) {
	for _, oversized := range []bool{true, false} {
		t.Run(fmt.Sprint(oversized), func(t *testing.T) {
			writes := make(chan string, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch body["action"] {
				case "export":
					writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": []any{map[string]any{"name": "extra"}}})
				case "import":
					writes <- "import"
					acks := []any{}
					for _, raw := range body["nodes"].([]any) {
						acks = append(acks, map[string]any{"name": raw.(map[string]any)["name"], "ok": true})
					}
					writeJSON(w, http.StatusOK, map[string]any{"ok": true, "results": acks})
				case "delete":
					writes <- "delete"
					writeJSON(w, http.StatusOK, ok())
				default:
					t.Errorf("unexpected action %v", body["action"])
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			remote := newSyncRemote(storage.SyncTarget{URL: server.URL})
			defer remote.client.CloseIdleConnections()
			src := syncSource{nodes: map[string]map[string]any{}}
			for i := 0; i < syncImportBatchSize; i++ {
				name := fmt.Sprintf("n%d", i)
				src.order = append(src.order, name)
				src.nodes[name] = map[string]any{"name": name}
			}
			// A bad node after a complete batch must still prevent every write.
			src.order = append(src.order, "bad")
			src.nodes["bad"] = map[string]any{"name": "bad", "note": make(chan int)}
			if oversized {
				src.nodes["bad"]["note"] = strings.Repeat("&", syncMaxRequestBytes/6+1)
			}
			result := newSyncTargetResult(storage.SyncTarget{})
			err := remote.syncNodes(context.Background(), src, syncOptions{Apply: true, Prune: true}, &result)
			if err == nil || !strings.Contains(err.Error(), "bad") {
				t.Fatalf("error = %v, want the failing node name", err)
			}
			if oversized {
				if !errors.Is(err, errSyncRequestTooLarge) {
					t.Fatalf("error = %v", err)
				}
			} else {
				var unsupported *json.UnsupportedTypeError
				if !errors.As(err, &unsupported) {
					t.Fatalf("error = %v", err)
				}
			}
			if len(writes) != 0 || result.Completed != (syncCompleted{}) || !result.PruneSkipped {
				t.Fatalf("writes = %d, result = %+v", len(writes), result)
			}
		})
	}
}
