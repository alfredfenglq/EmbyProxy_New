package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestPublicInfoImpersonationClearsIdentityAndAuthentication(t *testing.T) {
	for _, profile := range identity.ProfileKeys() {
		for _, tt := range []struct {
			name        string
			path        string
			impersonate bool
			input       string
			wantClear   bool
		}{
			{"token only", "/emby/System/Info/Public", true, "token", true},
			{"all credentials", "/emby/System/Info/Public", true, "all", true},
			{"query credentials only", "/emby/System/Info/Public", true, "query", true},
			{"403 not retried", "/emby/System/Info/Public", true, "forbidden", true},
			{"no emby prefix", "/System/Info/Public", true, "all", true},
			{"case and trailing slash", "/EmBy/SyStEm/InFo/PuBlIc/", true, "all", true},
			{"anonymous", "/System/Info/Public", true, "anonymous", true},
			{"passthrough node", "/emby/System/Info/Public", false, "all", false},
			{"private system info", "/emby/System/Info", true, "all", false},
			{"server domains", "/emby/System/Ext/ServerDomains", true, "all", false},
			{"different endpoint", "/emby/System/Info/Public/Extra", true, "all", false},
		} {
			t.Run(profile+"/"+tt.name, func(t *testing.T) {
				ids := identity.NewManager(nil)
				h := New(config.Config{}, newProxyTestStore(t), ids, logging.New("silent", false))
				node := storage.Node{
					Name: "node", Secret: "secret", Target: "https://upstream.example/proxy",
					Impersonate: tt.impersonate, ImpersonateProfile: profile,
				}
				q := url.Values{"tag": {"keep me"}, "UserId": {"business-user"}}
				raw := http.Header{
					"User-Agent": {"Source/1.0"}, "Accept": {"application/json"},
					"Accept-Language": {"zh-CN"}, "Accept-Encoding": {"gzip"},
					"Content-Type": {"application/json"}, "Connection": {"Keep-Alive"},
					"X-Request-Id": {"keep-request-id"},
				}
				if tt.input != "anonymous" && tt.input != "query" {
					raw.Set("X-Emby-Token", "test-token")
				}
				if tt.input == "all" || tt.input == "query" || tt.input == "forbidden" {
					auth := `Emby Client="Source", Device="SourceDevice", DeviceId="source-id", Version="1.0", Token="test-token"`
					for _, key := range []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "X-Authorization"} {
						if tt.input != "query" {
							raw.Set(key, auth)
						}
						q.Set(key, auth)
					}
					if tt.input != "query" {
						raw.Set("Authorization", "Bearer test-token")
					}
					q.Set("Authorization", "Bearer test-token")
					for _, key := range []string{"X-Emby-Client", "X-Emby-Device-Id", "X-Emby-Client-Capabilities", "X-Emby-User-Id", "X-MediaBrowser-Client", "X-MediaBrowser-Token", "x_emby_token", "X-Application"} {
						if tt.input != "query" {
							raw.Set(key, "test-value")
						}
						q.Set(key, "test-value")
					}
					q.Set("api_key", "test-token")
					q.Set("API-KEY", "test-token-alias")
					q.Set("DeviceId", "source-id")
					q.Set("DeviceName", "SourceDevice")
				}
				req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret"+tt.path+"?"+q.Encode(), nil)
				req.Header = raw
				originalHeaders := req.Header.Clone()
				originalQuery := req.URL.RawQuery
				calls := 0
				h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(out *http.Request) (*http.Response, error) {
					calls++
					if out.URL.Path != "/proxy"+tt.path {
						t.Fatalf("upstream path = %q", out.URL.Path)
					}
					if tt.wantClear {
						normalize := strings.NewReplacer("-", "", "_", "")
						for key := range out.Header {
							k := normalize.Replace(strings.ToLower(key))
							if strings.HasPrefix(k, "xemby") || strings.HasPrefix(k, "xmediabrowser") || k == "authorization" || k == "xauthorization" || k == "xapplication" {
								t.Errorf("public info retained header %s", key)
							}
						}
						if got := out.URL.Query(); !reflect.DeepEqual(got, url.Values{"tag": {"keep me"}, "UserId": {"business-user"}}) {
							t.Errorf("public info query = %v, want only business parameters", got)
						}
					} else if out.Header.Get("X-Emby-Token") != "test-token" {
						t.Error("authentication was removed from an unaffected request")
					}
					for _, key := range []string{"Accept", "Accept-Encoding", "Accept-Language", "Content-Type", "Connection", "X-Request-Id"} {
						if out.Header.Get(key) != raw.Get(key) {
							t.Errorf("ordinary header %s changed", key)
						}
					}
					wantUA := raw.Get("User-Agent")
					if tt.impersonate {
						wantUA = identity.GetProfile(profile).UserAgent
					}
					if out.Header.Get("User-Agent") != wantUA {
						t.Error("unexpected user agent")
					}
					if !tt.impersonate && (!reflect.DeepEqual(out.URL.Query(), q) || out.Header.Get("Authorization") != raw.Get("Authorization")) {
						t.Error("passthrough authentication changed")
					}
					if tt.input == "forbidden" {
						return textResponse(http.StatusForbidden, "denied", nil), nil
					}
					return bytesResponse(http.StatusOK, []byte(`{}`), http.Header{"Content-Type": {"application/json"}}), nil
				})}
				res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Secret: "secret", Path: tt.path}, nil, config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				wantStatus := http.StatusOK
				if tt.input == "forbidden" {
					wantStatus = http.StatusForbidden
				}
				if res.StatusCode != wantStatus || calls != 1 {
					t.Fatalf("status = %d, calls = %d", res.StatusCode, calls)
				}
				if !reflect.DeepEqual(req.Header, originalHeaders) || req.URL.RawQuery != originalQuery {
					t.Error("inbound request was mutated")
				}
			})
		}
	}
}
