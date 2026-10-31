package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
)

func TestLoginMirrorsNativeClient(t *testing.T) {
	const body = `{"Username":"person","Password":"legacy-hash","Pw":"plaintext"}`
	for _, profile := range append([]string{""}, identity.ProfileOrder...) {
		name := profile
		if name == "" {
			name = "passthrough"
		}
		for _, path := range []string{"/emby/Users/AuthenticateByName", "/Users/AuthenticateByName"} {
			for _, tc := range []struct {
				name           string
				status         int
				sourceAccept   string
				sourceType     string
				sourceAjaxFlag string
			}{
				{name: "success", status: http.StatusOK, sourceAccept: "*/*", sourceType: "application/json"},
				{name: "no-accept", status: http.StatusOK, sourceType: "application/json; charset=UTF-8"},
				{name: "source-ajax-flag", status: http.StatusOK, sourceAccept: "*/*", sourceType: "application/json", sourceAjaxFlag: "XMLHttpRequest"},
				{name: "forbidden-not-retried", status: http.StatusForbidden, sourceAccept: "*/*", sourceType: "application/json"},
				{name: "not-found-not-retried", status: http.StatusNotFound, sourceAccept: "*/*", sourceType: "application/json"},
			} {
				t.Run(name+path+"/"+tc.name, func(t *testing.T) {
					node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: profile != "", ImpersonateProfile: profile}
					h := newProxyTestHandler(t, node)
					h.ids = identity.NewManager(nil)
					calls := 0
					h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						if req.URL.Path != path {
							t.Fatalf("login path = %q, want source path %q", req.URL.Path, path)
						}
						raw, err := io.ReadAll(req.Body)
						if err != nil || string(raw) != body {
							t.Fatalf("login body = %q, error = %v; want unchanged body", raw, err)
						}
						if got := req.Header.Get("Accept"); got != tc.sourceAccept {
							t.Fatalf("Accept = %q, want source value %q", got, tc.sourceAccept)
						}
						if got := req.Header.Get("Content-Type"); got != tc.sourceType {
							t.Fatalf("Content-Type = %q, want source value %q", got, tc.sourceType)
						}
						if got := req.Header.Get("X-Requested-With"); got != tc.sourceAjaxFlag {
							t.Fatalf("X-Requested-With = %q, want source value %q", got, tc.sourceAjaxFlag)
						}
						if req.Header.Get("Origin") != "" || req.Header.Get("Referer") != "" {
							t.Fatalf("Origin/Referer sent: %v", req.Header)
						}
						if req.Header.Get("X-Emby-Token") != "" || req.Header.Get("X-Emby-Authorization") == "" {
							t.Fatalf("login identity headers = %v, want authorization without token", req.Header)
						}
						if tc.status == http.StatusOK {
							return textResponse(http.StatusOK, `{"AccessToken":"new-token"}`, http.Header{"Content-Type": {"application/json"}}), nil
						}
						return textResponse(tc.status, "denied", nil), nil
					})}
					req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node"+path, strings.NewReader(body))
					if tc.sourceAccept != "" {
						req.Header.Set("Accept", tc.sourceAccept)
					}
					req.Header.Set("Content-Type", tc.sourceType)
					if tc.sourceAjaxFlag != "" {
						req.Header.Set("X-Requested-With", tc.sourceAjaxFlag)
					}
					req.Header.Set("Origin", "https://proxy.example")
					req.Header.Set("Referer", "https://proxy.example/web/index.html")
					req.Header.Set("X-Emby-Authorization", `Emby Client="Source",Device="PC",DeviceId="source-device",Version="1"`)
					res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, []byte(body), config.ProxyEnv{})
					if err != nil {
						t.Fatal(err)
					}
					defer res.Body.Close()
					if res.StatusCode != tc.status || calls != 1 {
						t.Fatalf("status=%d calls=%d, want status %d from a single upstream call", res.StatusCode, calls, tc.status)
					}
				})
			}
		}
	}
}

func Test403IsNotRetried(t *testing.T) {
	for _, profile := range append([]string{""}, identity.ProfileOrder...) {
		name := profile
		if name == "" {
			name = "passthrough"
		}
		for _, image := range []bool{false, true} {
			kind, path, wantOrigin := "api", "/Users/account/Views", "https://source.example"
			if image {
				kind, path, wantOrigin = "image", "/Items/item/Images/Primary", ""
			}
			t.Run(name+"/"+kind, func(t *testing.T) {
				node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: profile != "", ImpersonateProfile: profile}
				h := newProxyTestHandler(t, node)
				h.ids = identity.NewManager(nil)
				var origins []string
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					origins = append(origins, req.Header.Get("Origin"))
					return textResponse(http.StatusForbidden, "denied", nil), nil
				})}
				if image {
					h.imageFollowClient = client
				} else {
					h.noRedirectClient = client
				}
				req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node"+path, nil)
				req.Header.Set("Origin", "https://source.example")
				res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, nil, config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if res.StatusCode != http.StatusForbidden || !reflect.DeepEqual(origins, []string{wantOrigin}) {
					t.Fatalf("status=%d, origins=%v; want one 403 request with origin %q", res.StatusCode, origins, wantOrigin)
				}
			})
		}
	}
}

func TestDirect403IsNotRetried(t *testing.T) {
	for _, profile := range append([]string{""}, identity.ProfileOrder...) {
		name := profile
		if name == "" {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: profile != "", ImpersonateProfile: profile}
			h := newProxyTestHandler(t, node)
			h.ids = identity.NewManager(nil)
			calls := 0
			h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Header.Get("Origin") != "" || req.Header.Get("Referer") != "" {
					t.Fatalf("direct request sent Origin/Referer: %v", req.Header)
				}
				return textResponse(http.StatusForbidden, "denied", nil), nil
			})}
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/http%3A%2F%2F8.8.8.8%2Fvideo.mkv", nil)
			req.Header.Set("Origin", "https://proxy.example")
			req.Header.Set("Range", "bytes=1024-")
			res, err := h.handleDirect(context.Background(), req, "http://8.8.8.8/video.mkv?sign=abc", config.ProxyEnv{ExternalAllowAny: true}, node, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusForbidden || calls != 1 {
				t.Fatalf("status=%d calls=%d, want a single 403 request", res.StatusCode, calls)
			}
		})
	}
}

func TestDirectRangeFallbackOnlyOn416(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rangeValue string
		first      int
		wantCalls  int
		wantStatus int
	}{
		{name: "416 from start", rangeValue: "bytes=0-", first: http.StatusRequestedRangeNotSatisfiable, wantCalls: 2, wantStatus: http.StatusOK},
		{name: "416 at offset", rangeValue: "bytes=1024-", first: http.StatusRequestedRangeNotSatisfiable, wantCalls: 1, wantStatus: http.StatusRequestedRangeNotSatisfiable},
		{name: "full body", rangeValue: "bytes=0-", first: http.StatusOK, wantCalls: 1, wantStatus: http.StatusOK},
		{name: "forbidden", rangeValue: "bytes=0-", first: http.StatusForbidden, wantCalls: 1, wantStatus: http.StatusForbidden},
		{name: "not found", rangeValue: "bytes=0-", first: http.StatusNotFound, wantCalls: 1, wantStatus: http.StatusNotFound},
		{name: "server error", rangeValue: "bytes=0-", first: http.StatusBadGateway, wantCalls: 1, wantStatus: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := storage.Node{Name: "node", Target: "https://upstream.example"}
			h := newProxyTestHandler(t, node)
			var ranges []string
			h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				ranges = append(ranges, req.Header.Get("Range"))
				if len(ranges) == 1 {
					return textResponse(tc.first, "first", nil), nil
				}
				return textResponse(http.StatusOK, "full", nil), nil
			})}
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/http%3A%2F%2F8.8.8.8%2Fvideo.mkv", nil)
			req.Header.Set("Range", tc.rangeValue)
			res, err := h.handleDirect(context.Background(), req, "http://8.8.8.8/video.mkv?sign=abc", config.ProxyEnv{ExternalAllowAny: true}, node, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.wantStatus || len(ranges) != tc.wantCalls {
				t.Fatalf("status=%d ranges=%q, want status %d after %d call(s)", res.StatusCode, ranges, tc.wantStatus, tc.wantCalls)
			}
			if tc.wantCalls == 2 && ranges[1] != "" {
				t.Fatalf("fallback request kept Range %q", ranges[1])
			}
		})
	}
}

func TestRefactorPreservesImpersonatedCapyPathHandling(t *testing.T) {
	for _, profile := range identity.ProfileOrder {
		t.Run(profile, func(t *testing.T) {
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
			h := newProxyTestHandler(t, node)
			h.ids = identity.NewManager(nil)
			calls := 0
			h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.Path != "/Users/account/Views" {
					t.Fatalf("configured Capy path handling changed: %s", req.URL.Path)
				}
				return textResponse(http.StatusOK, "ok", nil), nil
			})}
			const path = "/emby/Users/account/Views"
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node"+path, nil)
			req.Header.Set("User-Agent", "CapyPlayer/1.0")
			res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, nil, config.ProxyEnv{CapyStripEmby: "1"})
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK || calls != 1 {
				t.Fatalf("status=%d, calls=%d", res.StatusCode, calls)
			}
		})
	}
}

func TestImpersonatedResourceKeepsQueryAuthorizationToken(t *testing.T) {
	for _, profile := range []string{"hills_android", "hills_windows"} {
		t.Run(profile, func(t *testing.T) {
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
			h := newProxyTestHandler(t, node)
			h.ids = identity.NewManager(nil)
			calls := 0
			h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if got := req.Header.Get("X-Emby-Token"); got != "valid-token" {
					t.Fatalf("X-Emby-Token = %q, want token from query authorization; URL=%s", got, req.URL)
				}
				if req.URL.Query().Has("X-Emby-Authorization") {
					t.Fatalf("source query authorization retained: %s", req.URL)
				}
				return textResponse(http.StatusOK, "{}", nil), nil
			})}
			const path = "/Videos/item/AdditionalParts"
			query := url.Values{"X-Emby-Authorization": {`Emby Client="Source", DeviceId="source", Token="valid-token"`}}
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node"+path+"?"+query.Encode(), nil)
			res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, nil, config.ProxyEnv{})
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK || calls != 1 {
				t.Fatalf("status=%d, calls=%d", res.StatusCode, calls)
			}
		})
	}
}

func TestRefactorPreservesImpersonatedImageWriteRouting(t *testing.T) {
	for _, profile := range identity.ProfileOrder {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(profile+"/"+method, func(t *testing.T) {
				node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
				h := newProxyTestHandler(t, node)
				h.ids = identity.NewManager(nil)
				h.noRedirectClient = failRoundTripClient(t, "image write switched to the general API client")
				calls := 0
				h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					raw, err := io.ReadAll(req.Body)
					if err != nil || string(raw) != "image data" || req.Method != method {
						t.Fatalf("image write changed: method=%s, body=%q, error=%v", req.Method, raw, err)
					}
					return textResponse(http.StatusOK, "ok", nil), nil
				})}
				const path = "/Items/item/Images/Primary"
				req := httptest.NewRequest(method, "https://proxy.example/node"+path, strings.NewReader("image data"))
				res, err := h.handleOneTarget(context.Background(), req, node, parsedRoute{Name: "node", Path: path}, []byte("image data"), config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if res.StatusCode != http.StatusOK || calls != 1 {
					t.Fatalf("status=%d, calls=%d", res.StatusCode, calls)
				}
			})
		}
	}
}
