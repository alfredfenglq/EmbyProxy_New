package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestProgressThrottleKey(t *testing.T) {
	const fallbackKey = "node|127.0.0.1|device-1|legacy-session"
	for _, tt := range []struct {
		name        string
		query       string
		body        string
		want        string
		wantErr     bool
		wantTypeErr bool
	}{
		{name: "body ID", body: `{"PlaySessionId":" play-1 "}`, want: "node|play|play-1"},
		{name: "camel case body ID", body: `{"playSessionId":"play-1"}`, want: "node|play|play-1"},
		{name: "snake case body ID", body: `{"play_session_id":"play-1"}`, want: "node|play|play-1"},
		{name: "query takes precedence", query: "PlaySessionId=query-session", body: `{"PlaySessionId":"body-session"}`, want: "node|play|query-session"},
		{name: "camel case query ID", query: "playSessionId=play-1", body: `{}`, want: "node|play|play-1"},
		{name: "snake case query ID", query: "play_session_id=play-1", body: `{}`, want: "node|play|play-1"},
		{name: "bodyless query", query: "PlaySessionId=play-1", want: "node|play|play-1"},
		{name: "bodyless fallback", want: fallbackKey},
		{name: "missing ID", body: `{"PositionTicks":123}`, want: fallbackKey},
		{name: "empty ID", body: `{"PlaySessionId":" "}`, want: fallbackKey},
		{name: "null payload", body: `null`, want: fallbackKey},
		{name: "malformed object", body: `{"PlaySessionId":`, wantErr: true},
		{name: "invalid prefix", body: `not-json`, wantErr: true},
		{name: "whitespace body", body: " \r\n\t", wantErr: true},
		{name: "trailing garbage", body: `{"PlaySessionId":"play-1"} trailing`, wantErr: true},
		{name: "trailing object", body: `{} {}`, wantErr: true},
		{name: "query cannot hide malformed body", query: "PlaySessionId=play-1", body: `{"PlaySessionId":`, wantErr: true},
		{name: "array payload", body: `[]`, wantErr: true, wantTypeErr: true},
		{name: "string payload", body: `"value"`, wantErr: true, wantTypeErr: true},
		{name: "number payload", body: `123`, wantErr: true, wantTypeErr: true},
		{name: "query cannot hide type error", query: "PlaySessionId=play-1", body: `[]`, wantErr: true, wantTypeErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requestURL := &url.URL{Path: "/Sessions/Playing/Progress", RawQuery: tt.query}
			got, err := progressThrottleKey(" Node ", " 127.0.0.1 ", " device-1 ", " legacy-session ", requestURL, []byte(tt.body))
			if tt.wantErr {
				var syntaxErr *json.SyntaxError
				var typeErr *json.UnmarshalTypeError
				if tt.wantTypeErr {
					if !errors.As(err, &typeErr) {
						t.Fatalf("error = %v, want wrapped JSON type error", err)
					}
				} else if !errors.As(err, &syntaxErr) {
					t.Fatalf("error = %v, want wrapped JSON syntax error", err)
				}
				if got != "" {
					t.Fatalf("key = %q, want no key on parse failure", got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("progressThrottleKey() = %q, %v; want %q, nil", got, err, tt.want)
			}
		})
	}
}

func TestServeHTTPMalformedProgressBypassesThrottle(t *testing.T) {
	for _, tt := range []struct {
		name  string
		query string
		body  string
	}{
		{name: "malformed object", body: " \n{\"PlaySessionId\":\"body-session\","},
		{name: "invalid prefix", body: `not-json`},
		{name: "whitespace", body: " \r\n\t"},
		{name: "malformed body with query ID", query: "&PlaySessionId=query-session", body: `{"PositionTicks":`},
		{name: "type error with query ID", query: "&PlaySessionId=query-session", body: `[]`},
	} {
		for _, warm := range []bool{false, true} {
			for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
				t.Run(fmt.Sprintf("%s/warm=%t/status=%d", tt.name, warm, status), func(t *testing.T) {
					h := newProxyTestHandler(t, storage.Node{})
					h.cfg.Defaults.ProgressThrottleMS = 60_000
					key := "node|127.0.0.1|device-1|legacy-session"
					if tt.query != "" {
						key = "node|play|query-session"
					}
					if warm {
						h.progressThrottle.Set(key, "existing-success", time.Minute)
					}
					originalEntry := h.progressThrottle.m[key]
					path := "/emby/Sessions/Playing/Progress?SessionId=legacy-session" + tt.query
					actionCalls := 0
					h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						actionCalls++
						body, err := io.ReadAll(req.Body)
						if err != nil {
							t.Fatal(err)
						}
						if string(body) != tt.body || req.Method != http.MethodPost {
							t.Fatalf("upstream request changed: method=%s body=%q", req.Method, body)
						}
						if req.URL.Path != "/emby/Sessions/Playing/Progress" || req.URL.Query().Get("SessionId") != "legacy-session" {
							t.Fatalf("unexpected upstream URL: %s", req.URL)
						}
						if tt.query != "" && req.URL.Query().Get("PlaySessionId") != "query-session" {
							t.Fatalf("query session ID changed: %s", req.URL)
						}
						if req.Header.Get("Content-Type") != "application/json" {
							t.Fatalf("Content-Type = %q", req.Header.Get("Content-Type"))
						}
						return textResponse(status, "upstream response", http.Header{"X-Upstream-Result": []string{"preserved"}}), nil
					})}
					for i := 0; i < 3; i++ {
						ctx := WithAccessLogFields(context.Background())
						req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret"+path, strings.NewReader(tt.body)).WithContext(ctx)
						req.RemoteAddr = "127.0.0.1:12345"
						req.Header.Set("Content-Type", "application/json")
						req.Header.Set("X-Emby-Device-Id", "device-1")
						rr := httptest.NewRecorder()
						h.ServeHTTP(rr, req)
						if rr.Code != status || rr.Body.String() != "upstream response" || rr.Header().Get("X-Upstream-Result") != "preserved" {
							t.Fatalf("response = %d %q %v, want intact upstream response", rr.Code, rr.Body.String(), rr.Header())
						}
						fields := AccessLogFields(ctx)
						if fields["progressThrottle"] != "bypass" || fields["progressThrottleReason"] != "invalid-json" {
							t.Fatalf("missing throttle bypass diagnostics: %v", fields)
						}
						if detail, ok := fields["progressThrottleError"].(string); !ok || detail == "" {
							t.Fatalf("missing parsing error diagnostic: %v", fields)
						}
					}
					if actionCalls != 3 {
						t.Fatalf("upstream calls = %d, want 3", actionCalls)
					}
					wantEntries := 0
					if warm {
						wantEntries = 1
					}
					if len(h.progressThrottle.m) != wantEntries || h.progressThrottle.m[key] != originalEntry {
						t.Fatalf("malformed requests changed throttle cache: %v", h.progressThrottle.m)
					}
				})
			}
		}
	}
}

func TestServeHTTPProgressThrottleRequiresUpstreamSuccess(t *testing.T) {
	for _, body := range []string{`{"PlaySessionId":"play-1","PositionTicks":123}`, `{"PositionTicks":123}`} {
		for _, status := range []int{http.StatusBadRequest, http.StatusInternalServerError, http.StatusBadGateway} {
			t.Run(fmt.Sprintf("%s/status=%d", body, status), func(t *testing.T) {
				h := newProxyTestHandler(t, storage.Node{})
				h.cfg.Defaults.ProgressThrottleMS = 60_000
				actionCalls := 0
				h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					actionCalls++
					if len(h.progressThrottle.m) != 0 {
						t.Fatal("throttle window opened before upstream success")
					}
					if actionCalls <= 2 {
						return textResponse(status, "upstream failure", nil), nil
					}
					return textResponse(http.StatusOK, "accepted", nil), nil
				})}
				for i, wantStatus := range []int{status, status, http.StatusOK, http.StatusNoContent} {
					req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret/emby/Sessions/Playing/Progress", strings.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-Emby-Device-Id", "device-1")
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, req)
					if rr.Code != wantStatus {
						t.Fatalf("request %d status = %d, want %d", i, rr.Code, wantStatus)
					}
					if i < 2 && rr.Body.String() != "upstream failure" {
						t.Fatalf("failure body = %q, want upstream failure", rr.Body.String())
					}
					if i == 2 && rr.Body.String() != "accepted" {
						t.Fatalf("success body = %q, want accepted", rr.Body.String())
					}
				}
				if actionCalls != 3 {
					t.Fatalf("upstream calls = %d, want 3 with only the successful report throttled", actionCalls)
				}
			})
		}
	}
}

func TestHandleMediaProxyProgressTransportErrorDoesNotThrottleRetry(t *testing.T) {
	store := newProxyTestStore(t)
	h := New(config.Config{Defaults: config.Defaults{ProgressThrottleMS: 60_000}}, store, nil, logging.New("silent", false))
	upstreamErr := errors.New("upstream unavailable")
	actionCalls := 0
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		actionCalls++
		if actionCalls == 1 {
			return nil, upstreamErr
		}
		return textResponse(http.StatusNoContent, "", nil), nil
	})}
	const path = "/emby/Sessions/Playing/Progress"
	body := []byte(`{"PlaySessionId":"play-1"}`)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node"+path, strings.NewReader(string(body)))
		targetURL := &url.URL{Scheme: "https", Host: "upstream.example", Path: path}
		res, err := h.handleMediaProxy(context.Background(), req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: path}, targetURL, body, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
		if i == 0 {
			if !errors.Is(err, upstreamErr) || res != nil {
				t.Fatalf("response = %v, error = %v; want original transport error", res, err)
			}
			if len(h.progressThrottle.m) != 0 {
				t.Fatal("transport failure opened a throttle window")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", res.StatusCode)
		}
	}
	if actionCalls != 2 {
		t.Fatalf("upstream calls = %d, want 2", actionCalls)
	}
}
