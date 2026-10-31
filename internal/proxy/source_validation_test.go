package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
)

func TestImpersonatedRequestsRejectMalformedQueryBeforeForwarding(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	for _, profile := range identity.ProfileKeys() {
		node := storage.Node{Name: "node", Secret: "secret", Target: upstream.URL + "," + upstream.URL + "/line2", Impersonate: true, ImpersonateProfile: profile}
		h := newProxyTestHandler(t, node)
		h.ids = identity.NewManager(nil)
		for _, path := range []string{
			"/emby/Users/account/Views", "/emby/Users/AuthenticateByName",
			"/emby/Items/1/PlaybackInfo", "/emby/Videos/1/stream.mp4",
			"/emby/Items/1/Images/Primary", "/emby/System/Info/Public",
			"/movie.strm", "/embywebsocket", "/__raw__",
		} {
			for _, withHeader := range []bool{false, true} {
				name := profile + path + "/query-only"
				if withHeader {
					name = profile + path + "/with-header"
				}
				t.Run(name, func(t *testing.T) {
					requestURL := "https://proxy.example/node/secret" + path + "?"
					if path == "/__raw__" {
						requestURL = h.signedRawLink("https://proxy.example", "/node/secret", "https://upstream.example/video.mp4") + "&"
					}
					query := "X-Emby-Device-Id=abc%ZZ"
					if path == "/embywebsocket" {
						query = "deviceId=abc%ZZ"
					}
					req := httptest.NewRequest(http.MethodGet, requestURL+query, nil)
					req.Header.Set("X-Emby-Authorization", `Emby Client="Source", Token="test-token"`)
					if withHeader {
						req.Header.Set("X-Emby-Authorization", `Emby Client="Source", DeviceId="valid-header", Token="test-token"`)
					}
					if path == "/embywebsocket" {
						req.Header.Set("Connection", "Upgrade")
						req.Header.Set("Upgrade", "websocket")
					}
					if strings.HasSuffix(path, "AuthenticateByName") || strings.HasSuffix(path, "PlaybackInfo") {
						req.Method = http.MethodPost
					}
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)
					if rec.Code != http.StatusBadRequest {
						t.Fatalf("status=%d body=%q, want 400", rec.Code, rec.Body.String())
					}
					if calls.Load() != 0 {
						t.Fatal("malformed request reached upstream")
					}
					for _, target := range storage.SplitTargets(node.Target) {
						if _, banned := h.lineBan.Get("admin:node|" + target); banned {
							t.Fatal("invalid client query must not ban an upstream route")
						}
					}
				})
			}
		}
	}
}

func TestMalformedSourceQueryStopsAllBannedTargetFallback(t *testing.T) {
	node := storage.Node{Name: "node", Secret: "secret", Target: "https://first.example,https://second.example", Impersonate: true, ImpersonateProfile: "hills_android"}
	h := newProxyTestHandler(t, node)
	h.ids = identity.NewManager(nil)
	h.noRedirectClient = failRoundTripClient(t, "malformed input reached a previously banned target")
	for _, target := range storage.SplitTargets(node.Target) {
		h.lineBan.Set("admin:node|"+target, 1, time.Minute)
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/Items?X-Emby-Device-Id=bad%ZZ", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("fallback status=%d, want 400", rec.Code)
	}
	for _, target := range storage.SplitTargets(node.Target) {
		if _, banned := h.lineBan.Get("admin:node|" + target); !banned {
			t.Fatal("invalid request changed a target ban")
		}
	}
}

func TestSourceQueryErrorsPropagateFromProxyPaths(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.ids = identity.NewManager(nil)
	client := failRoundTripClient(t, "invalid source query reached upstream")
	h.rawDirectClient, h.playbackActionClient, h.playbackStreamClient = client, client, client
	node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: "hills_android"}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/Items?X-Emby-Device-Id=abc%ZZ", nil)
	ctx := context.Background()
	target := &url.URL{Scheme: "https", Host: "upstream.example", Path: "/Videos/1/stream.mp4"}
	for _, tt := range []struct {
		name string
		send func() (*http.Response, error)
	}{
		{"direct", func() (*http.Response, error) {
			return h.handleDirect(ctx, req, target.String(), config.ProxyEnv{}, node, nil)
		}},
		{"strm", func() (*http.Response, error) {
			return h.handleSTRM(ctx, req, node, parsedRoute{Name: "node", Path: "/movie.strm"}, target, nil, config.ProxyEnv{})
		}},
		{"media", func() (*http.Response, error) {
			return h.handleMediaProxy(ctx, req, node, parsedRoute{Name: "node", Path: target.Path}, target, nil, config.ProxyEnv{}, true, false, false, "", "")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res, err := tt.send()
			if res != nil || !errors.Is(err, identity.ErrInvalidQueryEncoding) {
				t.Fatalf("response=%v, error=%v; want no response and identity decoding error", res, err)
			}
		})
	}
}

func TestEncodedPercentSourceIDForwardedWithStableIdentity(t *testing.T) {
	for _, profile := range identity.ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			h := newProxyTestHandler(t, storage.Node{Name: "node", Secret: "secret", Impersonate: true, ImpersonateProfile: profile})
			h.ids = identity.NewManager(nil)
			var outbound *http.Request
			h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				outbound = r.Clone(r.Context())
				return textResponse(http.StatusOK, "ok", nil), nil
			})}
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/Items?X-Emby-Device-Id=abc%25ZZ&tag=keep%20me", nil)
			req.Header.Set("X-Emby-Authorization", `Emby Client="Source", Token="test-token"`)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || outbound == nil {
				t.Fatalf("valid escaped percent rejected: status=%d", rec.Code)
			}
			want := h.ids.Resolve(profile, "abc%ZZ").DeviceID
			if !strings.Contains(outbound.Header.Get("X-Emby-Authorization"), want) || outbound.Header.Get("X-Emby-Token") != "test-token" {
				t.Fatalf("wrong outbound identity/token: %v", outbound.Header)
			}
			if outbound.URL.Query().Get("tag") != "keep me" {
				t.Fatal("business query changed")
			}
		})
	}
}

func TestPassthroughSourceQueryRemainsUnchanged(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{Impersonate: false})
	const raw = "X-Emby-Device-Id=abc%ZZ"
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.RawQuery != raw {
			t.Fatalf("passthrough query=%q, want %q", r.URL.RawQuery, raw)
		}
		return textResponse(http.StatusOK, "ok", nil), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/Items?"+raw, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("passthrough status=%d, want 200", rec.Code)
	}
}

func TestStreamForwardingDoesNotDependOnEarlierRequests(t *testing.T) {
	for _, profile := range identity.ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			for _, warmed := range []bool{false, true} {
				h := newProxyTestHandler(t, storage.Node{Impersonate: true, ImpersonateProfile: profile})
				h.ids = identity.NewManager(nil)
				if warmed {
					h.ids.Resolve(profile, "source-device")
				}
				var got string
				h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					got = r.URL.Query().Get("DeviceId")
					return textResponse(http.StatusOK, "stream", http.Header{"Content-Type": {"video/mp4"}}), nil
				})}
				req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/Videos/1/stream.mp4?DeviceId=source-device&api_key=t", nil)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				res := rec.Result()
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if rec.Code != http.StatusOK || got != "source-device" {
					t.Fatalf("warmed=%t, status=%d, DeviceId=%q; want 200 and unchanged ID", warmed, rec.Code, got)
				}
			}
		})
	}
}
