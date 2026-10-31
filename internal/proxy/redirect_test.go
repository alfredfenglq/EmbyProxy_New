package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

func redirectTo(status int, location string) *http.Response {
	return textResponse(status, "", http.Header{"Location": {location}})
}

func TestFollowedRedirectsKeepSourceReferer(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, sourceReferer := range []string{"", "https://source.example/page"} {
			t.Run(fmt.Sprintf("%d/referer=%q", status, sourceReferer), func(t *testing.T) {
				var referers []string
				client := newProxyHTTPClientWithTransport(true, roundTripFunc(func(req *http.Request) (*http.Response, error) {
					referers = append(referers, req.Header.Get("Referer"))
					switch req.URL.Host + req.URL.Path {
					case "upstream.example/emby/videos/1/stream.mkv":
						return redirectTo(status, "https://upstream.example/videos/1/original.mkv?api_key=token"), nil
					case "upstream.example/videos/1/original.mkv":
						return redirectTo(status, "https://cdn1.example/hop?sign=1"), nil
					case "cdn1.example/hop":
						return redirectTo(status, "https://cdn2.example/file.mkv?sign=2"), nil
					}
					return textResponse(http.StatusOK, "ok", nil), nil
				}))
				req := httptest.NewRequest(http.MethodGet, "https://upstream.example/emby/videos/1/stream.mkv?api_key=token", nil)
				req.RequestURI = ""
				if sourceReferer != "" {
					req.Header.Set("Referer", sourceReferer)
				}
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				// Same-host hop, then two cross-host hops: none may carry a previous hop URL.
				want := []string{sourceReferer, sourceReferer, sourceReferer, sourceReferer}
				if res.StatusCode != http.StatusOK || !reflect.DeepEqual(referers, want) {
					t.Fatalf("status=%d referers=%q, want %q", res.StatusCode, referers, want)
				}
			})
		}
	}
}

func TestFollowedRedirectsStopAfterTen(t *testing.T) {
	calls := 0
	client := newProxyHTTPClientWithTransport(true, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return redirectTo(http.StatusFound, fmt.Sprintf("https://upstream.example/loop?n=%d", calls)), nil
	}))
	req := httptest.NewRequest(http.MethodGet, "https://upstream.example/loop", nil)
	req.RequestURI = ""
	if res, err := client.Do(req); err == nil {
		res.Body.Close()
		t.Fatal("redirect loop did not stop")
	}
	if calls != 10 {
		t.Fatalf("calls = %d, want 10", calls)
	}
}

func TestDirectRedirectsKeepOnlyAdapterReferer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		want   string
	}{
		{name: "generic", target: "http://8.8.8.8/video.mkv?sign=abc", want: ""},
		{name: "tianyi adapter", target: "http://8.8.8.8/cloud.189.cn/video.mkv?sign=abc", want: "https://cloud.189.cn/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := storage.Node{Name: "node", Target: "https://upstream.example"}
			h := newProxyTestHandler(t, node)
			var referers []string
			h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				referers = append(referers, req.Header.Get("Referer"))
				if req.URL.Host == "8.8.8.8" {
					return redirectTo(http.StatusFound, "http://8.8.4.4/file.mkv?sign=next"), nil
				}
				return textResponse(http.StatusOK, "ok", nil), nil
			})}
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/x", nil)
			res, err := h.handleDirect(context.Background(), req, tc.target, config.ProxyEnv{ExternalAllowAny: true}, node, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if want := []string{tc.want, tc.want}; res.StatusCode != http.StatusOK || !reflect.DeepEqual(referers, want) {
				t.Fatalf("status=%d referers=%q, want %q", res.StatusCode, referers, want)
			}
		})
	}
}

func TestDirectRedirectsStopAfterTen(t *testing.T) {
	node := storage.Node{Name: "node", Target: "https://upstream.example"}
	h := newProxyTestHandler(t, node)
	calls := 0
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls > 20 {
			t.Fatal("redirect loop was not stopped")
		}
		return redirectTo(http.StatusFound, fmt.Sprintf("http://8.8.8.8/loop?n=%d", calls)), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/x", nil)
	res, err := h.handleDirect(context.Background(), req, "http://8.8.8.8/loop", config.ProxyEnv{ExternalAllowAny: true}, node, nil)
	if err == nil {
		res.Body.Close()
		if res.StatusCode < 500 {
			t.Fatalf("status = %d, want a failed redirect loop", res.StatusCode)
		}
	}
	if calls != 10 {
		t.Fatalf("calls = %d, want 10", calls)
	}
}
