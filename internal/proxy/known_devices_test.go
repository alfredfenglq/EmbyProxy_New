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
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestNodeStreamUsesKnownSourceWithoutChangingOtherFields(t *testing.T) {
	for _, profile := range identity.ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			ctx := context.Background()
			store := newProxyTestStore(t)
			h := New(config.Config{}, store, identity.NewManager(store), logging.New("silent", false))
			var sent *http.Request
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				sent = req.Clone(req.Context())
				sent.Header = cloneHeader(req.Header)
				return bytesResponse(http.StatusOK, []byte(`{"MediaSources":[]}`), http.Header{"Content-Type": {"application/json"}}), nil
			})}
			h.noRedirectClient, h.playbackActionClient, h.playbackStreamClient = client, client, client
			node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
			send := func(node storage.Node, method, path, query, source string) *http.Request {
				t.Helper()
				sent = nil
				r := httptest.NewRequest(method, "https://proxy.example/"+node.Name+"/secret"+path+"?"+query, nil)
				r.Header.Set("User-Agent", "Hills Windows/1.5.5")
				r.Header.Set("Range", "bytes=288822199-")
				r.Header.Set("Icy-Metadata", "1")
				if source != "" {
					r.Header.Set("X-Emby-Authorization", `Emby Client="Source", DeviceId="`+source+`", Version="1"`)
					r.Header.Set("X-Emby-Token", "shared-token")
				}
				res, err := h.handleNode(ctx, r, node, parsedRoute{Name: node.Name, Secret: "secret", Path: path}, nil, config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if sent == nil {
					t.Fatal("request was not forwarded")
				}
				return sent
			}
			const source = "0123456789abcdef0123456789abcdef"
			const stream = "/Videos/777738/stream.mkv"
			query := "Static=true&mediaSourceId=mediasource_777738&deviceId=" + source + "&api_key=shared-token&Tag"
			before := send(node, http.MethodGet, stream, query, "")
			if got := before.URL.Query().Get("deviceId"); got != source {
				t.Fatalf("unobserved ID changed: %q", got)
			}
			// Learn from PlaybackInfo, then a second device sharing the same token.
			send(node, http.MethodPost, "/emby/Items/777738/PlaybackInfo", "", source)
			send(node, http.MethodGet, "/emby/Users/account/Views", "", "phone-device")
			want := h.ids.Resolve(profile, source).DeviceID
			after := send(node, http.MethodGet, stream, query, "")
			q := before.URL.Query()
			q.Set("deviceId", want)
			if !reflect.DeepEqual(after.URL.Query(), q) || !reflect.DeepEqual(after.Header, before.Header) || after.URL.Path != before.URL.Path || after.Method != before.Method {
				t.Fatalf("fields other than DeviceId changed: before=%s %v after=%s %v", before.URL, before.Header, after.URL, after.Header)
			}
			if after.Header.Get("X-Emby-Authorization") != "" || after.Header.Get("X-Emby-Token") != "" {
				t.Fatal("history-based identity must not add stream identity headers")
			}
			for _, tt := range []struct{ name, method, query, explicit, key, want string }{
				{"head", http.MethodHead, query, "", "deviceId", want},
				{"normalized", http.MethodGet, "DeviceId=+" + strings.ToUpper(source) + "+&api_key=t", "", "DeviceId", want},
				{"other device sharing token", http.MethodGet, "deviceId=phone-device&api_key=shared-token", "", "deviceId", h.ids.Resolve(profile, "phone-device").DeviceID},
				{"already derived", http.MethodGet, "deviceId=" + want + "&api_key=t", "", "deviceId", want},
				{"unknown server ID", http.MethodGet, "deviceId=server-issued&X-Emby-Token=m2.stream-token", "", "deviceId", "server-issued"},
				{"no device", http.MethodGet, "api_key=t", "", "deviceId", ""},
				{"explicit identity wins", http.MethodGet, query, "phone-device", "deviceId", source},
				{"explicit query identity wins", http.MethodGet, query + "&X-Emby-Device-Id=phone-device", "", "deviceId", source},
				{"first unknown stays", http.MethodGet, "deviceId=server-issued&DeviceId=" + source, "", "deviceId", "server-issued"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					out := send(node, tt.method, stream, tt.query, tt.explicit)
					if got := out.URL.Query().Get(tt.key); got != tt.want {
						t.Fatalf("stream ID = %q, want %q", got, tt.want)
					}
				})
			}
			other := node
			other.Name = "other"
			if got := send(other, http.MethodGet, stream, query, "").URL.Query().Get("deviceId"); got != source {
				t.Fatalf("observation crossed nodes: %q", got)
			}
			node.Target = "https://second-line.example"
			if got := send(node, http.MethodGet, stream, query, "").URL.Query().Get("deviceId"); got != want {
				t.Fatalf("observation lost across upstream lines: %q", got)
			}
			node.ImpersonateProfile = "hills_android"
			if got := send(node, http.MethodGet, stream, query, "").URL.Query().Get("deviceId"); got != h.ids.Resolve("hills_android", source).DeviceID {
				t.Fatalf("current node profile not used: %q", got)
			}
			// A restart forgets observations even when the database is unchanged.
			h.ids = identity.NewManager(store)
			if got := send(node, http.MethodGet, stream, query, "").URL.Query().Get("deviceId"); got != source {
				t.Fatalf("new manager unexpectedly retained a source: %q", got)
			}
			send(node, http.MethodPost, "/emby/Items/777738/PlaybackInfo", "", source)
			if got := send(node, http.MethodGet, stream, query, "").URL.Query().Get("deviceId"); got != h.ids.Resolve(node.ImpersonateProfile, source).DeviceID {
				t.Fatalf("source was not relearned after restart: %q", got)
			}
			node.Impersonate = false
			if got := send(node, http.MethodGet, stream, query, "").URL.Query().Get("deviceId"); got != source {
				t.Fatalf("non-impersonated stream changed: %q", got)
			}
		})
	}
}

func TestKnownDevicesOnlyLearnSuccessfulExplicitNodeRequests(t *testing.T) {
	for _, tt := range []struct {
		name, path, query string
		header            bool
		status            int
		impersonate       bool
		want              string
	}{
		{"header source", "/emby/Users/account/Views", "", true, 200, true, "device-a"},
		{"query source", "/emby/Users/account/Views", "X-Emby-Device-Id=device-a", false, 200, true, "device-a"},
		{"failed auth", "/emby/Users/account/Views", "", true, 401, true, ""},
		{"bare ID is not evidence", "/Videos/1/stream.mp4", "deviceId=device-a&api_key=t", false, 200, true, ""},
		{"non-impersonated", "/emby/Users/account/Views", "", true, 200, false, ""},
		{"public probe", "/emby/System/Info/Public", "", true, 200, true, ""},
		{"image", "/emby/Items/1/Images/Primary", "", true, 200, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := newProxyTestStore(t)
			h := New(config.Config{}, store, identity.NewManager(store), logging.New("silent", false))
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return bytesResponse(tt.status, []byte(`{}`), http.Header{"Content-Type": {"application/json"}}), nil
			})}
			h.noRedirectClient, h.playbackStreamClient, h.imageFollowClient = client, client, client
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: tt.impersonate, ImpersonateProfile: "yamby"}
			r := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret"+tt.path+"?"+tt.query, nil)
			if tt.header {
				r.Header.Set("X-Emby-Authorization", `Emby DeviceId="device-a", Token="t"`)
			}
			res, err := h.handleNode(ctx, r, node, parsedRoute{Name: "node", Path: tt.path}, nil, config.ProxyEnv{})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			got, err := h.ids.KnownStreamSource("node", &url.URL{RawQuery: "deviceId=device-a"})
			if err != nil || got != tt.want {
				t.Fatalf("learned source = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestKnownSourceDoesNotChangeDirectOrSTRMRequests(t *testing.T) {
	for _, route := range []string{"raw", "strm"} {
		t.Run(route, func(t *testing.T) {
			var results [][]string
			for _, learn := range []bool{false, true} {
				store := newProxyTestStore(t)
				h := New(config.Config{}, store, identity.NewManager(store), logging.New("silent", false))
				if learn {
					h.ids.RememberSourceDevice("node", "device-a")
				}
				var urls []string
				// A public literal IP avoids DNS; the transport below intercepts all I/O.
				const external = "https://8.8.8.8/video.mp4?deviceId=device-a&api_key=t"
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					urls = append(urls, req.URL.String())
					if strings.HasSuffix(req.URL.Path, ".strm") {
						return textResponse(http.StatusOK, external, nil), nil
					}
					return textResponse(http.StatusOK, "video", nil), nil
				})}
				h.rawDirectClient, h.playbackActionClient = client, client
				node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: "yamby"}
				path := "/movie.strm"
				requestURL := "https://proxy.example/node/secret" + path + "?deviceId=device-a&api_key=t"
				if route == "raw" {
					path = "/__raw__"
					requestURL = h.signedRawLink("https://proxy.example", "/node/secret", external)
				}
				r := httptest.NewRequest(http.MethodGet, requestURL, nil)
				res, err := h.handleNode(context.Background(), r, node, parsedRoute{Name: "node", Secret: "secret", Path: path}, nil, config.ProxyEnv{ExternalAllowHosts: "8.8.8.8"})
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if res.StatusCode != http.StatusOK || len(urls) == 0 {
					t.Fatalf("route did not reach upstream: status=%d urls=%v", res.StatusCode, urls)
				}
				results = append(results, urls)
			}
			if !reflect.DeepEqual(results[0], results[1]) {
				t.Fatalf("known source changed %s URLs: %v", route, results)
			}
		})
	}
}

func TestKnownSourceDoesNotChangeNonStreamRequests(t *testing.T) {
	for _, path := range []string{
		"/emby/Users/AuthenticateByName", "/emby/Users/account/Views", "/emby/Items/1/PlaybackInfo",
		"/emby/Sessions/Playing", "/emby/Sessions/Playing/Progress", "/emby/Items/1/Images/Primary",
		"/emby/System/Info/Public", "/emby/smartstrm", "/emby/Videos/1/stream.mp4",
	} {
		t.Run(path, func(t *testing.T) {
			var captured []*http.Request
			for _, learn := range []bool{false, true} {
				store := newProxyTestStore(t)
				h := New(config.Config{}, store, identity.NewManager(store), logging.New("silent", false))
				if learn {
					h.ids.RememberSourceDevice("node", "device-a")
				}
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					captured = append(captured, req.Clone(req.Context()))
					return bytesResponse(http.StatusOK, []byte(`{}`), http.Header{"Content-Type": {"application/json"}}), nil
				})}
				h.noRedirectClient, h.playbackActionClient, h.imageFollowClient, h.playbackStreamClient = client, client, client, client
				node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: "yamby"}
				method := http.MethodGet
				if strings.Contains(path, "Authenticate") || strings.Contains(path, "PlaybackInfo") || strings.Contains(path, "Sessions") || strings.Contains(path, "Videos") {
					method = http.MethodPost
				}
				r := httptest.NewRequest(method, "https://proxy.example/node/secret"+path+"?deviceId=device-a&api_key=t", nil)
				res, err := h.handleNode(context.Background(), r, node, parsedRoute{Name: "node", Path: path}, nil, config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}
			if len(captured) != 2 || captured[0].URL.String() != captured[1].URL.String() || !reflect.DeepEqual(captured[0].Header, captured[1].Header) {
				t.Fatalf("historical identity changed a non-stream request: %v", captured)
			}
		})
	}
}
