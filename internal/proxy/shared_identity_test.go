package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestSharedIdentityNodeRequests(t *testing.T) {
	for _, profile := range identity.ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			store := newProxyTestStore(t)
			ids := identity.NewManager(store)
			if err := ids.Init(context.Background()); err != nil {
				t.Fatal(err)
			}
			h := New(config.Config{}, store, ids, logging.New("silent", false))
			var sent *http.Request
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				sent = r.Clone(r.Context())
				return bytesResponse(200, []byte(`{}`), http.Header{"Content-Type": {"application/json"}}), nil
			})}
			h.noRedirectClient, h.playbackActionClient, h.playbackStreamClient, h.imageFollowClient = client, client, client, client
			node := storage.Node{Name: "node", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile, SharedDeviceIdentity: true}
			want := ids.ResolveShared(profile, "device-a").DeviceID
			send := func(n storage.Node, method, path, query, source string) *http.Request {
				t.Helper()
				sent = nil
				r := httptest.NewRequest(method, "https://proxy.example/"+n.Name+path+"?"+query, nil)
				r.Header.Set("X-Emby-Token", "token")
				if source != "" {
					r.Header.Set("X-Emby-Authorization", `Emby Client="Source", DeviceId="`+source+`"`)
				}
				res, err := h.handleNode(context.Background(), r, n, parsedRoute{Name: n.Name, Path: path}, nil, config.ProxyEnv{})
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if sent == nil {
					t.Fatal("no upstream request")
				}
				return sent
			}
			for _, source := range []string{"device-a", "device-b"} {
				for _, path := range []string{"/emby/Users/AuthenticateByName", "/emby/Items/1/PlaybackInfo", "/emby/Sessions/Playing"} {
					out := send(node, http.MethodPost, path, "", source)
					got := outboundDeviceIDRE.FindStringSubmatch(out.Header.Get("X-Emby-Authorization"))
					if len(got) != 2 || got[1] != want {
						t.Fatalf("%s identity = %v", path, got)
					}
					if v := out.URL.Query().Get("X-Emby-Device-Id"); v != "" && v != want {
						t.Fatal("query/header identity mismatch")
					}
				}
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, source := range []string{"", "device-a"} {
					out := send(node, method, "/Videos/1/stream.mkv", "deviceId=device-a&api_key=stream-token", source)
					if out.URL.Query().Get("deviceId") != want || out.URL.Query().Get("api_key") != "stream-token" {
						t.Fatalf("stream = %s", out.URL)
					}
					if out.Header.Get("X-Emby-Authorization") != "" {
						t.Fatal("stream gained identity header")
					}
				}
			}
			for _, value := range []string{want, "server-issued"} {
				out := send(node, http.MethodGet, "/Videos/1/stream.mkv", "deviceId="+value+"&api_key=t", "")
				if out.URL.Query().Get("deviceId") != value {
					t.Fatal("server-issued/shared ID changed")
				}
			}
			for _, path := range []string{"/emby/System/Info/Public", "/emby/Items/1/Images/Primary"} {
				out := send(node, http.MethodGet, path, "api_key=t", "device-a")
				if out.Header.Get("X-Emby-Authorization") != "" || out.URL.Query().Has("X-Emby-Device-Id") {
					t.Fatal("resource gained identity")
				}
			}
			out := send(node, http.MethodGet, "/emby/Users/account/Views", "", "")
			if out.Header.Get("X-Emby-Authorization") != "" || out.Header.Get("X-Emby-Token") != "token" {
				t.Fatal("missing-source semantics changed")
			}
			node.SharedDeviceIdentity = false
			out = send(node, http.MethodGet, "/emby/Users/account/Views", "", "device-a")
			got := outboundDeviceIDRE.FindStringSubmatch(out.Header.Get("X-Emby-Authorization"))
			if len(got) != 2 || got[1] != ids.Resolve(profile, "device-a").DeviceID {
				t.Fatal("disabled mode failed to restore v1 ID")
			}
			node.SharedDeviceIdentity = true
			node.Impersonate = false
			out = send(node, http.MethodGet, "/emby/Users/account/Views", "", "device-a")
			got = outboundDeviceIDRE.FindStringSubmatch(out.Header.Get("X-Emby-Authorization"))
			if len(got) != 2 || got[1] != "device-a" {
				t.Fatal("shared option changed non-impersonated request")
			}
		})
	}
}

func TestSharedIdentityWebSocket(t *testing.T) {
	requests := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer upstream.Close()
	ids := identity.NewManager(nil)
	h := New(config.Config{}, newProxyTestStore(t), ids, logging.New("silent", false))
	for _, profile := range identity.ProfileKeys() {
		for _, source := range []string{"device-a", "device-b"} {
			r := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/embywebsocket?deviceId="+source+"&api_key=token", nil)
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			r = r.WithContext(ctx)
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
			node := storage.Node{Name: "node", Target: upstream.URL, Impersonate: true, ImpersonateProfile: profile, SharedDeviceIdentity: true}
			h.handleWebSocket(httptest.NewRecorder(), r, node, parsedRoute{Name: "node", Path: "/embywebsocket"})
			select {
			case out := <-requests:
				if out.URL.Query().Get("deviceId") != ids.ResolveShared(profile, source).DeviceID || out.URL.Query().Get("api_key") != "token" {
					t.Fatalf("unexpected handshake %s", out.URL)
				}
			case <-ctx.Done():
				t.Fatal("no handshake")
			}
			cancel()
		}
	}
}
