package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestWebSocketHandshakePreservesExistingDeviceIDParameter(t *testing.T) {
	requests := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		// Inspect the actual outbound handshake without starting a tunnel.
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer upstream.Close()

	ids := identity.NewManager(nil)
	h := New(config.Config{}, newProxyTestStore(t), ids, logging.New("silent", false))
	for _, profile := range identity.ProfileKeys() {
		for _, impersonate := range []bool{true, false} {
			mode := "impersonated"
			if !impersonate {
				mode = "passthrough"
			}
			for _, tt := range []struct {
				name          string
				query         string
				hasDeviceID   bool
				authorization bool
			}{
				{name: "browser", query: "deviceId=source-device", hasDeviceID: true},
				{name: "capitalized", query: "DeviceId=source-device", hasDeviceID: true},
				{name: "duplicate aliases", query: "deviceId=first&deviceId=second&DEVICEID=third", hasDeviceID: true},
				{name: "empty parameter", query: "deviceId=", hasDeviceID: true},
				{name: "missing parameter"},
				{name: "standalone identity only", query: "X-Emby-Device-Id=source-device"},
				{name: "authorization only", authorization: true},
				{name: "authorization and device", query: "deviceId=source-device", hasDeviceID: true, authorization: true},
			} {
				t.Run(profile+"/"+mode+"/"+tt.name, func(t *testing.T) {
					const path = "/embywebsocket"
					rawQuery := "api_key=url%2Btoken%2Fvalue%3D&tag=keep%20me"
					if tt.query != "" {
						rawQuery += "&" + tt.query
					}
					req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node"+path+"?"+rawQuery, nil)
					req.Header.Set("Connection", "Upgrade")
					req.Header.Set("Upgrade", "websocket")
					req.Header.Set("User-Agent", "Source/1.0")
					if tt.authorization {
						req.Header.Set("X-Emby-Authorization", `Emby Client="Source", Device="PC", DeviceId="source-device", Version="1"`)
						req.Header.Set("X-Emby-Token", "header-token")
					}
					originalHeaders := req.Header.Clone()
					node := storage.Node{Name: "node", Target: upstream.URL, Impersonate: impersonate, ImpersonateProfile: profile}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					source, err := identity.WebSocketSourceDeviceID(req.Header, req.URL)
					if err != nil {
						t.Fatal(err)
					}
					snap := ids.Resolve(profile, source)
					if h.tryWebSocketTarget(ctx, httptest.NewRecorder(), req, node, snap, parsedRoute{Name: "node", Path: path}, upstream.URL, []string{upstream.URL}, "", "test", time.Now()) {
						t.Fatal("rejected handshake unexpectedly started a tunnel")
					}
					var out *http.Request
					select {
					case out = <-requests:
					case <-ctx.Done():
						t.Fatal("upstream did not receive a handshake")
					}
					if out.URL.Path != path || out.Header.Get("Connection") != "Upgrade" || out.Header.Get("Upgrade") != "websocket" {
						t.Fatalf("unexpected handshake: URL=%s, headers=%v", out.URL, out.Header)
					}
					if req.URL.RawQuery != rawQuery || !reflect.DeepEqual(req.Header, originalHeaders) {
						t.Fatal("inbound request was mutated")
					}
					if !impersonate {
						if out.URL.RawQuery != rawQuery || out.Header.Get("X-Emby-Authorization") != req.Header.Get("X-Emby-Authorization") || out.Header.Get("User-Agent") != req.Header.Get("User-Agent") {
							t.Fatalf("passthrough identity changed: URL=%s, headers=%v", out.URL, out.Header)
						}
						return
					}
					query := out.URL.Query()
					if query.Get("api_key") != "url+token/value=" || query.Get("tag") != "keep me" {
						t.Fatalf("token or business parameter changed: %v", query)
					}
					if tt.hasDeviceID {
						if got := query["deviceId"]; !reflect.DeepEqual(got, []string{snap.DeviceID}) {
							t.Fatalf("deviceId = %v, want [%s]", got, snap.DeviceID)
						}
						if got := query.Get("deviceId"); got == "source-device" || got == "first" {
							t.Fatalf("deviceId = %q, want the source device impersonated", got)
						}
					}
					for key := range query {
						if strings.EqualFold(key, "deviceId") && (!tt.hasDeviceID || key != "deviceId") {
							t.Fatalf("unexpected device ID parameter: %s=%v", key, query[key])
						}
					}
					if out.Header.Get("User-Agent") != snap.UserAgent {
						t.Fatalf("User-Agent = %q, want %q", out.Header.Get("User-Agent"), snap.UserAgent)
					}
					if tt.authorization {
						if !strings.Contains(out.Header.Get("X-Emby-Authorization"), snap.DeviceID) || out.Header.Get("X-Emby-Token") != "header-token" {
							t.Fatalf("header identity differs from the selected profile: %v", out.Header)
						}
					} else {
						for _, key := range []string{"Authorization", "X-Authorization", "X-Emby-Authorization", "X-MediaBrowser-Authorization", "X-Emby-Token", "X-MediaBrowser-Token"} {
							if out.Header.Get(key) != "" || query.Has(key) {
								t.Fatalf("browser handshake gained authentication field %s", key)
							}
						}
					}
				})
			}
		}
	}
}
