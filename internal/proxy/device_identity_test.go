package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

var outboundDeviceIDRE = regexp.MustCompile(`DeviceId="?([^",\s]+)`)

func TestHandleNodeDerivesImpersonatedDevicePerSourceDevice(t *testing.T) {
	for _, profile := range identity.ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			var upstreamReq *http.Request
			h := New(config.Config{}, newProxyTestStore(t), identity.NewManager(nil), logging.New("silent", false))
			h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				upstreamReq = req.Clone(req.Context())
				upstreamReq.Header = cloneHeader(req.Header)
				return bytesResponse(http.StatusOK, []byte("{}"), http.Header{"Content-Type": {"application/json"}}), nil
			})}
			node := storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example", Impersonate: true, ImpersonateProfile: profile}
			const path = "/emby/Users/account/Views"
			send := func(sourceDevice string) *http.Request {
				t.Helper()
				upstreamReq = nil
				req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret"+path+"?tag=v1", nil)
				auth := `Emby Client="Source", Device="PC", Version="1"`
				if sourceDevice != "" {
					auth = `Emby Client="Source", Device="PC", DeviceId="` + sourceDevice + `", Version="1"`
				}
				req.Header.Set("X-Emby-Authorization", auth)
				req.Header.Set("X-Emby-Token", "header-token")
				res, err := h.handleNode(context.Background(), req, node, parsedRoute{Name: "node", Secret: "secret", Path: path}, nil, config.ProxyEnv{})
				if err != nil {
					t.Fatalf("handleNode() error = %v", err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if upstreamReq == nil {
					t.Fatal("upstream request was not sent")
				}
				return upstreamReq
			}
			deviceOf := func(req *http.Request) string {
				match := outboundDeviceIDRE.FindStringSubmatch(req.Header.Get("X-Emby-Authorization"))
				if match == nil {
					t.Fatalf("X-Emby-Authorization = %q, want a device ID", req.Header.Get("X-Emby-Authorization"))
				}
				return match[1]
			}

			first := send("device-a")
			want := identity.NewManager(nil).Resolve(profile, "device-a").DeviceID
			if got := deviceOf(first); got != want {
				t.Fatalf("DeviceId = %q, want derived %q", got, want)
			}
			if got := deviceOf(send("device-a")); got != want {
				t.Fatalf("repeated DeviceId = %q, want stable %q", got, want)
			}
			if got := deviceOf(send("device-b")); got == want {
				t.Fatalf("device-b shares device-a's DeviceId %q", got)
			}
			if outbound := first.URL.RawQuery + fmt.Sprint(first.Header); strings.Contains(outbound, "device-a") {
				t.Fatalf("source device ID leaked upstream: %s", outbound)
			}
			if query := first.URL.Query(); query.Has("X-Emby-Device-Id") && query.Get("X-Emby-Device-Id") != want {
				t.Fatalf("query X-Emby-Device-Id = %q, want header DeviceId %q", query.Get("X-Emby-Device-Id"), want)
			}

			anonymous := send("")
			if got := anonymous.Header.Get("X-Emby-Authorization"); got != "" {
				t.Fatalf("X-Emby-Authorization = %q, want absent without a source device", got)
			}
			if got := anonymous.Header.Get("X-Emby-Token"); got != "header-token" {
				t.Fatalf("X-Emby-Token = %q, want header-token", got)
			}
			for _, key := range []string{"X-Emby-Authorization", "X-Emby-Device-Id", "X-Emby-Client"} {
				if anonymous.URL.Query().Has(key) {
					t.Fatalf("query %s present without a source device: %s", key, anonymous.URL.RawQuery)
				}
			}
		})
	}
}
