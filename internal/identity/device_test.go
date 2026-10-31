package identity

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"embyproxy/internal/storage"
)

const goldenSourceDeviceID = "0123456789abcdef"

var desktopNameRE = regexp.MustCompile(`^DESKTOP-[A-Z0-9]{7}$`)

func TestResolveDeviceIDGoldenValues(t *testing.T) {
	// These values pin the v1 derivation. Changing them changes every
	// impersonated device and invalidates tokens bound to devices upstream.
	for _, tt := range []struct{ profile, deviceID, deviceName string }{
		{"yamby", "d035fbd5-0292-437f-9249-beec04a1bbfe", "Android"},
		{"hills_android", "428a557da3096d25", "diting"},
		{"hills_windows", "376cdd1bdb7b489a1ff551d46c0ecac7", "DESKTOP-IPRCZZM"},
	} {
		t.Run(tt.profile, func(t *testing.T) {
			snap := NewManager(nil).Resolve(tt.profile, goldenSourceDeviceID)
			if snap.DeviceID != tt.deviceID || snap.DeviceName != tt.deviceName {
				t.Fatalf("Resolve() = %q/%q, want %q/%q", snap.DeviceID, snap.DeviceName, tt.deviceID, tt.deviceName)
			}
			if snap.SourceDeviceID != goldenSourceDeviceID {
				t.Fatalf("SourceDeviceID = %q, want %q", snap.SourceDeviceID, goldenSourceDeviceID)
			}
		})
	}
}

func TestResolveKeepsDeviceStableAcrossInstances(t *testing.T) {
	for _, profile := range ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			// Separate managers stand in for separate proxy instances and routes.
			first := NewManager(nil).Resolve(profile, "Source-Device")
			second := NewManager(nil).Resolve(profile, "  source-device ")
			if first.DeviceID == "" || first.DeviceID != second.DeviceID || first.DeviceName != second.DeviceName {
				t.Fatalf("same source device resolved to %q/%q and %q/%q", first.DeviceID, first.DeviceName, second.DeviceID, second.DeviceName)
			}
			if other := NewManager(nil).Resolve(profile, "other-device"); other.DeviceID == first.DeviceID {
				t.Fatalf("different source devices share %q", first.DeviceID)
			}
			if !validDeviceID(GetProfile(profile), first.DeviceID) || first.DeviceID != strings.ToLower(first.DeviceID) {
				t.Fatalf("DeviceID = %q, want lowercase %s format", first.DeviceID, profile)
			}
			if GetProfile(profile).DeviceIDFormat == "uuid" && (first.DeviceID[14] != '4' || !strings.ContainsRune("89ab", rune(first.DeviceID[19]))) {
				t.Fatalf("DeviceID = %q, want UUID version 4 variant 1", first.DeviceID)
			}
		})
	}
}

func TestResolveSeparatesProfiles(t *testing.T) {
	android := NewManager(nil).Resolve("hills_android", goldenSourceDeviceID).DeviceID
	windows := NewManager(nil).Resolve("hills_windows", goldenSourceDeviceID).DeviceID
	if strings.HasPrefix(windows, android) {
		t.Fatalf("hills_android %q is a prefix of hills_windows %q", android, windows)
	}
}

func TestResolveWithoutSourceCarriesNoDeviceIdentity(t *testing.T) {
	for _, profile := range ProfileKeys() {
		snap := NewManager(nil).Resolve(profile, "  ")
		selected := GetProfile(profile)
		if snap.DeviceID != "" || snap.SourceDeviceID != "" {
			t.Fatalf("%s: snapshot without source = %+v, want no device identity", profile, snap)
		}
		if snap.Profile != selected.Key || snap.ClientName != selected.ClientName || snap.UserAgent != selected.UserAgent {
			t.Fatalf("%s: snapshot without source = %+v, want static profile fields", profile, snap)
		}
	}
}

func TestInitHillsWindowsDeviceName(t *testing.T) {
	ctx := context.Background()

	t.Run("existing deployment keeps saved name", func(t *testing.T) {
		store := newIdentityTestStore(t)
		saved := persisted{Profiles: map[string]deviceState{"hills_windows": {DeviceName: "DESKTOP-016875", DeviceID: testHillsWindowsID}}}
		if err := store.KV().Put(ctx, identityKey, saved); err != nil {
			t.Fatal(err)
		}
		m := NewManager(store)
		if err := m.Init(ctx); err != nil {
			t.Fatal(err)
		}
		for _, source := range []string{"device-a", "device-b"} {
			if got := m.Resolve("hills_windows", source).DeviceName; got != "DESKTOP-016875" {
				t.Fatalf("DeviceName for %s = %q, want saved DESKTOP-016875", source, got)
			}
		}
		var stored persisted
		if _, err := store.KV().GetJSON(ctx, identityKey, &stored); err != nil {
			t.Fatal(err)
		}
		if got := stored.Profiles["hills_windows"]; got.DeviceName != "DESKTOP-016875" || got.DeviceID != testHillsWindowsID {
			t.Fatalf("stored hills_windows state = %+v, want retained", got)
		}
	})

	t.Run("new deployment derives name per device", func(t *testing.T) {
		store := newIdentityTestStore(t)
		m := NewManager(store)
		if err := m.Init(ctx); err != nil {
			t.Fatal(err)
		}
		a := m.Resolve("hills_windows", "device-a").DeviceName
		b := m.Resolve("hills_windows", "device-b").DeviceName
		if !desktopNameRE.MatchString(a) || !desktopNameRE.MatchString(b) || a == b {
			t.Fatalf("derived names = %q, %q, want distinct DESKTOP-[A-Z0-9]{7}", a, b)
		}
		var stored persisted
		if _, err := store.KV().GetJSON(ctx, identityKey, &stored); err != nil {
			t.Fatal(err)
		}
		state := stored.Profiles["hills_windows"]
		if state.DeviceName != "" || !validDeviceID(GetProfile("hills_windows"), state.DeviceID) {
			t.Fatalf("stored hills_windows state = %+v, want no name and a retained random ID", state)
		}
		restarted := NewManager(store)
		if err := restarted.Init(ctx); err != nil {
			t.Fatal(err)
		}
		if got := restarted.Resolve("hills_windows", "device-a").DeviceName; got != a {
			t.Fatalf("DeviceName after restart = %q, want %q", got, a)
		}
	})
}

func TestSourceDeviceIDPriority(t *testing.T) {
	auth := func(id string) string {
		return `Emby Client="Source", Device="PC", DeviceId="` + id + `", Version="1", Token="token"`
	}
	for _, tt := range []struct {
		name    string
		headers http.Header
		query   string
		want    string
	}{
		{"authorization header wins", http.Header{"X-Emby-Authorization": {auth("auth-header")}, "X-Emby-Device-Id": {"device-header"}}, "X-Emby-Authorization=" + url.QueryEscape(auth("auth-query")) + "&X-Emby-Device-Id=device-query", "auth-header"},
		{"media browser scheme", http.Header{"Authorization": {`MediaBrowser Client="Source", DeviceId=unquoted-id, Version="1"`}}, "", "unquoted-id"},
		{"underscore authorization alias", http.Header{"X_Emby_Authorization": {auth("alias-header")}}, "", "alias-header"},
		{"device header", http.Header{"X-Emby-Authorization": {`Emby Token="token"`}, "X-Emby-Device-Id": {"device-header"}}, "X-Emby-Device-Id=device-query", "device-header"},
		{"media browser device header", http.Header{"X-MediaBrowser-Device-Id": {"mb-device"}}, "", "mb-device"},
		{"query authorization", http.Header{}, "X-Emby-Device-Id=device-query&X-Emby-Authorization=" + url.QueryEscape(auth("auth-query")), "auth-query"},
		{"query device id in order", http.Header{}, "x_emby_device_id=first&X-Emby-Device-Id=second", "first"},
		{"bearer authorization ignored", http.Header{"Authorization": {`Bearer DeviceId="bearer"`}}, "", ""},
		{"bare device id is server issued", http.Header{}, "DeviceId=server-device&deviceId=other", ""},
		{"token only", http.Header{"X-Emby-Token": {"token"}}, "api_key=token", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := SourceDeviceID(tt.headers, parseIdentityURL(t, tt.query)); err != nil || got != tt.want {
				t.Fatalf("SourceDeviceID() = %q, %v; want %q, nil", got, err, tt.want)
			}
		})
	}
}

func TestWebSocketSourceDeviceIDFallsBackToBareDeviceID(t *testing.T) {
	u := parseIdentityURL(t, "deviceId=+&DEVICEID=first&deviceId=second")
	if got, err := WebSocketSourceDeviceID(http.Header{}, u); err != nil || got != "first" {
		t.Fatalf("WebSocketSourceDeviceID() = %q, %v; want first, nil", got, err)
	}
	headers := http.Header{"X-Emby-Authorization": {`Emby DeviceId="auth-device"`}}
	if got, err := WebSocketSourceDeviceID(headers, u); err != nil || got != "auth-device" {
		t.Fatalf("WebSocketSourceDeviceID() = %q, %v; want auth-device, nil", got, err)
	}
}

func TestRequestWithoutSourceDeviceKeepsOnlyToken(t *testing.T) {
	manager := NewManager(nil)
	for _, profile := range ProfileKeys() {
		for _, tt := range []struct {
			name    string
			headers http.Header
			query   string
		}{
			{"header authorization", http.Header{"X-Emby-Authorization": {`Emby Client="Source", Device="PC", Version="1", Token="auth-token"`}}, "X-Emby-Client=Source&X-Emby-Device-Name=PC&tag=v1"},
			{"query authorization", http.Header{}, "X-Emby-Authorization=" + url.QueryEscape(`Emby Client="Source", Device="PC", Version="1", Token="auth-token"`) + "&X-Emby-Client=Source&tag=v1"},
		} {
			t.Run(profile+"/"+tt.name, func(t *testing.T) {
				headers := tt.headers.Clone()
				u := parseIdentityURL(t, tt.query)
				source, err := SourceDeviceID(headers, u)
				if err != nil {
					t.Fatal(err)
				}
				snap := manager.Resolve(profile, source)

				ApplyToURL(u, headers, snap)
				ApplyToHeaders(headers, snap)

				if got := headers.Get("X-Emby-Authorization"); got != "" {
					t.Fatalf("X-Emby-Authorization = %q, want absent without a source device", got)
				}
				if got := headers.Get("X-Emby-Token"); got != "auth-token" {
					t.Fatalf("X-Emby-Token = %q, want auth-token", got)
				}
				if got, want := u.Query(), (url.Values{"tag": {"v1"}}); !reflect.DeepEqual(got, want) {
					t.Fatalf("query = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestNormalizeImpersonatedStreamDeviceID(t *testing.T) {
	for _, profile := range ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			manager := NewManager(nil)
			current := manager.Resolve(profile, "Current-Device")
			manager.Resolve(profile, "earlier-device")
			for _, tt := range []struct{ name, query, wantKey, want string }{
				{"server issued device stays", "deviceId=server-issued&api_key=t", "deviceId", "server-issued"},
				{"current source device", "DeviceId=current-device&api_key=t", "DeviceId", current.DeviceID},
				{"earlier source is not this request source", "DeviceId=EARLIER-DEVICE&api_key=t", "DeviceId", "EARLIER-DEVICE"},
				{"first non-blank value", "DeviceId=&deviceid=server-issued&api_key=t", "deviceid", "server-issued"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					u, err := url.Parse("https://example.test/emby/Videos/1/stream.mp4?" + tt.query)
					if err != nil {
						t.Fatal(err)
					}
					if err := NormalizeImpersonatedResource(u, http.Header{}, current, ResourceStream); err != nil {
						t.Fatal(err)
					}
					query := u.Query()
					if got := query[tt.wantKey]; !reflect.DeepEqual(got, []string{tt.want}) {
						t.Fatalf("%s = %v, want [%s]; raw query: %s", tt.wantKey, got, tt.want, u.RawQuery)
					}
					for key := range query {
						if strings.EqualFold(key, "deviceid") && key != tt.wantKey {
							t.Fatalf("unexpected device parameter %s; raw query: %s", key, u.RawQuery)
						}
					}
					if got := query.Get("api_key"); got != "t" {
						t.Fatalf("api_key = %q, want t", got)
					}
				})
			}
		})
	}
}

func newIdentityTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}
