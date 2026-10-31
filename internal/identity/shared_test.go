package identity

import (
	"context"
	"net/url"
	"reflect"
	"testing"
)

func TestSharedIdentityPersistsWithoutChangingDerivedIdentity(t *testing.T) {
	ctx := context.Background()
	store := newIdentityTestStore(t)
	m := NewManager(store)
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	var saved persisted
	if _, err := store.KV().GetJSON(ctx, identityKey, &saved); err != nil {
		t.Fatal(err)
	}
	for _, profile := range ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			original := m.Resolve(profile, "device-a")
			a, b := m.ResolveShared(profile, "device-a"), m.ResolveShared(profile, "device-b")
			if a.DeviceID != saved.Profiles[profile].DeviceID || a.DeviceID != b.DeviceID || a.DeviceName != b.DeviceName {
				t.Fatalf("shared identities differ: %+v / %+v", a, b)
			}
			m.RememberSourceDevice("node", a.DeviceID)
			if source, err := m.KnownStreamSource("node", &url.URL{RawQuery: "deviceId=" + a.DeviceID}); err != nil || source != "" {
				t.Fatalf("shared ID must not be treated as a source: %q, %v", source, err)
			}
			if a.SourceDeviceID != "device-a" || b.SourceDeviceID != "device-b" {
				t.Fatal("lost source identity")
			}
			if got := m.ResolveShared(profile, " "); got.DeviceID != "" || got.SourceDeviceID != "" {
				t.Fatal("invented missing identity")
			}
			if got := m.Resolve(profile, "device-a"); got != original {
				t.Fatal("v1 identity changed after toggling")
			}
			restarted := NewManager(store)
			if err := restarted.Init(ctx); err != nil {
				t.Fatal(err)
			}
			if got := restarted.ResolveShared(profile, "device-a"); got != a {
				t.Fatalf("identity changed after restart: %+v / %+v", got, a)
			}
		})
	}
	var after persisted
	if _, err := store.KV().GetJSON(ctx, identityKey, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved, after) {
		t.Fatal("shared mode modified persisted identity")
	}
}

func TestSharedIdentityKeepsLegacyWindowsName(t *testing.T) {
	store := newIdentityTestStore(t)
	saved := persisted{Profiles: map[string]deviceState{"hills_windows": {DeviceID: testHillsWindowsID, DeviceName: "DESKTOP-LEGACY"}}}
	if err := store.KV().Put(context.Background(), identityKey, saved); err != nil {
		t.Fatal(err)
	}
	m := NewManager(store)
	if err := m.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := m.ResolveShared("hills_windows", "device-a")
	if got.DeviceID != testHillsWindowsID || got.DeviceName != "DESKTOP-LEGACY" {
		t.Fatalf("legacy identity lost: %+v", got)
	}
}
