package identity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestKnownStreamSourceExactMatches(t *testing.T) {
	m := NewManager(nil)
	for _, source := range []string{" Device-A ", "device-b"} {
		m.RememberSourceDevice(" Node ", source)
	}
	for _, tt := range []struct{ name, node, query, want string }{
		{"normalized source", "node", "deviceId=+DEVICE-A+&api_key=shared", "device-a"},
		{"second device sharing token", "NODE", "DeviceId=device-b&api_key=shared", "device-b"},
		{"no token requirement", "node", "deviceId=device-a", "device-a"},
		{"different node", "other", "deviceId=device-a", ""},
		{"unknown", "node", "deviceId=server-issued", ""},
		{"absent", "node", "api_key=t", ""},
		{"blank node", "", "deviceId=device-a", ""},
		{"first nonblank wins", "node", "deviceId=&DEVICEID=server-issued&deviceId=device-a", ""},
		{"recognized first nonblank", "node", "deviceId=&DEVICEID=device-a&deviceId=other", "device-a"},
		{"identity query is not bare", "node", "X-Emby-Device-Id=device-a", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.KnownStreamSource(tt.node, parseIdentityURL(t, tt.query))
			if err != nil || got != tt.want {
				t.Fatalf("KnownStreamSource = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	for _, raw := range []string{"deviceId=device-a&bad=%ZZ", "deviceId=device-a;bad"} {
		_, err := m.KnownStreamSource("node", parseIdentityURL(t, raw))
		if !errors.Is(err, ErrInvalidQueryEncoding) {
			t.Fatalf("query %q: error = %v", raw, err)
		}
	}
}

func TestKnownDevicesProtectDerivedIDs(t *testing.T) {
	m := NewManager(nil)
	m.RememberSourceDevice("node", "device-a")
	// Even a value later declared as a source cannot cause a known derived
	// device ID to be hashed a second time in the history-based fallback.
	for _, profile := range ProfileKeys() {
		derived := m.Resolve(profile, "device-a").DeviceID
		m.RememberSourceDevice("node", derived)
	}
	for _, profile := range ProfileKeys() {
		derived := m.Resolve(profile, "device-a").DeviceID
		if got, err := m.KnownStreamSource("node", parseIdentityURL(t, "deviceId="+strings.ToUpper(derived))); err != nil || got != "" {
			t.Fatalf("derived %s was treated as source: %q, %v", profile, got, err)
		}
	}
}

func TestKnownDevicesStayInMemory(t *testing.T) {
	store := newIdentityTestStore(t)
	m := NewManager(store)
	m.RememberSourceDevice("node", "device-a")
	u := parseIdentityURL(t, "deviceId=device-a")
	if got, err := m.KnownStreamSource("node", u); err != nil || got != "device-a" {
		t.Fatalf("in-memory source = %q, %v", got, err)
	}
	var count int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM proxy_kv WHERE k LIKE 'system:source_devices:%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stored %d source-device records, want none", count)
	}
	// Managers sharing the same database still have independent observations.
	if got, err := NewManager(store).KnownStreamSource("node", u); err != nil || got != "" {
		t.Fatalf("new manager restored a source: %q, %v", got, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Neither recording nor lookup may access even an unavailable database.
	fresh := NewManager(store)
	fresh.RememberSourceDevice("node", "device-b")
	if got, err := fresh.KnownStreamSource("node", parseIdentityURL(t, "deviceId=device-b")); err != nil || got != "device-b" {
		t.Fatalf("memory-only operation depended on the database: %q, %v", got, err)
	}
	if got, err := fresh.KnownStreamSource("other", u); err != nil || got != "" {
		t.Fatalf("unknown node lookup accessed the database: %q, %v", got, err)
	}
}

func TestKnownDevicesConcurrentObservations(t *testing.T) {
	m := NewManager(nil)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			source := fmt.Sprintf("device-%d", i)
			m.RememberSourceDevice("node", source)
			u := &url.URL{RawQuery: "deviceId=" + source}
			if got, err := m.KnownStreamSource("node", u); err != nil || got != source {
				t.Errorf("concurrent lookup = %q, %v", got, err)
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < 24; i++ {
		source := fmt.Sprintf("device-%d", i)
		if got, err := m.KnownStreamSource("node", parseIdentityURL(t, "deviceId="+source)); err != nil || got != source {
			t.Fatalf("lost in-memory observation: %q, %v", got, err)
		}
	}
}
