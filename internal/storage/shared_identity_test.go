package storage

import "testing"

func TestSharedDeviceIdentityStorageRoundTrip(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		n := Node{Name: "node", Target: "https://example.com", Impersonate: true, SharedDeviceIdentity: enabled}
		packed, err := PackNode(n)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := UnpackNode(n.Name, packed)
		if !ok || got.SharedDeviceIdentity != enabled {
			t.Fatalf("round trip = %+v, %v", got, ok)
		}
	}
	legacy, ok := UnpackNode("legacy", `{"t":"https://example.com"}`)
	if !ok || legacy.SharedDeviceIdentity {
		t.Fatal("legacy node must default to per-source identity")
	}
}
