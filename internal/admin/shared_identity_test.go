package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"embyproxy/internal/storage"
	"embyproxy/internal/validators"
)

func TestSharedDeviceIdentityUI(t *testing.T) {
	node, err := exec.LookPath("node")
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("Node.js is required for UI tests")
	}
	if err != nil {
		t.Fatal(err)
	}
	const script = "testdata/shared_identity_test.cjs"
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, node, "--test", script).CombinedOutput(); err != nil {
		t.Fatalf("UI tests failed: %v\n%s", err, output)
	}
}

func TestSharedDeviceIdentityExportImport(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		n := storage.Node{Name: "node", Target: "https://example.com", Impersonate: true, SharedDeviceIdentity: enabled, KeepaliveMaxPerDay: 1}
		raw, err := json.Marshal(exportNode(n))
		if err != nil {
			t.Fatal(err)
		}
		var input map[string]any
		if err := json.Unmarshal(raw, &input); err != nil {
			t.Fatal(err)
		}
		if input["sharedDeviceIdentity"] != enabled {
			t.Fatal("export lost setting")
		}
		result := validators.ValidateNodeInput(input)
		if result.Error != "" || result.Node.SharedDeviceIdentity != enabled {
			t.Fatalf("import = %+v", result)
		}
		delete(input, "sharedDeviceIdentity")
		result = validators.ValidateNodeInput(input)
		if result.Error != "" || result.Node.SharedDeviceIdentity {
			t.Fatalf("legacy default = %+v", result)
		}
	}
}
