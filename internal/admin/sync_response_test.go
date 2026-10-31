package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"embyproxy/internal/storage"
)

func TestSyncImportAcknowledgementsGatePruning(t *testing.T) {
	for _, tt := range []struct {
		name, reply                       string
		wantErr                           error
		added, updated, deleted, failures int
	}{
		{"missing", `{"ok":true}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"null", `{"ok":true,"results":null}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"object", `{"ok":true,"results":{}}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"empty", `{"ok":true,"results":[]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"partial", `{"ok":true,"results":[{"name":"new","ok":true}]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"malformed item", `{"ok":true,"results":[{"name":"new","ok":true},null]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"wrong name", `{"ok":true,"results":[{"name":"new","ok":true},{"name":"other","ok":true}]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"duplicate", `{"ok":true,"results":[{"name":"new","ok":true},{"name":"new","ok":true}]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"missing status", `{"ok":true,"results":[{"name":"new","ok":true},{"name":"update"}]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"string status", `{"ok":true,"results":[{"name":"new","ok":true},{"name":"update","ok":"true"}]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"missing error", `{"ok":true,"results":[{"name":"new","ok":true},{"name":"update","ok":false}]}`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"failed", `{"ok":true,"results":[{"name":"new","ok":false,"error":"rejected"},{"name":"update","ok":false,"error":"rejected"}]}`, errSyncImportFailed, 0, 0, 0, 2},
		{"partial success", `{"ok":true,"results":[{"name":"new","ok":true},{"name":"update","ok":false,"error":"rejected"}]}`, errSyncImportFailed, 1, 0, 0, 1},
		{"reordered success", `{"ok":true,"results":[{"name":"update","ok":true},{"name":"new","ok":true}]}`, nil, 1, 1, 1, 0},
		{"trailing garbage", `{"ok":true,"results":[]}garbage`, errInvalidSyncResponse, 0, 0, 0, 0},
		{"multiple objects", `{"ok":true} {"results":[]}`, errInvalidSyncResponse, 0, 0, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			deletes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				switch body["action"] {
				case "export":
					writeJSON(w, 200, map[string]any{"ok": true, "nodes": []any{
						map[string]any{"name": "update", "target": "https://old.example.com"},
						map[string]any{"name": "extra", "target": "https://extra.example.com"},
					}})
				case "import":
					fmt.Fprint(w, tt.reply)
				case "delete", "batchDelete":
					deletes++
					writeJSON(w, 200, map[string]any{"ok": true})
				default:
					t.Errorf("unexpected action %v", body["action"])
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			remote := newSyncRemote(storage.SyncTarget{URL: server.URL})
			defer remote.client.CloseIdleConnections()
			src := syncSource{order: []string{"new", "update"}, nodes: map[string]map[string]any{
				"new":    {"name": "new", "target": "https://new.example.com"},
				"update": {"name": "update", "target": "https://updated.example.com"},
			}}
			result := newSyncTargetResult(storage.SyncTarget{})
			err := remote.syncNodes(context.Background(), src, syncOptions{Apply: true, Prune: true}, &result)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			want := syncCompleted{Added: tt.added, Updated: tt.updated, Deleted: tt.deleted}
			if result.Completed != want || deletes != tt.deleted || result.PruneSkipped != (tt.wantErr != nil) || len(result.ImportFailures) != tt.failures {
				t.Fatalf("result = %+v, delete requests = %d", result, deletes)
			}
		})
	}
}

func TestSyncPartialBatchAndDeleteCounts(t *testing.T) {
	for _, failImport := range []bool{true, false} {
		t.Run(fmt.Sprint(failImport), func(t *testing.T) {
			imports, deletes := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				switch body["action"] {
				case "export":
					writeJSON(w, 200, map[string]any{"ok": true, "nodes": []any{map[string]any{"name": "extra1"}, map[string]any{"name": "extra2"}}})
				case "import":
					imports++
					if failImport && imports == 2 {
						writeJSON(w, 200, map[string]any{"ok": true})
						return
					}
					acks := []any{}
					for _, raw := range body["nodes"].([]any) {
						acks = append(acks, map[string]any{"name": raw.(map[string]any)["name"], "ok": true})
					}
					writeJSON(w, 200, map[string]any{"ok": true, "results": acks})
				case "delete":
					deletes++
					if deletes == 2 {
						writeJSON(w, 500, map[string]any{"ok": false, "error": "test failure"})
						return
					}
					writeJSON(w, 200, map[string]any{"ok": true})
				default:
					t.Errorf("unexpected action %v", body["action"])
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			r := newSyncRemote(storage.SyncTarget{URL: server.URL})
			defer r.client.CloseIdleConnections()
			src := syncSource{nodes: map[string]map[string]any{}}
			for i := 0; i < syncImportBatchSize+1; i++ {
				name := fmt.Sprintf("n%d", i)
				src.order = append(src.order, name)
				src.nodes[name] = map[string]any{"name": name}
			}
			result := newSyncTargetResult(storage.SyncTarget{})
			err := r.syncNodes(context.Background(), src, syncOptions{Apply: true, Prune: true}, &result)
			if err == nil {
				t.Fatal("expected failure")
			}
			if failImport {
				if !errors.Is(err, errInvalidSyncResponse) || deletes != 0 || result.Completed.Added != syncImportBatchSize || !result.PruneSkipped {
					t.Fatalf("result=%+v, error=%v", result, err)
				}
			} else if result.Completed.Added != syncImportBatchSize+1 || result.Completed.Deleted != 1 || deletes != 2 {
				t.Fatalf("result=%+v, deletes=%d", result, deletes)
			}
		})
	}
}

func TestSyncExportRequiresCompleteShape(t *testing.T) {
	for _, raw := range []string{`{}`, `{"nodes":null}`, `{"nodes":{}}`, `{"nodes":[null]}`, `{"nodes":[{}]}`, `{"nodes":[{"name":"n"},{"name":"n"}]}`} {
		t.Run(raw, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal([]byte(raw), &body); err != nil {
				t.Fatal(err)
			}
			if _, err := syncExportNodes(body); !errors.Is(err, errInvalidSyncResponse) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
