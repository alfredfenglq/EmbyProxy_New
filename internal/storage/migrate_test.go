package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func newMigrateTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestMigrateStoreSQLiteToSQLiteIsIdempotent(t *testing.T) {
	ctx := context.Background()
	src := newMigrateTestStore(t)
	dst := newMigrateTestStore(t)

	seed := []string{
		`INSERT INTO proxy_kv (k, v, updated_at) VALUES ('u:admin:node:alpha', '{"name":"alpha"}', 1000)`,
		`INSERT INTO proxy_kv (k, v, updated_at) VALUES ('system:config', '{}', 1001)`,
		`INSERT INTO keepalive_state (node, anchor_ts, last_play_ts, last_notify_day, notify_count_day, notify_count) VALUES ('admin:alpha', 900, 950, '2026-01-02', '2026-01-02', 1)`,
		`INSERT INTO play_sessions (k, day, last_ts) VALUES ('sess1', '2026-01-02', 100)`,
		`INSERT INTO play_events (k, day, last_ts) VALUES ('ev1', '2026-01-02', 100)`,
		`INSERT INTO playback_states (k, node, client, mode, item_key, last_event_ts, last_position_ticks, has_position, is_paused, closed, updated_at) VALUES ('st1', 'alpha', 'c', 'proxy', 'i', 100, 0, 0, 0, 0, 100)`,
		`INSERT INTO play_stats (day, node, client, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at) VALUES ('2026-01-02', 'alpha', 'c', 3, 60000, 7000, 1000, 6000, 2, 0, 100)`,
		`INSERT INTO play_buckets (bucket_start, node, client, mode, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at) VALUES (60000, 'alpha', 'c', 'proxy', 3, 60000, 7000, 1000, 6000, 2, 0, 100)`,
	}
	for _, q := range seed {
		if _, err := src.dbx().ExecContext(ctx, q); err != nil {
			t.Fatalf("seed %q error = %v", q, err)
		}
	}

	counts, err := MigrateStore(ctx, src, dst)
	if err != nil {
		t.Fatalf("MigrateStore() error = %v", err)
	}
	wantCounts := map[string]int64{
		"proxy_kv": 2, "keepalive_state": 1, "play_sessions": 1, "play_events": 1,
		"playback_states": 1, "play_stats": 1, "play_buckets": 1,
	}
	for table, want := range wantCounts {
		if counts[table] != want {
			t.Fatalf("MigrateStore() count[%s] = %d, want %d", table, counts[table], want)
		}
	}
	// Re-running must converge, not double-count.
	if _, err := MigrateStore(ctx, src, dst); err != nil {
		t.Fatalf("MigrateStore() second run error = %v", err)
	}
	var plays, bytesTotal int64
	if err := dst.dbx().QueryRowContext(ctx, `SELECT plays, bytes FROM play_stats WHERE day = '2026-01-02'`).Scan(&plays, &bytesTotal); err != nil {
		t.Fatalf("read migrated play_stats error = %v", err)
	}
	if plays != 3 || bytesTotal != 7000 {
		t.Fatalf("migrated play_stats = plays %d bytes %d, want 3 and 7000", plays, bytesTotal)
	}
	var kv string
	if err := dst.dbx().QueryRowContext(ctx, `SELECT v FROM proxy_kv WHERE k = 'u:admin:node:alpha'`).Scan(&kv); err != nil {
		t.Fatalf("read migrated proxy_kv error = %v", err)
	}
	if kv != `{"name":"alpha"}` {
		t.Fatalf("migrated proxy_kv = %q", kv)
	}
	if _, err := MigrateStore(ctx, src, src); err == nil {
		t.Fatalf("MigrateStore() with identical source and destination must fail")
	}
}
