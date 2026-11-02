package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// postgresTestDSN returns the DSN for the optional live-PostgreSQL tests, or
// "" when they must be skipped. The DSN must point at a throwaway database:
// the tests create the application tables in it and drop them afterwards.
func postgresTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("EMBYPROXY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("EMBYPROXY_TEST_PG_DSN is not set, skipping live PostgreSQL tests")
	}
	return dsn
}

func dropPostgresTestTables(t *testing.T, store *Store) {
	t.Helper()
	for _, table := range []string{"play_buckets", "play_stats", "playback_states", "play_events", "play_sessions", "keepalive_state", "proxy_kv"} {
		if _, err := store.db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+table); err != nil {
			t.Fatalf("drop table %s error = %v", table, err)
		}
	}
}

func TestPostgresSmoke(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx := context.Background()
	store, err := NewWithDatabaseURL("", dsn)
	if err != nil {
		t.Fatalf("NewWithDatabaseURL() error = %v", err)
	}
	defer func() {
		dropPostgresTestTables(t, store)
		_ = store.Close()
	}()
	if !store.IsPG() {
		t.Fatalf("IsPG() = false, want true")
	}
	if err := store.KV().Put(ctx, "smoke:key", "smoke-value"); err != nil {
		t.Fatalf("KV.Put() error = %v", err)
	}
	value, ok, err := store.KV().Get(ctx, "smoke:key")
	if err != nil || !ok || value != "smoke-value" {
		t.Fatalf("KV.Get() = %q, %v, %v", value, ok, err)
	}
	node := Node{Name: "smoke", Target: "https://upstream.example"}
	if err := store.SaveNode(ctx, "admin", node); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	got, err := store.GetNode(ctx, "admin", "smoke")
	if err != nil || got == nil || got.Target != node.Target {
		t.Fatalf("GetNode() = %+v, %v", got, err)
	}
	if err := store.LogPlaybackTraffic(ctx, PlaybackInput{
		Node:          node,
		IsPlayback:    true,
		Mode:          "proxy",
		Method:        "GET",
		RequestURL:    "/emby/Videos/1/stream",
		InboundBytes:  100,
		OutboundBytes: 200,
	}); err != nil {
		t.Fatalf("LogPlaybackTraffic() error = %v", err)
	}
	stats, err := store.GetPlayStats(ctx, 7)
	if err != nil {
		t.Fatalf("GetPlayStats() error = %v", err)
	}
	found := false
	for _, stat := range stats {
		if stat.Node == "smoke" && stat.Bytes == 300 {
			found = true
		}
	}
	if !found {
		t.Fatalf("GetPlayStats() did not contain the expected smoke row: %+v", stats)
	}
}

func TestMigrateSQLiteToPostgres(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx := context.Background()
	src, err := New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatalf("New() source error = %v", err)
	}
	defer func() { _ = src.Close() }()
	if _, err := src.dbx().ExecContext(ctx, `INSERT INTO proxy_kv (k, v, updated_at) VALUES ('mig:key', 'mig-value', 42)`); err != nil {
		t.Fatalf("seed source error = %v", err)
	}
	dst, err := NewWithDatabaseURL("", dsn)
	if err != nil {
		t.Fatalf("NewWithDatabaseURL() error = %v", err)
	}
	defer func() {
		dropPostgresTestTables(t, dst)
		_ = dst.Close()
	}()
	counts, err := MigrateStore(ctx, src, dst)
	if err != nil {
		t.Fatalf("MigrateStore() error = %v", err)
	}
	if counts["proxy_kv"] != 1 {
		t.Fatalf("MigrateStore() proxy_kv count = %d, want 1", counts["proxy_kv"])
	}
	value, ok, err := dst.KV().Get(ctx, "mig:key")
	if err != nil || !ok || value != "mig-value" {
		t.Fatalf("migrated KV.Get() = %q, %v, %v", value, ok, err)
	}
}

func TestPostgresPlayStatsServerUpgrade(t *testing.T) {
	dsn := postgresTestDSN(t)
	ctx := context.Background()
	store, err := NewWithDatabaseURL("", dsn)
	if err != nil {
		t.Fatalf("NewWithDatabaseURL() error = %v", err)
	}
	defer func() {
		dropPostgresTestTables(t, store)
		_ = store.Close()
	}()

	// Replace the current table with the pre-server schema and one old row.
	if _, err := store.db.ExecContext(ctx, `DROP TABLE IF EXISTS play_stats`); err != nil {
		t.Fatalf("drop play_stats error = %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE play_stats (
		day TEXT NOT NULL, node TEXT NOT NULL, client TEXT NOT NULL,
		plays BIGINT DEFAULT 0, playback_ms BIGINT DEFAULT 0,
		bytes BIGINT DEFAULT 0, inbound_bytes BIGINT DEFAULT 0,
		outbound_bytes BIGINT DEFAULT 0, sessions BIGINT DEFAULT 0,
		errors BIGINT DEFAULT 0, updated_at BIGINT NOT NULL,
		CONSTRAINT play_stats_old_pk PRIMARY KEY(day, node, client)
	)`); err != nil {
		t.Fatalf("create old play_stats error = %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO play_stats (day, node, client, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at) VALUES ('2026-01-02', 'alpha', 'c', 3, 60000, 7000, 1000, 6000, 2, 0, 100)`); err != nil {
		t.Fatalf("seed old play_stats error = %v", err)
	}

	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema() error = %v", err)
	}

	var plays int64
	var server string
	if err := store.db.QueryRowContext(ctx, `SELECT plays, server FROM play_stats WHERE day = '2026-01-02'`).Scan(&plays, &server); err != nil {
		t.Fatalf("read upgraded play_stats error = %v", err)
	}
	if plays != 3 || server != "" {
		t.Fatalf("upgraded old row = plays %d server %q, want 3 and empty", plays, server)
	}
	for _, srv := range []string{"A", "B"} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO play_stats (day, node, client, server, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at) VALUES ('2026-01-02', 'alpha', 'c', $1, 1, 0, 0, 0, 0, 0, 0, 101)`, srv); err != nil {
			t.Fatalf("insert server %s error = %v", srv, err)
		}
	}
	var count int64
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM play_stats WHERE day = '2026-01-02' AND node = 'alpha' AND client = 'c'`).Scan(&count); err != nil {
		t.Fatalf("count play_stats error = %v", err)
	}
	if count != 3 {
		t.Fatalf("play_stats rows = %d, want 3 (old '' + A + B)", count)
	}
}
