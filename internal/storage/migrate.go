package storage

import (
	"context"
	"fmt"
	"strings"
)

// migrateTable describes one of the tables copied by MigrateStore. The
// column order must match the table definition in sqliteSchema.
type migrateTable struct {
	name    string
	columns []string
	pk      []string
}

// migrateTables lists every table that holds user-visible state: the
// key/value store (nodes, system/TG/2FA/sync configuration, identity) plus
// the keepalive and playback statistics tables. Anything else on disk
// (image cache, traffic captures, console logs) is per-machine by design
// and is intentionally not migrated.
var migrateTables = []migrateTable{
	{name: "proxy_kv", columns: []string{"k", "v", "updated_at"}, pk: []string{"k"}},
	{name: "keepalive_state", columns: []string{"node", "anchor_ts", "last_play_ts", "last_notify_day", "notify_count_day", "notify_count"}, pk: []string{"node"}},
	{name: "play_sessions", columns: []string{"k", "day", "last_ts"}, pk: []string{"k"}},
	{name: "play_events", columns: []string{"k", "day", "last_ts"}, pk: []string{"k"}},
	{name: "playback_states", columns: []string{"k", "node", "client", "mode", "item_key", "last_event_ts", "last_position_ticks", "has_position", "is_paused", "closed", "updated_at"}, pk: []string{"k"}},
	{name: "play_stats", columns: []string{"day", "node", "client", "plays", "playback_ms", "bytes", "inbound_bytes", "outbound_bytes", "sessions", "errors", "updated_at"}, pk: []string{"day", "node", "client"}},
	{name: "play_buckets", columns: []string{"bucket_start", "node", "client", "mode", "plays", "playback_ms", "bytes", "inbound_bytes", "outbound_bytes", "sessions", "errors", "updated_at"}, pk: []string{"bucket_start", "node", "client", "mode"}},
}

// MigrateStore copies every row of the seven state tables from src to dst.
// Destination rows are overwritten (SET col = excluded.col), never added
// to, so re-running the migration after a partial or repeated run converges
// to the source contents instead of double-counting statistics. The source
// store is only read, never modified or deleted. It returns the number of
// rows copied per table. Callers that need dialect guarantees (for example
// the migrate-sqlite-to-pg command, which requires a SQLite source and a
// PostgreSQL destination) must check src.IsPG()/dst.IsPG() themselves;
// this function works between any two stores.
func MigrateStore(ctx context.Context, src, dst *Store) (map[string]int64, error) {
	if src == nil || dst == nil {
		return nil, fmt.Errorf("migrate: source and destination stores are required")
	}
	if src == dst {
		return nil, fmt.Errorf("migrate: source and destination are the same store")
	}
	counts := map[string]int64{}
	for _, table := range migrateTables {
		n, err := migrateTableRows(ctx, src, dst, table)
		if err != nil {
			return counts, err
		}
		counts[table.name] = n
	}
	return counts, nil
}

func migrateTableRows(ctx context.Context, src, dst *Store, table migrateTable) (int64, error) {
	rows, err := src.dbx().QueryContext(ctx, `SELECT `+strings.Join(table.columns, ", ")+` FROM `+table.name+` ORDER BY `+strings.Join(table.pk, ", "))
	if err != nil {
		return 0, fmt.Errorf("migrate %s: read source: %w", table.name, err)
	}
	type row struct {
		values []any
	}
	var data []row
	for rows.Next() {
		vals := make([]any, len(table.columns))
		ptrs := make([]any, len(table.columns))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			rows.Close()
			return 0, fmt.Errorf("migrate %s: scan source row: %w", table.name, err)
		}
		for i, v := range vals {
			// database/sql may hand TEXT columns back as []byte; the
			// PostgreSQL driver would encode []byte as bytea, which does
			// not fit a TEXT column, so normalise to string here.
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		data = append(data, row{values: vals})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("migrate %s: read source: %w", table.name, err)
	}
	rows.Close()

	placeholders := make([]string, len(table.columns))
	for i := range placeholders {
		placeholders[i] = "?"
	}
	assignments := make([]string, 0, len(table.columns))
	for _, col := range table.columns {
		if isPKColumn(table.pk, col) {
			continue
		}
		assignments = append(assignments, col+" = excluded."+col)
	}
	insert := `INSERT INTO ` + table.name + ` (` + strings.Join(table.columns, ", ") + `) VALUES (` + strings.Join(placeholders, ", ") + `)` +
		` ON CONFLICT(` + strings.Join(table.pk, ", ") + `) DO UPDATE SET ` + strings.Join(assignments, ", ")

	tx, err := dst.dbx().BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("migrate %s: begin destination transaction: %w", table.name, err)
	}
	defer tx.Rollback()
	for _, r := range data {
		if _, err := tx.ExecContext(ctx, insert, r.values...); err != nil {
			return 0, fmt.Errorf("migrate %s: write destination: %w", table.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("migrate %s: commit destination: %w", table.name, err)
	}
	return int64(len(data)), nil
}

func isPKColumn(pk []string, col string) bool {
	for _, p := range pk {
		if p == col {
			return true
		}
	}
	return false
}
