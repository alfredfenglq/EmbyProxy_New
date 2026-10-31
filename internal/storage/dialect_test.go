package storage

import "testing"

func TestConvertPlaceholders(t *testing.T) {
	for _, tt := range []struct {
		name  string
		query string
		want  string
	}{
		{name: "no placeholders", query: "SELECT 1", want: "SELECT 1"},
		{name: "single", query: "SELECT v FROM proxy_kv WHERE k = ?", want: "SELECT v FROM proxy_kv WHERE k = $1"},
		{name: "multiple", query: "INSERT INTO t (a, b, c) VALUES (?, ?, ?)", want: "INSERT INTO t (a, b, c) VALUES ($1, $2, $3)"},
		{name: "repeated in update", query: "UPDATE t SET a = ?, b = ? WHERE c = ?", want: "UPDATE t SET a = $1, b = $2 WHERE c = $3"},
		{name: "literal question mark untouched", query: "SELECT 'what?' FROM t WHERE k = ?", want: "SELECT 'what?' FROM t WHERE k = $1"},
		{name: "escaped quote in literal", query: "SELECT 'it''s ?' FROM t WHERE k = ?", want: "SELECT 'it''s ?' FROM t WHERE k = $1"},
		{name: "limit offset", query: "SELECT k FROM proxy_kv WHERE k LIKE ? ORDER BY k LIMIT ? OFFSET ?", want: "SELECT k FROM proxy_kv WHERE k LIKE $1 ORDER BY k LIMIT $2 OFFSET $3"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertPlaceholders(tt.query); got != tt.want {
				t.Fatalf("convertPlaceholders(%q) = %q, want %q", tt.query, got, tt.want)
			}
		})
	}
}

func TestConvertQueryDialects(t *testing.T) {
	sqlite := "INSERT INTO play_stats (day, updated_at) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET updated_at = MAX(play_stats.updated_at, excluded.updated_at)"
	if got := convertQuery(false, sqlite); got != sqlite {
		t.Fatalf("SQLite query must pass through untouched, got %q", got)
	}
	want := "INSERT INTO play_stats (day, updated_at) VALUES ($1, $2) ON CONFLICT(day) DO UPDATE SET updated_at = GREATEST(play_stats.updated_at, excluded.updated_at)"
	if got := convertQuery(true, sqlite); got != want {
		t.Fatalf("convertQuery(true, ...) = %q, want %q", got, want)
	}
}
