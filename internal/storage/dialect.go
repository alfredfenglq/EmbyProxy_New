package storage

import (
	"context"
	"database/sql"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgreSQL connection pool defaults. SQLite keeps MaxOpenConns(1) in New;
// only the PostgreSQL branch uses these values.
const (
	postgresMaxOpenConns = 20
	postgresMaxIdleConns = 5
)

// convertPlaceholders rewrites the SQLite-style "?" placeholders in query to
// PostgreSQL-style "$1", "$2", ... in argument order. It is quote-aware: a
// "?" inside a single-quoted string literal is left untouched (doubled
// single quotes ” are treated as an escaped quote, not as a string end).
// The storage package currently has no SQL string literal containing "?",
// so the quote handling is defensive, not load-bearing.
func convertPlaceholders(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inString := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '\'' {
			if inString && i+1 < len(query) && query[i+1] == '\'' {
				b.WriteString("''")
				i++
				continue
			}
			inString = !inString
			b.WriteByte(c)
			continue
		}
		if c == '?' && !inString {
			n++
			b.WriteByte('$')
			b.WriteString(intToString(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// convertQuery applies every PostgreSQL dialect rewrite to a query written
// for SQLite. Besides placeholders it rewrites the two-argument scalar
// MAX(a, b) to GREATEST(a, b): in PostgreSQL MAX is only an aggregate
// function, while GREATEST is the scalar form. This rewrite is safe here
// because every MAX( in the storage package's SQL is a two-argument scalar
// in an ON CONFLICT ... DO UPDATE clause (verified by grep); there is no
// aggregate MAX over rows anywhere in this package. SQLite queries pass
// through untouched.
func convertQuery(pg bool, query string) string {
	if !pg {
		return query
	}
	return strings.ReplaceAll(convertPlaceholders(query), "MAX(", "GREATEST(")
}

// dialectDB wraps *sql.DB and rewrites every query for the store's dialect
// before execution. All storage code must go through it (via Store.dbx)
// instead of touching Store.db directly, so a query written once works on
// both SQLite and PostgreSQL.
type dialectDB struct {
	db *sql.DB
	pg bool
}

func (d *dialectDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.db.ExecContext(ctx, convertQuery(d.pg, query), args...)
}

func (d *dialectDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.db.QueryContext(ctx, convertQuery(d.pg, query), args...)
}

func (d *dialectDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.db.QueryRowContext(ctx, convertQuery(d.pg, query), args...)
}

func (d *dialectDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*dialectTx, error) {
	tx, err := d.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &dialectTx{tx: tx, pg: d.pg}, nil
}

// dialectTx wraps *sql.Tx the same way dialectDB wraps *sql.DB. It also
// implements the sqlExecer interface (ExecContext only), so helpers such as
// upsertPlayBucket accept it exactly like they accepted *sql.DB / *sql.Tx.
type dialectTx struct {
	tx *sql.Tx
	pg bool
}

func (t *dialectTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, convertQuery(t.pg, query), args...)
}

func (t *dialectTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, convertQuery(t.pg, query), args...)
}

func (t *dialectTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, convertQuery(t.pg, query), args...)
}

func (t *dialectTx) Commit() error {
	return t.tx.Commit()
}

func (t *dialectTx) Rollback() error {
	return t.tx.Rollback()
}
