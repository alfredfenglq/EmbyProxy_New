package storage

import (
	"container/list"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
	// pg is true when the store is backed by PostgreSQL instead of SQLite.
	pg                bool
	mu                sync.RWMutex
	nodeCache         map[string]cacheEntry[*Node]
	negativeNodeMu    sync.Mutex
	negativeNodeCache map[string]*list.Element
	negativeNodeOrder *list.List
	nodeListCache     map[string]cacheEntry[[]Node]
	hostIndexCache    map[string]cacheEntry[map[string]HostMatch]
	sysConfigCache    systemConfigCacheEntry
	sysConfigGen      uint64
	nodeCacheGen      uint64
	playbackMu        sync.RWMutex
	playbackClosed    bool
	playbackQueue     chan PlaybackInput
	playbackWG        sync.WaitGroup
	playbackDropped   uint64
	// serverName is this EmbyProxy instance's name (INSTANCE_NAME, e.g. A/B/C).
	// It is recorded in play_stats so the admin stats table can show which
	// server served each playback. Set once at startup via SetServerName.
	serverMu   sync.RWMutex
	serverName string
	// playStatsServerMigrated is set when this startup migrated an existing
	// play_stats table to the (day, node, client, server) primary key.
	// Fresh tables already have the new key, so they do not set it.
	playStatsServerMigrated bool
}

type KV struct {
	store *Store
}

type cacheEntry[T any] struct {
	value T
	exp   time.Time
}

type systemConfigCacheEntry struct {
	value SystemConfig
	ok    bool
	exp   time.Time
}

const (
	systemConfigCacheTTL      = 5 * time.Second
	nodeCacheTTL              = 10 * time.Second
	negativeNodeCacheCapacity = 4096
)

type negativeNodeCacheEntry struct {
	key string
	exp time.Time
}

type ListResult struct {
	Keys         []string
	ListComplete bool
	Cursor       int
}

func New(dbPath string) (*Store, error) {
	return newStore(dbPath, "")
}

// NewWithDatabaseURL opens a store backed by PostgreSQL when databaseURL is
// non-empty (a postgres:// DSN for the pgx driver), and falls back to the
// local SQLite file at dbPath otherwise. Existing callers that pass only a
// path keep the previous SQLite behaviour unchanged.
func NewWithDatabaseURL(dbPath, databaseURL string) (*Store, error) {
	return newStore(dbPath, databaseURL)
}

func newStore(dbPath, databaseURL string) (*Store, error) {
	if databaseURL != "" {
		db, err := sql.Open("pgx", databaseURL)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(postgresMaxOpenConns)
		db.SetMaxIdleConns(postgresMaxIdleConns)
		store := &Store{
			db:                db,
			pg:                true,
			nodeCache:         map[string]cacheEntry[*Node]{},
			negativeNodeCache: map[string]*list.Element{},
			negativeNodeOrder: list.New(),
			nodeListCache:     map[string]cacheEntry[[]Node]{},
			hostIndexCache:    map[string]cacheEntry[map[string]HostMatch]{},
		}
		if err := store.InitSchema(context.Background()); err != nil {
			_ = db.Close()
			return nil, err
		}
		store.startPlaybackAsyncLogger()
		return store, nil
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{
		db:                db,
		nodeCache:         map[string]cacheEntry[*Node]{},
		negativeNodeCache: map[string]*list.Element{},
		negativeNodeOrder: list.New(),
		nodeListCache:     map[string]cacheEntry[[]Node]{},
		hostIndexCache:    map[string]cacheEntry[map[string]HostMatch]{},
	}
	if err := store.InitSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	store.startPlaybackAsyncLogger()
	return store, nil
}

// IsPG reports whether this store is backed by PostgreSQL.
func (s *Store) IsPG() bool {
	return s != nil && s.pg
}

// dbx returns the dialect-aware executor for this store. All SQL in this
// package must go through it instead of s.db directly.
func (s *Store) dbx() *dialectDB {
	return &dialectDB{db: s.db, pg: s.pg}
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closePlaybackAsyncLogger()
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) KV() *KV {
	return &KV{store: s}
}

// SetServerName records this instance's name for playback statistics.
// Call once at startup, before serving traffic; config.Load already
// trims INSTANCE_NAME and falls back to the hostname when empty.
func (s *Store) SetServerName(name string) {
	if s == nil {
		return
	}
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	s.serverName = strings.TrimSpace(name)
}

// ServerName returns the name set by SetServerName, or "" if unset.
func (s *Store) ServerName() string {
	if s == nil {
		return ""
	}
	s.serverMu.RLock()
	defer s.serverMu.RUnlock()
	return s.serverName
}

// PlayStatsServerMigrated reports whether this startup migrated an existing
// play_stats table to the server key. Callers use it to warn that every
// instance sharing the database must run the new binary: old binaries'
// play_stats upserts name the old primary key and fail on PostgreSQL once
// the key has changed (SQLSTATE 42P10), and the async stats writer drops
// those errors silently, so a rolling upgrade would lose statistics.
func (s *Store) PlayStatsServerMigrated() bool {
	if s == nil {
		return false
	}
	s.serverMu.RLock()
	defer s.serverMu.RUnlock()
	return s.playStatsServerMigrated
}

func (s *Store) InitSchema(ctx context.Context) error {
	schema := sqliteSchema
	if s.pg {
		// The PostgreSQL schema is the SQLite schema with every INTEGER
		// column widened to BIGINT: timestamps are Unix milliseconds and
		// byte counters can exceed 32 bits. INTEGER only appears as a
		// column type in the schema below, so this replacement is exact.
		schema = strings.ReplaceAll(schema, "INTEGER", "BIGINT")
	}
	_, err := s.dbx().ExecContext(ctx, schema)
	if err != nil {
		return err
	}
	if err := s.ensurePlaybackStatColumns(ctx); err != nil {
		return err
	}
	return s.ensurePlayStatsServerColumn(ctx)
}

// sqliteSchema is the single source for the table definitions. The
// PostgreSQL schema is derived from it in InitSchema by widening INTEGER
// to BIGINT.
const sqliteSchema = `
		CREATE TABLE IF NOT EXISTS proxy_kv (
			k TEXT PRIMARY KEY,
			v TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS keepalive_state (
			node TEXT PRIMARY KEY,
			anchor_ts INTEGER NOT NULL,
			last_play_ts INTEGER DEFAULT 0,
			last_notify_day TEXT,
			notify_count_day TEXT,
			notify_count INTEGER DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS play_sessions (
			k TEXT PRIMARY KEY,
			day TEXT NOT NULL,
			last_ts INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS play_events (
			k TEXT PRIMARY KEY,
			day TEXT NOT NULL,
			last_ts INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS playback_states (
			k TEXT PRIMARY KEY,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			server TEXT NOT NULL DEFAULT '',
			mode TEXT NOT NULL,
			item_key TEXT NOT NULL,
			last_event_ts INTEGER NOT NULL,
			last_position_ticks INTEGER NOT NULL DEFAULT 0,
			has_position INTEGER NOT NULL DEFAULT 0,
			is_paused INTEGER NOT NULL DEFAULT 0,
			closed INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_playback_states_updated_at ON playback_states(updated_at);
		CREATE TABLE IF NOT EXISTS play_stats (
			day TEXT NOT NULL,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			server TEXT NOT NULL DEFAULT '',
			plays INTEGER DEFAULT 0,
			playback_ms INTEGER DEFAULT 0,
			bytes INTEGER DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0,
			sessions INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(day, node, client, server)
		);
		CREATE TABLE IF NOT EXISTS play_buckets (
			bucket_start INTEGER NOT NULL,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			mode TEXT NOT NULL,
			plays INTEGER DEFAULT 0,
			playback_ms INTEGER DEFAULT 0,
			bytes INTEGER DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0,
			sessions INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(bucket_start, node, client, mode)
		);
	`

func (s *Store) ensurePlaybackStatColumns(ctx context.Context) error {
	for table, columns := range map[string][]string{
		"play_stats": {
			"playback_ms INTEGER DEFAULT 0",
			"inbound_bytes INTEGER DEFAULT 0",
			"outbound_bytes INTEGER DEFAULT 0",
		},
		"play_buckets": {
			"playback_ms INTEGER DEFAULT 0",
		},
		"playback_states": {
			"closed INTEGER DEFAULT 0",
			"server TEXT DEFAULT ''",
		},
	} {
		cols, err := s.tableColumns(ctx, table)
		if err != nil {
			return err
		}
		for _, column := range columns {
			if s.pg {
				column = strings.ReplaceAll(column, "INTEGER", "BIGINT")
			}
			name := strings.Fields(column)[0]
			if cols[name] {
				continue
			}
			// PostgreSQL uses IF NOT EXISTS so concurrent startups do
			// not race on the check-then-add: the second ADD is a no-op
			// instead of failing the whole startup. SQLite has no such
			// clause and runs one process per file, so it keeps the
			// check-then-add.
			stmt := `ALTER TABLE ` + table + ` ADD COLUMN ` + column
			if s.pg {
				stmt = `ALTER TABLE ` + table + ` ADD COLUMN IF NOT EXISTS ` + column
			}
			if _, err := s.dbx().ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) ensurePlayStatsServerColumn(ctx context.Context) error {
	if s.pg {
		return s.ensurePlayStatsServerColumnPG(ctx)
	}
	cols, err := s.tableColumns(ctx, "play_stats")
	if err != nil {
		return err
	}
	if !cols["server"] {
		if _, err := s.dbx().ExecContext(ctx, `ALTER TABLE play_stats ADD COLUMN server TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
		s.setPlayStatsServerMigrated()
	}
	hasServerInPK, err := s.playStatsPKHasServer(ctx)
	if err != nil {
		return err
	}
	if hasServerInPK {
		return nil
	}
	// Tables created before the server column existed still have the old
	// PRIMARY KEY(day, node, client); rows from different servers would
	// collapse into one row on upsert. Old rows keep server '' (shown as
	// '-' in the admin table); only their key changes, no data is lost.
	// SQLite cannot alter a primary key, so rebuild the table: the new
	// table has the same columns plus server, keyed by
	// (day, node, client, server). This runs after
	// ensurePlaybackStatColumns, so every column in the SELECT exists.
	// COALESCE preserves server values if a previous startup already wrote
	// them but was interrupted before the key change; a constant '' here
	// would wipe A/B/C back to empty on the next rebuild.
	tx, err := s.dbx().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`CREATE TABLE play_stats_new (
			day TEXT NOT NULL,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			server TEXT NOT NULL DEFAULT '',
			plays INTEGER DEFAULT 0,
			playback_ms INTEGER DEFAULT 0,
			bytes INTEGER DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0,
			sessions INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(day, node, client, server)
		)`,
		`INSERT INTO play_stats_new (day, node, client, server, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at)
			SELECT day, node, client, COALESCE(server, ''), plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at FROM play_stats`,
		`DROP TABLE play_stats`,
		`ALTER TABLE play_stats_new RENAME TO play_stats`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.setPlayStatsServerMigrated()
	return nil
}

// ensurePlayStatsServerColumnPG is the PostgreSQL half of the play_stats
// server migration. The whole migration runs in one transaction behind a
// transaction-scoped advisory lock, so concurrent startups serialize
// instead of racing on ADD COLUMN / DROP CONSTRAINT, and a failure anywhere
// leaves the old primary key intact instead of a table with no key at all.
// The primary key constraint name is looked up, not assumed: a table whose
// key is not literally named play_stats_pkey would otherwise leave DROP
// as a no-op and fail ADD PRIMARY KEY with "multiple primary keys".
func (s *Store) ensurePlayStatsServerColumnPG(ctx context.Context) error {
	tx, err := s.dbx().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('embyproxy_play_stats_server'))`); err != nil {
		return err
	}
	cols, err := tableColumnsWith(ctx, tx, true, "play_stats")
	if err != nil {
		return err
	}
	migrated := false
	if !cols["server"] {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE play_stats ADD COLUMN IF NOT EXISTS server TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
		migrated = true
	}
	hasServerInPK, err := playStatsPKHasServerWith(ctx, tx, true)
	if err != nil {
		return err
	}
	if !hasServerInPK {
		var pkName string
		err := tx.QueryRowContext(ctx, `SELECT conname FROM pg_constraint WHERE conrelid = 'play_stats'::regclass AND contype = 'p'`).Scan(&pkName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// No primary key at all (e.g. a previous non-transactional
		// migration was killed between DROP and ADD): skip the DROP
		// and just add the new key.
		if err == nil {
			quoted := `"` + strings.ReplaceAll(pkName, `"`, `""`) + `"`
			if _, err := tx.ExecContext(ctx, `ALTER TABLE play_stats DROP CONSTRAINT `+quoted); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE play_stats ADD PRIMARY KEY (day, node, client, server)`); err != nil {
			return err
		}
		migrated = true
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if migrated {
		s.setPlayStatsServerMigrated()
	}
	return nil
}

// playStatsPKHasServer reports whether server is part of play_stats'
// primary key.
func (s *Store) playStatsPKHasServer(ctx context.Context) (bool, error) {
	return playStatsPKHasServerWith(ctx, s.dbx(), s.pg)
}

func playStatsPKHasServerWith(ctx context.Context, q dbQuerier, pg bool) (bool, error) {
	if pg {
		rows, err := q.QueryContext(ctx, `SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) WHERE i.indrelid = 'play_stats'::regclass AND i.indisprimary`)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return false, err
			}
			if name == "server" {
				return true, nil
			}
		}
		return false, rows.Err()
	}
	rows, err := q.QueryContext(ctx, `PRAGMA table_info(play_stats)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == "server" && pk > 0 {
			return true, nil
		}
	}
	return false, rows.Err()
}

// dbQuerier is satisfied by both dialectDB and dialectTx, so schema checks
// can run either standalone or inside a migration transaction.
type dbQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) setPlayStatsServerMigrated() {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	s.playStatsServerMigrated = true
}

func (s *Store) tableColumns(ctx context.Context, table string) (map[string]bool, error) {
	return tableColumnsWith(ctx, s.dbx(), s.pg, table)
}

func tableColumnsWith(ctx context.Context, q dbQuerier, pg bool, table string) (map[string]bool, error) {
	if pg {
		// information_schema.columns is the PostgreSQL equivalent of
		// PRAGMA table_info. The query goes through dbx() so its "?"
		// placeholder is rewritten to "$1". No schema filter: the check
		// only needs column existence, and the tables are created by
		// this program in the connection's default schema.
		rows, err := q.QueryContext(ctx, `SELECT column_name FROM information_schema.columns WHERE table_name = ?`, table)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		cols := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return nil, err
			}
			cols[name] = true
		}
		return cols, rows.Err()
	}
	rows, err := q.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

func (kv *KV) Get(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := kv.store.dbx().QueryRowContext(ctx, `SELECT v FROM proxy_kv WHERE k = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (kv *KV) GetJSON(ctx context.Context, key string, dst any) (bool, error) {
	value, ok, err := kv.Get(ctx, key)
	if err != nil || !ok {
		return ok, err
	}
	if err := json.Unmarshal([]byte(value), dst); err != nil {
		return false, nil
	}
	return true, nil
}

func (kv *KV) Put(ctx context.Context, key string, value any) error {
	var raw string
	switch v := value.(type) {
	case string:
		raw = v
	case []byte:
		raw = string(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		raw = string(b)
	}
	_, err := kv.store.dbx().ExecContext(ctx, `
		INSERT INTO proxy_kv (k, v, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at
	`, key, raw, time.Now().UnixMilli())
	return err
}

func (kv *KV) Delete(ctx context.Context, key string) error {
	_, err := kv.store.dbx().ExecContext(ctx, `DELETE FROM proxy_kv WHERE k = ?`, key)
	return err
}

func (kv *KV) List(ctx context.Context, prefix string, cursor, limit int) (ListResult, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if cursor < 0 {
		cursor = 0
	}
	rows, err := kv.store.dbx().QueryContext(ctx, `SELECT k FROM proxy_kv WHERE k LIKE ? ORDER BY k LIMIT ? OFFSET ?`, prefix+"%", limit+1, cursor)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()
	keys := make([]string, 0, limit+1)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return ListResult{}, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}
	complete := len(keys) <= limit
	if !complete {
		keys = keys[:limit]
	}
	return ListResult{Keys: keys, ListComplete: complete, Cursor: cursor + limit}, nil
}

func (s *Store) GetNode(ctx context.Context, uid, name string) (*Node, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	cacheKey := uid + ":" + name
	if node, ok := s.getNodeCache(cacheKey); ok {
		return node, nil
	}
	if s.getNegativeNodeCache(cacheKey) {
		return nil, nil
	}
	nodeCacheGen := s.nodeCacheGeneration()
	packed, ok, err := s.KV().Get(ctx, "u:"+uid+":node:"+name)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.setNegativeNodeCacheIfGeneration(cacheKey, nodeCacheTTL, nodeCacheGen)
		return nil, nil
	}
	node, valid := UnpackNode(name, packed)
	if !valid {
		s.setNegativeNodeCacheIfGeneration(cacheKey, nodeCacheTTL, nodeCacheGen)
		return nil, nil
	}
	s.setNodeCacheIfGeneration(cacheKey, &node, nodeCacheTTL, nodeCacheGen)
	return &node, nil
}

// CleanupNodeCache removes expired positive and negative node cache entries.
func (s *Store) CleanupNodeCache() {
	if s == nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	for key, entry := range s.nodeCache {
		if now.After(entry.exp) {
			delete(s.nodeCache, key)
		}
	}
	s.mu.Unlock()

	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	for key, element := range s.negativeNodeCache {
		entry, ok := element.Value.(negativeNodeCacheEntry)
		if !ok || now.After(entry.exp) {
			delete(s.negativeNodeCache, key)
			s.negativeNodeOrder.Remove(element)
		}
	}
}

func (s *Store) ListNodes(ctx context.Context, uid string) ([]Node, error) {
	cacheKey := "list:" + uid
	if nodes, ok := s.getListCache(cacheKey); ok {
		return cloneNodes(nodes), nil
	}
	prefix := "u:" + uid + ":node:"
	cursor := 0
	nodes := []Node{}
	for {
		res, err := s.KV().List(ctx, prefix, cursor, 1000)
		if err != nil {
			return nil, err
		}
		for _, key := range res.Keys {
			name := strings.TrimPrefix(key, prefix)
			packed, ok, err := s.KV().Get(ctx, key)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if node, valid := UnpackNode(name, packed); valid {
				nodes = append(nodes, node)
			}
		}
		if res.ListComplete {
			break
		}
		cursor = res.Cursor
	}
	SortNodes(nodes)
	s.setListCache(cacheKey, cloneNodes(nodes), nodeCacheTTL)
	return nodes, nil
}

func (s *Store) SaveNode(ctx context.Context, uid string, node Node) error {
	node.Name = strings.ToLower(strings.TrimSpace(node.Name))
	packed, err := PackNode(node)
	if err != nil {
		return err
	}
	if err := s.KV().Put(ctx, "u:"+uid+":node:"+node.Name, packed); err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	if _, err := s.dbx().ExecContext(ctx, `
		INSERT INTO keepalive_state (node, anchor_ts) VALUES (?, ?)
		ON CONFLICT(node) DO NOTHING
	`, uid+":"+node.Name, now); err != nil {
		return err
	}
	s.InvalidateNodeCache(uid, node.Name)
	return nil
}

func (s *Store) DeleteNode(ctx context.Context, uid, name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if err := s.KV().Delete(ctx, "u:"+uid+":node:"+name); err != nil {
		return err
	}
	if _, err := s.dbx().ExecContext(ctx, `DELETE FROM keepalive_state WHERE node = ?`, uid+":"+name); err != nil {
		return err
	}
	s.InvalidateNodeCache(uid, name)
	return nil
}

func (s *Store) InvalidateNodeCache(uid, name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	key := uid + ":" + name
	s.mu.Lock()
	s.nodeCacheGen++
	delete(s.nodeCache, key)
	delete(s.nodeListCache, "list:"+uid)
	delete(s.hostIndexCache, "hostidx:"+uid)
	s.mu.Unlock()

	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	if element, ok := s.negativeNodeCache[key]; ok {
		delete(s.negativeNodeCache, key)
		s.negativeNodeOrder.Remove(element)
	}
}

func (s *Store) GetHostIndex(ctx context.Context, uid string) (map[string]HostMatch, error) {
	cacheKey := "hostidx:" + uid
	if hit, ok := s.getHostIndexCache(cacheKey); ok {
		return cloneHostIndex(hit), nil
	}
	nodes, err := s.ListNodes(ctx, uid)
	if err != nil {
		return nil, err
	}
	out := map[string]HostMatch{}
	for _, node := range nodes {
		for _, target := range SplitTargets(node.Target) {
			u, err := url.Parse(target)
			if err == nil && u.Host != "" {
				out[strings.ToLower(u.Host)] = HostMatch{Name: node.Name, Secret: node.Secret}
			}
		}
	}
	s.setHostIndexCache(cacheKey, cloneHostIndex(out), nodeCacheTTL)
	return out, nil
}

func (s *Store) GetTGConfig(ctx context.Context) (TGConfig, error) {
	var cfg TGConfig
	value, ok, err := s.KV().Get(ctx, "tg:config")
	if err != nil || !ok {
		return TGConfig{Enabled: false}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &raw); err != nil {
		return TGConfig{Enabled: false}, nil
	}
	if err := json.Unmarshal([]byte(value), &cfg); err != nil {
		return TGConfig{Enabled: false}, nil
	}
	if _, ok := raw["reportEnabled"]; !ok && cfg.Enabled {
		cfg.ReportEnabled = true
	}
	return cfg, nil
}

func (s *Store) SaveTGConfig(ctx context.Context, cfg TGConfig) error {
	return s.KV().Put(ctx, "tg:config", cfg)
}

func (s *Store) GetSystemConfig(ctx context.Context, fallback SystemConfig) (SystemConfig, error) {
	s.mu.RLock()
	entry := s.sysConfigCache
	gen := s.sysConfigGen
	s.mu.RUnlock()
	if !entry.exp.IsZero() && time.Now().Before(entry.exp) {
		if entry.ok {
			return entry.value, nil
		}
		return fallback, nil
	}

	cfg := fallback
	ok, err := s.KV().GetJSON(ctx, "system:config", &cfg)
	if err != nil || !ok {
		if err == nil {
			s.setSystemConfigCacheIfGen(gen, SystemConfig{}, false, systemConfigCacheTTL)
		}
		return fallback, err
	}
	s.setSystemConfigCacheIfGen(gen, cfg, true, systemConfigCacheTTL)
	return cfg, nil
}

func (s *Store) SaveSystemConfig(ctx context.Context, cfg SystemConfig) error {
	if err := s.KV().Put(ctx, "system:config", cfg); err != nil {
		s.invalidateSystemConfigCache()
		return err
	}
	s.setSystemConfigCache(cfg, true, systemConfigCacheTTL)
	return nil
}

func (s *Store) setSystemConfigCache(value SystemConfig, ok bool, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sysConfigGen++
	s.sysConfigCache = systemConfigCacheEntry{value: value, ok: ok, exp: time.Now().Add(ttl)}
}

func (s *Store) setSystemConfigCacheIfGen(gen uint64, value SystemConfig, ok bool, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sysConfigGen != gen {
		return
	}
	s.sysConfigCache = systemConfigCacheEntry{value: value, ok: ok, exp: time.Now().Add(ttl)}
}

func (s *Store) invalidateSystemConfigCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sysConfigGen++
	s.sysConfigCache = systemConfigCacheEntry{}
}

func (s *Store) getNodeCache(key string) (*Node, bool) {
	s.mu.RLock()
	entry, ok := s.nodeCache[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.exp) {
		if ok {
			s.mu.Lock()
			delete(s.nodeCache, key)
			s.mu.Unlock()
		}
		return nil, false
	}
	if entry.value == nil {
		return nil, true
	}
	node := *entry.value
	return &node, true
}

func (s *Store) nodeCacheGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodeCacheGen
}

func (s *Store) setNodeCacheIfGeneration(key string, value *Node, ttl time.Duration, generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodeCacheGen != generation {
		return false
	}
	if value == nil {
		s.nodeCache[key] = cacheEntry[*Node]{value: nil, exp: time.Now().Add(ttl)}
		return true
	}
	node := *value
	s.nodeCache[key] = cacheEntry[*Node]{value: &node, exp: time.Now().Add(ttl)}
	return true
}

func (s *Store) getNegativeNodeCache(key string) bool {
	now := time.Now()
	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	element, ok := s.negativeNodeCache[key]
	if !ok {
		return false
	}
	entry, valid := element.Value.(negativeNodeCacheEntry)
	if !valid || now.After(entry.exp) {
		delete(s.negativeNodeCache, key)
		s.negativeNodeOrder.Remove(element)
		return false
	}
	s.negativeNodeOrder.MoveToFront(element)
	return true
}

func (s *Store) setNegativeNodeCache(key string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	now := time.Now()
	s.negativeNodeMu.Lock()
	defer s.negativeNodeMu.Unlock()
	if element, ok := s.negativeNodeCache[key]; ok {
		element.Value = negativeNodeCacheEntry{key: key, exp: now.Add(ttl)}
		s.negativeNodeOrder.MoveToFront(element)
		return
	}
	element := s.negativeNodeOrder.PushFront(negativeNodeCacheEntry{key: key, exp: now.Add(ttl)})
	s.negativeNodeCache[key] = element
	for len(s.negativeNodeCache) > negativeNodeCacheCapacity {
		oldest := s.negativeNodeOrder.Back()
		if oldest == nil {
			break
		}
		entry, _ := oldest.Value.(negativeNodeCacheEntry)
		delete(s.negativeNodeCache, entry.key)
		s.negativeNodeOrder.Remove(oldest)
	}
}

func (s *Store) setNegativeNodeCacheIfGeneration(key string, ttl time.Duration, generation uint64) bool {
	if ttl <= 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.nodeCacheGen != generation {
		return false
	}
	s.setNegativeNodeCache(key, ttl)
	return true
}

func (s *Store) getListCache(key string) ([]Node, bool) {
	s.mu.RLock()
	entry, ok := s.nodeListCache[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.exp) {
		if ok {
			s.mu.Lock()
			delete(s.nodeListCache, key)
			s.mu.Unlock()
		}
		return nil, false
	}
	return cloneNodes(entry.value), true
}

func (s *Store) setListCache(key string, value []Node, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeListCache[key] = cacheEntry[[]Node]{value: cloneNodes(value), exp: time.Now().Add(ttl)}
}

func (s *Store) getHostIndexCache(key string) (map[string]HostMatch, bool) {
	s.mu.RLock()
	entry, ok := s.hostIndexCache[key]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.exp) {
		if ok {
			s.mu.Lock()
			delete(s.hostIndexCache, key)
			s.mu.Unlock()
		}
		return nil, false
	}
	return cloneHostIndex(entry.value), true
}

func (s *Store) setHostIndexCache(key string, value map[string]HostMatch, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostIndexCache[key] = cacheEntry[map[string]HostMatch]{value: cloneHostIndex(value), exp: time.Now().Add(ttl)}
}

func cloneNodes(nodes []Node) []Node {
	out := make([]Node, len(nodes))
	copy(out, nodes)
	return out
}

func cloneHostIndex(in map[string]HostMatch) map[string]HostMatch {
	out := make(map[string]HostMatch, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func mustJSON(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(b)
}
