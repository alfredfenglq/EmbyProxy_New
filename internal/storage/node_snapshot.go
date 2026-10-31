package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidNodeSnapshot indicates that at least one stored node cannot be decoded.
var ErrInvalidNodeSnapshot = errors.New("invalid node snapshot")

// ListNodesSnapshot reads all node keys and values in one SQLite read snapshot.
// Unlike the best-effort cached list used by the UI, it never skips unreadable
// records. Destructive synchronization must not treat corrupt records as deletions.
func (s *Store) ListNodesSnapshot(ctx context.Context, uid string) ([]Node, error) {
	prefix := "u:" + uid + ":node:"
	// The final ':' increments to ';', giving an indexed prefix range without
	// mixing Go byte lengths with SQLite character counts for non-ASCII UIDs.
	rows, err := s.dbx().QueryContext(ctx, `SELECT k, v FROM proxy_kv WHERE k >= ? AND k < ?`, prefix, "u:"+uid+":node;")
	if err != nil {
		return nil, fmt.Errorf("read node snapshot: %w", err)
	}
	defer rows.Close()
	nodes := []Node{}
	for rows.Next() {
		var key, packed string
		if err := rows.Scan(&key, &packed); err != nil {
			return nil, fmt.Errorf("read node snapshot row: %w", err)
		}
		name := strings.TrimPrefix(key, prefix)
		node, valid := UnpackNode(name, packed)
		if !valid || name == "" || name != strings.ToLower(strings.TrimSpace(name)) || strings.TrimSpace(node.Target) == "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidNodeSnapshot, name)
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read node snapshot: %w", err)
	}
	SortNodes(nodes)
	return nodes, nil
}
