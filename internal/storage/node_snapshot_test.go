package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestListNodesSnapshotRejectsCorruptionDespiteCachedList(t *testing.T) {
	ctx := context.Background()
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SaveNode(ctx, "admin", Node{Name: "healthy", Target: "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListNodes(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{broken`, `null`, `{}`, `[]`, `{"t":42}`, `{"t":""}`} {
		t.Run(raw, func(t *testing.T) {
			if err := s.KV().Put(ctx, "u:admin:node:broken", raw); err != nil {
				t.Fatal(err)
			}
			if nodes, err := s.ListNodesSnapshot(ctx, "admin"); !errors.Is(err, ErrInvalidNodeSnapshot) || nodes != nil {
				t.Fatalf("snapshot = %v, %v", nodes, err)
			}
		})
	}
	if err := s.KV().Delete(ctx, "u:admin:node:broken"); err != nil {
		t.Fatal(err)
	}
	if err := s.KV().Put(ctx, "u:other:node:broken", `{broken`); err != nil {
		t.Fatal(err)
	}
	if nodes, err := s.ListNodesSnapshot(ctx, "admin"); err != nil || len(nodes) != 1 || nodes[0].Name != "healthy" {
		t.Fatalf("valid snapshot = %v, %v", nodes, err)
	}
	for _, uid := range []string{"中文用户", "admin_2", "admin%"} {
		if err := s.SaveNode(ctx, uid, Node{Name: "healthy", Target: "https://example.com"}); err != nil {
			t.Fatal(err)
		}
		if nodes, err := s.ListNodesSnapshot(ctx, uid); err != nil || len(nodes) != 1 || nodes[0].Name != "healthy" {
			t.Fatalf("snapshot for %q = %v, %v", uid, nodes, err)
		}
	}
}

func TestListNodesSnapshotPropagatesReadErrors(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if nodes, err := s.ListNodesSnapshot(ctx, "admin"); !errors.Is(err, context.Canceled) || nodes != nil {
		t.Fatalf("canceled snapshot = %v, %v", nodes, err)
	}
	if _, err := s.db.Exec(`DROP TABLE proxy_kv`); err != nil {
		t.Fatal(err)
	}
	if nodes, err := s.ListNodesSnapshot(context.Background(), "admin"); err == nil || nodes != nil {
		t.Fatalf("unreadable snapshot = %v, %v", nodes, err)
	}
}
