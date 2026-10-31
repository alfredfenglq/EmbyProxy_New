package storage

import (
	"context"
	"encoding/json"
)

const syncTargetsKey = "sync:targets"

// SyncTarget is a remote EmbyProxy instance that receives pushed nodes and settings.
// The remote ADMIN_TOKEN is stored only as an encrypted envelope.
type SyncTarget struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	TokenVersion    int    `json:"tokenVersion"`
	TokenSalt       string `json:"tokenSalt"`
	TokenNonce      string `json:"tokenNonce"`
	TokenCiphertext string `json:"tokenCiphertext"`
}

func (s *Store) GetSyncTargets(ctx context.Context) ([]SyncTarget, error) {
	value, ok, err := s.KV().Get(ctx, syncTargetsKey)
	if err != nil || !ok {
		return []SyncTarget{}, err
	}
	targets := []SyncTarget{}
	if err := json.Unmarshal([]byte(value), &targets); err != nil {
		return []SyncTarget{}, err
	}
	return targets, nil
}

func (s *Store) SaveSyncTargets(ctx context.Context, targets []SyncTarget) error {
	if targets == nil {
		targets = []SyncTarget{}
	}
	return s.KV().Put(ctx, syncTargetsKey, targets)
}
