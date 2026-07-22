package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// FS is a filesystem-backed Store for local development. Layout mirrors the
// S3 backend (versioned objects + latest pointer files).
type FS struct {
	dir string
}

// NewFS returns a filesystem store rooted at dir (created if missing).
func NewFS(dir string) (*FS, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: create snapshot dir: %w", err)
	}
	return &FS{dir: dir}, nil
}

func (f *FS) put(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	path := filepath.Join(f.dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (f *FS) get(key string, v any) (bool, error) {
	b, err := os.ReadFile(filepath.Join(f.dir, filepath.FromSlash(key))) //nolint:gosec // keys are internal constants
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func (f *FS) SaveSnapshot(_ context.Context, snap *trust.Snapshot) error {
	if err := f.put(snapshotKey(snap), snap); err != nil {
		return err
	}
	return f.put(latestSnapshotKey, snap)
}

func (f *FS) LoadLatestSnapshot(_ context.Context) (*trust.Snapshot, error) {
	var snap trust.Snapshot
	ok, err := f.get(latestSnapshotKey, &snap)
	if err != nil || !ok {
		return nil, err
	}
	return &snap, nil
}

func (f *FS) SaveBootstrap(_ context.Context, b *trust.Bootstrap) error {
	if err := f.put(bootstrapKey(b), b); err != nil {
		return err
	}
	return f.put(latestBootstrapKey, b)
}

func (f *FS) LoadLatestBootstrap(_ context.Context) (*trust.Bootstrap, error) {
	var b trust.Bootstrap
	ok, err := f.get(latestBootstrapKey, &b)
	if err != nil || !ok {
		return nil, err
	}
	return &b, nil
}
