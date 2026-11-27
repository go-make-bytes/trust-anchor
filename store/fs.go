package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// FS is a filesystem-backed Store for local development. Layout mirrors the
// S3 backend (one version object per stored version + latest pointer files).
type FS struct {
	dir string
	ver *versions
}

// NewFS returns a filesystem store rooted at dir (created if missing).
func NewFS(dir string) (*FS, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: create snapshot dir: %w", err)
	}
	f := &FS{dir: dir}
	f.ver = newVersions(f)

	return f, nil
}

// setClock replaces the clock the versions' first-seen times are read from.
func (f *FS) setClock(now func() time.Time) { f.ver.now = now }

func (f *FS) put(_ context.Context, key string, v any) error {
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

func (f *FS) get(_ context.Context, key string, v any) (bool, error) {
	b, err := os.ReadFile(filepath.Join(f.dir, filepath.FromSlash(key))) //nolint:gosec // keys are internal constants
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func (f *FS) list(_ context.Context, prefix string) ([]string, error) {
	dir, base := filepath.Split(filepath.FromSlash(prefix))
	entries, err := os.ReadDir(filepath.Join(f.dir, dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, base) || strings.HasSuffix(name, ".tmp") {
			continue
		}
		keys = append(keys, filepath.ToSlash(filepath.Join(dir, name)))
	}

	return keys, nil
}

func (f *FS) remove(_ context.Context, key string) error {
	err := os.Remove(filepath.Join(f.dir, filepath.FromSlash(key)))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}

func (f *FS) SaveSnapshot(ctx context.Context, snap *trust.Snapshot) error {
	return f.ver.save(ctx, snap)
}

func (f *FS) SweepSnapshots(ctx context.Context, before time.Time) (int, error) {
	return f.ver.sweep(ctx, before)
}

func (f *FS) LoadLatestSnapshot(ctx context.Context) (*trust.Snapshot, error) {
	var snap trust.Snapshot
	ok, err := f.get(ctx, latestSnapshotKey, &snap)
	if err != nil || !ok {
		return nil, err
	}
	return &snap, nil
}

func (f *FS) SaveBootstrap(ctx context.Context, b *trust.Bootstrap) error {
	if err := f.put(ctx, bootstrapKey(b), b); err != nil {
		return err
	}
	return f.put(ctx, latestBootstrapKey, b)
}

func (f *FS) LoadLatestBootstrap(ctx context.Context) (*trust.Bootstrap, error) {
	var b trust.Bootstrap
	ok, err := f.get(ctx, latestBootstrapKey, &b)
	if err != nil || !ok {
		return nil, err
	}
	return &b, nil
}
