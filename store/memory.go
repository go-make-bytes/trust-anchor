package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// Memory is an in-memory Store for tests and ephemeral development runs. It
// keeps the JSON-marshalled history like a real backend would, under the same
// one-version-per-content-id rule.
type Memory struct {
	mu      sync.Mutex
	objects map[string][]byte
	ver     *versions
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	m := &Memory{objects: map[string][]byte{}}
	m.ver = newVersions(m)

	return m
}

// setClock replaces the clock the versions' first-seen times are read from.
func (m *Memory) setClock(now func() time.Time) { m.ver.now = now }

func (m *Memory) put(_ context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = b
	return nil
}

func (m *Memory) get(_ context.Context, key string, v any) (bool, error) {
	m.mu.Lock()
	b, ok := m.objects[key]
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, v)
}

func (m *Memory) list(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	return keys, nil
}

func (m *Memory) remove(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)

	return nil
}

func (m *Memory) SaveSnapshot(ctx context.Context, snap *trust.Snapshot) error {
	return m.ver.save(ctx, snap)
}

func (m *Memory) SweepSnapshots(ctx context.Context, before time.Time) (int, error) {
	return m.ver.sweep(ctx, before)
}

// SnapshotVersions reports how many stored versions the store holds.
func (m *Memory) SnapshotVersions() int {
	n, _ := m.ver.count(context.Background())

	return n
}

func (m *Memory) LoadLatestSnapshot(ctx context.Context) (*trust.Snapshot, error) {
	var snap trust.Snapshot
	ok, err := m.get(ctx, latestSnapshotKey, &snap)
	if err != nil || !ok {
		return nil, err
	}
	return &snap, nil
}

func (m *Memory) SaveBootstrap(ctx context.Context, b *trust.Bootstrap) error {
	if err := m.put(ctx, bootstrapKey(b), b); err != nil {
		return err
	}
	return m.put(ctx, latestBootstrapKey, b)
}

func (m *Memory) LoadLatestBootstrap(ctx context.Context) (*trust.Bootstrap, error) {
	var b trust.Bootstrap
	ok, err := m.get(ctx, latestBootstrapKey, &b)
	if err != nil || !ok {
		return nil, err
	}
	return &b, nil
}
