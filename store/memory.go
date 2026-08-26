package store

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// Memory is an in-memory Store for tests and ephemeral development runs. It
// keeps the JSON-marshalled history like a real backend would.
type Memory struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{objects: map[string][]byte{}}
}

func (m *Memory) put(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = b
	return nil
}

func (m *Memory) get(key string, v any) (bool, error) {
	m.mu.Lock()
	b, ok := m.objects[key]
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, v)
}

func (m *Memory) SaveSnapshot(_ context.Context, snap *trust.Snapshot) error {
	if err := m.put(snapshotKey(snap), snap); err != nil {
		return err
	}
	return m.put(latestSnapshotKey, snap)
}

func (m *Memory) LoadLatestSnapshot(_ context.Context) (*trust.Snapshot, error) {
	var snap trust.Snapshot
	ok, err := m.get(latestSnapshotKey, &snap)
	if err != nil || !ok {
		return nil, err
	}
	return &snap, nil
}

func (m *Memory) SaveBootstrap(_ context.Context, b *trust.Bootstrap) error {
	if err := m.put(bootstrapKey(b), b); err != nil {
		return err
	}
	return m.put(latestBootstrapKey, b)
}

func (m *Memory) LoadLatestBootstrap(_ context.Context) (*trust.Bootstrap, error) {
	var b trust.Bootstrap
	ok, err := m.get(latestBootstrapKey, &b)
	if err != nil || !ok {
		return nil, err
	}
	return &b, nil
}
