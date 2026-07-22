// Package store persists versioned trust snapshots and the approved OJEU
// bootstrap state. The platform standard is S3-API object storage; a
// filesystem backend exists for development and a memory backend for tests.
// There is intentionally no relational database — the dataset is tens of
// certificates plus metadata (see DECISIONS.md).
package store

import (
	"context"
	"fmt"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// Store persists snapshots (versioned, with a "latest" pointer) and the
// approved bootstrap set (versioned, with a "latest" pointer).
type Store interface {
	// SaveSnapshot persists snap as a new version and updates latest.
	SaveSnapshot(ctx context.Context, snap *trust.Snapshot) error
	// LoadLatestSnapshot returns the latest persisted snapshot, or (nil, nil)
	// when none exists yet.
	LoadLatestSnapshot(ctx context.Context) (*trust.Snapshot, error)

	// SaveBootstrap persists b as a new version and updates latest.
	SaveBootstrap(ctx context.Context, b *trust.Bootstrap) error
	// LoadLatestBootstrap returns the latest approved bootstrap, or (nil, nil)
	// when none exists yet.
	LoadLatestBootstrap(ctx context.Context) (*trust.Bootstrap, error)
}

// snapshotKey names a versioned snapshot object.
func snapshotKey(snap *trust.Snapshot) string {
	return fmt.Sprintf("snapshots/%s-%s.json", snap.GeneratedAt.UTC().Format("20060102T150405Z"), snap.ID[:16])
}

// bootstrapKey names a versioned bootstrap object.
func bootstrapKey(b *trust.Bootstrap) string {
	return fmt.Sprintf("bootstrap/v%04d.json", b.Version)
}

const (
	latestSnapshotKey  = "snapshot-latest.json"
	latestBootstrapKey = "bootstrap-latest.json"
)
