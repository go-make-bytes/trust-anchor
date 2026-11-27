// Package store persists versioned trust snapshots and the approved OJEU
// bootstrap state. The platform standard is S3-API object storage; a
// filesystem backend exists for development and a memory backend for tests.
// There is intentionally no relational database — the dataset is tens of
// certificates plus metadata.
package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// Store persists snapshots (versioned, with a "latest" pointer) and the
// approved bootstrap set (versioned, with a "latest" pointer).
type Store interface {
	// SaveSnapshot persists snap. The store keeps one stored version per
	// content id: a snapshot whose ID equals the latest stored version's
	// replaces that version in place (a refresh of the same version); any
	// other ID is a new version and becomes the latest. Only the latest is
	// ever replaced, so the history A, B, A is three versions.
	SaveSnapshot(ctx context.Context, snap *trust.Snapshot) error
	// SweepSnapshots removes every version that a newer version replaced
	// before the given time, and reports how many it removed. The latest
	// version is never removed.
	SweepSnapshots(ctx context.Context, before time.Time) (removed int, err error)
	// LoadLatestSnapshot returns the latest persisted snapshot, or (nil, nil)
	// when none exists yet.
	LoadLatestSnapshot(ctx context.Context) (*trust.Snapshot, error)

	// SaveBootstrap persists b as a new version and updates latest.
	SaveBootstrap(ctx context.Context, b *trust.Bootstrap) error
	// LoadLatestBootstrap returns the latest approved bootstrap, or (nil, nil)
	// when none exists yet.
	LoadLatestBootstrap(ctx context.Context) (*trust.Bootstrap, error)
}

const (
	snapshotPrefix = "snapshots/"
	// snapshotTimeLayout writes the first-seen time of a version into its key,
	// to the microsecond so keys sort in the order versions were first seen.
	snapshotTimeLayout = "20060102T150405.000000Z"
	// snapshotParseLayout reads it back; keys written by earlier releases carry
	// the time to the second only, which this layout accepts as well (a
	// fractional second after the seconds field is optional when parsing).
	snapshotParseLayout = "20060102T150405Z"
	idKeyLen            = 16
)

// sameVersion reports whether a version object whose key carries keyID holds
// the version of content id id. New keys carry the full id, compared whole.
// Keys written by an earlier release carry only the first idKeyLen characters:
// such a key stands for the id only when the full id starts with them.
func sameVersion(keyID, id string) bool {
	if keyID == id {
		return true
	}

	return len(keyID) == idKeyLen && strings.HasPrefix(id, keyID)
}

// snapshotKeyFor names the object of a version first seen at firstSeen. The key
// is stable for the version: a refresh of the same version overwrites it.
func snapshotKeyFor(firstSeen time.Time, id string) string {
	return fmt.Sprintf("%s%s-%s.json", snapshotPrefix, firstSeen.UTC().Format(snapshotTimeLayout), id)
}

// versionRef names one stored version.
type versionRef struct {
	key       string
	id        string // the key's id part
	firstSeen time.Time
}

// parseSnapshotKey reads a version's first-seen time and id back out of its
// key; ok is false for any object that is not a version.
func parseSnapshotKey(key string) (versionRef, bool) {
	name, found := strings.CutPrefix(key, snapshotPrefix)
	if !found {
		return versionRef{}, false
	}
	name, found = strings.CutSuffix(name, ".json")
	if !found {
		return versionRef{}, false
	}
	stamp, id, found := strings.Cut(name, "-")
	if !found || id == "" {
		return versionRef{}, false
	}
	t, err := time.Parse(snapshotParseLayout, stamp)
	if err != nil {
		return versionRef{}, false
	}

	return versionRef{key: key, id: id, firstSeen: t.UTC()}, true
}

// blob is the object layer the memory, files and S3 stores share, so that the
// one-version-per-content-id rule and the sweep are written once.
type blob interface {
	put(ctx context.Context, key string, v any) error
	get(ctx context.Context, key string, v any) (bool, error)
	// list returns the keys that start with prefix.
	list(ctx context.Context, prefix string) ([]string, error)
	remove(ctx context.Context, key string) error
}

// versions applies the storing rule over a blob: one stored object per version
// (its first-seen time and id in the key), the "latest" pointer object written
// after it.
//
// The current version's key is found again after a restart from a listing: of
// every version object the newest by first-seen time is the current one, and
// it is only reused when its id is the id being saved.
type versions struct {
	mu  sync.Mutex
	b   blob
	now func() time.Time

	loaded bool
	cur    versionRef // zero when the store holds no version
}

func newVersions(b blob) *versions { return &versions{b: b, now: time.Now} }

// entries lists the stored versions, oldest first.
func (v *versions) entries(ctx context.Context) ([]versionRef, error) {
	keys, err := v.b.list(ctx, snapshotPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]versionRef, 0, len(keys))
	for _, k := range keys {
		if ref, ok := parseSnapshotKey(k); ok {
			out = append(out, ref)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].firstSeen.Equal(out[j].firstSeen) {
			return out[i].firstSeen.Before(out[j].firstSeen)
		}

		return out[i].key < out[j].key
	})

	return out, nil
}

func (v *versions) save(ctx context.Context, snap *trust.Snapshot) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.loaded {
		es, err := v.entries(ctx)
		if err != nil {
			return err
		}
		if len(es) > 0 {
			v.cur = es[len(es)-1]
		}
		v.loaded = true
	}

	ref := v.cur
	if ref.key == "" || !sameVersion(ref.id, snap.ID) {
		// Another content id: a new version, first seen now (never earlier than
		// the one it follows, so the order of keys is the order of versions).
		t := v.now().UTC().Truncate(time.Microsecond)
		if ref.key != "" && !t.After(ref.firstSeen) {
			t = ref.firstSeen.Add(time.Microsecond)
		}
		ref = versionRef{key: snapshotKeyFor(t, snap.ID), id: snap.ID, firstSeen: t}
	}

	if err := v.b.put(ctx, ref.key, snap); err != nil {
		return err
	}
	v.cur = ref

	return v.b.put(ctx, latestSnapshotKey, snap)
}

func (v *versions) sweep(ctx context.Context, before time.Time) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	es, err := v.entries(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	// A version was replaced when the next one was first seen; the last one
	// has no successor and is never removed.
	for i := 0; i+1 < len(es); i++ {
		if !es[i+1].firstSeen.Before(before) {
			break
		}
		if es[i].key == v.cur.key {
			// The current version's object stays, even when another object
			// sorts after it (a write that landed though its call failed).
			continue
		}
		if err := v.b.remove(ctx, es[i].key); err != nil {
			return removed, err
		}
		removed++
	}

	return removed, nil
}

// count reports how many versions are stored.
func (v *versions) count(ctx context.Context) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	es, err := v.entries(ctx)

	return len(es), err
}

// bootstrapKey names a versioned bootstrap object.
func bootstrapKey(b *trust.Bootstrap) string {
	return fmt.Sprintf("bootstrap/v%04d.json", b.Version)
}

const (
	latestSnapshotKey  = "snapshot-latest.json"
	latestBootstrapKey = "bootstrap-latest.json"
)
