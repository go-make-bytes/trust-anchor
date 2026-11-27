package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// idSnap is versionSnap with a chosen content id, so two ids can share any
// prefix.
func idSnap(id, digest string) *trust.Snapshot {
	s := versionSnap(1, digest)
	s.ID = id

	return s
}

const sharedPrefix = "0123456789abcdef" // the first 16 characters of both ids

var (
	idOne = sharedPrefix + strings.Repeat("1", 48)
	idTwo = sharedPrefix + strings.Repeat("2", 48)
)

// plantObject writes a version object by hand, as an earlier release or an
// interrupted write would have left it.
func plantObject(t *testing.T, dir, key string, snap *trust.Snapshot) string {
	t.Helper()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func openFS(t *testing.T, dir string, at time.Time) *FS {
	t.Helper()
	f, err := NewFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	clk := &steppingClock{now: at}
	f.setClock(clk.Now)

	return f
}

// Versions are told apart by the full content id: two ids that share their
// first 16 characters are two versions, and the second never overwrites the
// first's object.
func TestIDsSharingTheirFirstSixteenCharactersAreTwoVersions(t *testing.T) {
	ctx := context.Background()
	for _, su := range storesUnderTest() {
		t.Run(su.name, func(t *testing.T) {
			s, clk := su.make(t)
			for i, sn := range []*trust.Snapshot{idSnap(idOne, "one"), idSnap(idTwo, "two")} {
				clk.now = epoch.Add(time.Duration(i) * time.Hour)
				if err := s.SaveSnapshot(ctx, sn); err != nil {
					t.Fatal(err)
				}
			}
			if got := su.count(t, s); got != 2 {
				t.Fatalf("%d stored versions, want 2", got)
			}
			if id, digest := latestDigest(t, s); id != idTwo || digest != "two" {
				t.Fatalf("latest is %s/%s, want the second id", id, digest)
			}

			// The same full id again refreshes in place.
			clk.now = epoch.Add(2 * time.Hour)
			if err := s.SaveSnapshot(ctx, idSnap(idTwo, "two-again")); err != nil {
				t.Fatal(err)
			}
			if got := su.count(t, s); got != 2 {
				t.Fatalf("%d stored versions after a same-id save, want 2", got)
			}
		})
	}
}

// New keys carry the full id.
func TestNewKeysCarryTheFullID(t *testing.T) {
	dir := t.TempDir()
	if err := openFS(t, dir, epoch).SaveSnapshot(context.Background(), idSnap(idOne, "one")); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if len(files) != 1 || !strings.HasSuffix(files[0], "-"+idOne+".json") {
		t.Fatalf("the version object is %v, want a key ending in the full id", files)
	}
}

// A key an earlier release wrote (16 characters of the id) is still found after
// a restart and overwritten by a save of the same id; another id is a new
// version.
func TestALegacyShortKeyIsFoundAfterARestartAndOverwrittenBySameIDSave(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	legacy := "snapshots/20260101T000000Z-" + sharedPrefix + ".json"
	path := plantObject(t, dir, legacy, idSnap(idOne, "legacy"))
	plantObject(t, dir, "snapshot-latest.json", idSnap(idOne, "legacy"))

	f := openFS(t, dir, epoch)
	if err := f.SaveSnapshot(ctx, idSnap(idOne, "refreshed")); err != nil {
		t.Fatal(err)
	}
	if got := countFSVersions(t, dir); got != 1 {
		t.Fatalf("%d objects after a same-id save, want the legacy one overwritten", got)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // test path
	if err != nil || !strings.Contains(string(raw), "refreshed") {
		t.Fatalf("the legacy object was not overwritten: %v %s", err, raw)
	}

	// Another id (even one that shares nothing with the legacy key) is new.
	other := openFS(t, dir, epoch.Add(time.Hour))
	if err := other.SaveSnapshot(ctx, idSnap(strings.Repeat("f", 64), "other")); err != nil {
		t.Fatal(err)
	}
	if got := countFSVersions(t, dir); got != 2 {
		t.Fatalf("%d objects after another id, want 2", got)
	}
}

// The sweep handles both key forms together.
func TestTheSweepHandlesLegacyAndFullKeys(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	plantObject(t, dir, "snapshots/20260101T000000Z-aaaaaaaaaaaaaaaa.json", idSnap(strings.Repeat("a", 64), "l1"))
	plantObject(t, dir, "snapshots/20260102T000000Z-bbbbbbbbbbbbbbbb.json", idSnap(strings.Repeat("b", 64), "l2"))

	f := openFS(t, dir, epoch)
	for i, id := range []string{idOne, idTwo} {
		f.ver.now = (&steppingClock{now: epoch.Add(time.Duration(i) * time.Hour)}).Now
		if err := f.SaveSnapshot(ctx, idSnap(id, "new")); err != nil {
			t.Fatal(err)
		}
	}
	if got := countFSVersions(t, dir); got != 4 {
		t.Fatalf("%d objects, want 4", got)
	}
	n, err := f.SweepSnapshots(ctx, epoch.Add(1000*24*time.Hour))
	if err != nil || n != 3 {
		t.Fatalf("sweep removed %d (err %v), want the three replaced versions", n, err)
	}
	if got := countFSVersions(t, dir); got != 1 {
		t.Fatalf("%d objects left, want only the latest", got)
	}
}

// The sweep never removes the current version's object, even when another
// object sorts after it (a write that landed though its call reported an
// error, so the store did not adopt it).
func TestTheSweepNeverRemovesTheCurrentVersionsObject(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := openFS(t, dir, epoch)
	if err := f.SaveSnapshot(ctx, idSnap(idOne, "current")); err != nil {
		t.Fatal(err)
	}
	current, _ := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))

	plantObject(t, dir, snapshotKeyFor(epoch.Add(time.Hour), idTwo), idSnap(idTwo, "unadopted"))

	if _, err := f.SweepSnapshots(ctx, epoch.Add(1000*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(current[0]); err != nil {
		t.Fatalf("the current version's object is gone: %v", err)
	}
}
