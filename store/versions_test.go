package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-make-bytes/trust-anchor/trust"
)

var epoch = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// steppingClock returns a clock that stays where it was put until moved.
type steppingClock struct{ now time.Time }

func (c *steppingClock) Now() time.Time { return c.now }

// versionSnap builds a snapshot whose content id follows seq and whose
// digest (outside the id) tells one save of the same version from another.
func versionSnap(seq uint64, digest string) *trust.Snapshot {
	s := &trust.Snapshot{
		GeneratedAt:  epoch,
		LOTLSequence: seq,
		LOTLDigest:   digest,
		Territories: []*trust.Territory{{
			Code: "LV", TLSequence: 51,
			Anchors: []trust.Anchor{{Territory: "LV", FingerprintSHA256: "aa", CertDER: []byte{1, 2, 3}}},
		}},
	}
	s.ComputeID()

	return s
}

type storeUnderTest struct {
	name  string
	make  func(t *testing.T) (Store, *steppingClock)
	count func(t *testing.T, s Store) int
}

func countFSVersions(t *testing.T, dir string) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if err != nil {
		t.Fatal(err)
	}

	return len(files)
}

func storesUnderTest() []storeUnderTest {
	return []storeUnderTest{
		{
			name: "memory",
			make: func(t *testing.T) (Store, *steppingClock) {
				t.Helper()
				m := NewMemory()
				clk := &steppingClock{now: epoch}
				m.setClock(clk.Now)

				return m, clk
			},
			count: func(t *testing.T, s Store) int { t.Helper(); return s.(*Memory).SnapshotVersions() },
		},
		{
			name: "fs",
			make: func(t *testing.T) (Store, *steppingClock) {
				t.Helper()
				f, err := NewFS(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				clk := &steppingClock{now: epoch}
				f.setClock(clk.Now)

				return f, clk
			},
			count: func(t *testing.T, s Store) int { t.Helper(); return countFSVersions(t, s.(*FS).dir) },
		},
	}
}

func latestDigest(t *testing.T, s Store) (string, string) {
	t.Helper()
	got, err := s.LoadLatestSnapshot(context.Background())
	if err != nil || got == nil {
		t.Fatalf("load latest: %v %v", got, err)
	}

	return got.ID, got.LOTLDigest
}

// The store keeps one stored version per content id: the same id replaces
// the latest in place, another id is a new version, and only the latest is
// ever replaced (A, B, A is three versions).
func TestSnapshotsKeepOneVersionPerContentID(t *testing.T) {
	ctx := context.Background()
	a1, a2, a3 := versionSnap(1, "a1"), versionSnap(1, "a2"), versionSnap(1, "a3")
	b := versionSnap(2, "b1")
	if a1.ID != a3.ID || a1.ID == b.ID {
		t.Fatal("test premise: the ids must follow the sequence")
	}

	steps := []struct {
		name       string
		save       *trust.Snapshot
		wantCount  int
		wantDigest string
	}{
		{"first save is a version", a1, 1, "a1"},
		{"the same id replaces it", a2, 1, "a2"},
		{"the same id again", a2, 1, "a2"},
		{"another id is a new version", b, 2, "b1"},
		{"back to the first id is a third version", a3, 3, "a3"},
		{"the same id again replaces that one", a1, 3, "a1"},
	}

	for _, su := range storesUnderTest() {
		t.Run(su.name, func(t *testing.T) {
			s, clk := su.make(t)
			for _, st := range steps {
				clk.now = clk.now.Add(time.Minute)
				if err := s.SaveSnapshot(ctx, st.save); err != nil {
					t.Fatalf("%s: %v", st.name, err)
				}
				if got := su.count(t, s); got != st.wantCount {
					t.Fatalf("%s: %d stored versions, want %d", st.name, got, st.wantCount)
				}
				if id, digest := latestDigest(t, s); id != st.save.ID || digest != st.wantDigest {
					t.Fatalf("%s: latest is %s/%s, want %s/%s", st.name, id[:8], digest, st.save.ID[:8], st.wantDigest)
				}
			}
		})
	}
}

// The sweep removes a version only once the version after it is older than the
// cutoff, never the latest, and a second sweep finds nothing.
func TestSweepRemovesOnlyVersionsReplacedBeforeTheCutoff(t *testing.T) {
	ctx := context.Background()
	day := 24 * time.Hour

	for _, su := range storesUnderTest() {
		t.Run(su.name, func(t *testing.T) {
			s, clk := su.make(t)

			if n, err := s.SweepSnapshots(ctx, epoch.Add(1000*day)); n != 0 || err != nil {
				t.Fatalf("empty store: removed %d, err %v", n, err)
			}

			// A first seen at +0, B at +1 day, C at +2 days: A was replaced at
			// +1 day, B at +2 days, C is the latest.
			for i, sn := range []*trust.Snapshot{versionSnap(1, "a"), versionSnap(2, "b"), versionSnap(3, "c")} {
				clk.now = epoch.Add(time.Duration(i) * day)
				if err := s.SaveSnapshot(ctx, sn); err != nil {
					t.Fatal(err)
				}
			}

			cut := epoch.Add(day) // exactly when A was replaced
			if n, err := s.SweepSnapshots(ctx, cut); n != 0 || err != nil {
				t.Fatalf("one second before the replacement ages out: removed %d, err %v", n, err)
			}
			if n, err := s.SweepSnapshots(ctx, cut.Add(time.Second)); n != 1 || err != nil {
				t.Fatalf("one second after: removed %d, err %v", n, err)
			}
			if got := su.count(t, s); got != 2 {
				t.Fatalf("%d versions after the first sweep, want 2", got)
			}
			if n, err := s.SweepSnapshots(ctx, cut.Add(time.Second)); n != 0 || err != nil {
				t.Fatalf("the same sweep twice: removed %d, err %v", n, err)
			}

			// A cutoff in the far future removes every replaced version and
			// keeps the latest.
			if n, err := s.SweepSnapshots(ctx, epoch.Add(1000*day)); n != 1 || err != nil {
				t.Fatalf("far future: removed %d, err %v", n, err)
			}
			if got := su.count(t, s); got != 1 {
				t.Fatalf("%d versions after the last sweep, want only the latest", got)
			}
			if _, digest := latestDigest(t, s); digest != "c" {
				t.Fatalf("latest after the sweep carries %q, want c", digest)
			}

			// A version that served for a long time stays until its own
			// replacement has aged: one version only, 400 days old, kept.
			if n, err := s.SweepSnapshots(ctx, epoch.Add(2000*day)); n != 0 || err != nil {
				t.Fatalf("the only version: removed %d, err %v", n, err)
			}
		})
	}
}

// A same-id save refreshes a version in place: it does not move the time the
// version was first seen, so the time its successor replaced it is unchanged.
func TestSameIDSaveKeepsTheFirstSeenTime(t *testing.T) {
	ctx := context.Background()
	hour := time.Hour

	for _, su := range storesUnderTest() {
		t.Run(su.name, func(t *testing.T) {
			s, clk := su.make(t)
			save := func(at time.Duration, sn *trust.Snapshot) {
				t.Helper()
				clk.now = epoch.Add(at)
				if err := s.SaveSnapshot(ctx, sn); err != nil {
					t.Fatal(err)
				}
			}
			save(0, versionSnap(1, "a"))
			save(10*hour, versionSnap(1, "a-later")) // refreshed ten hours on
			save(20*hour, versionSnap(2, "b"))       // replaces A at +20h

			if n, err := s.SweepSnapshots(ctx, epoch.Add(20*hour)); n != 0 || err != nil {
				t.Fatalf("at the replacement time: removed %d, err %v", n, err)
			}
			if n, err := s.SweepSnapshots(ctx, epoch.Add(20*hour+time.Second)); n != 1 || err != nil {
				t.Fatalf("just after: removed %d, err %v", n, err)
			}
		})
	}
}

// After a restart the files store finds the current version's object again:
// a same-id save overwrites it and a new id adds one.
func TestFSStoreFindsTheCurrentVersionAfterARestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	open := func(at time.Time) *FS {
		t.Helper()
		f, err := NewFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		clk := &steppingClock{now: at}
		f.setClock(clk.Now)

		return f
	}

	if err := open(epoch).SaveSnapshot(ctx, versionSnap(1, "a")); err != nil {
		t.Fatal(err)
	}
	before, _ := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))

	second := open(epoch.Add(time.Hour)) // a new process
	if err := second.SaveSnapshot(ctx, versionSnap(1, "a2")); err != nil {
		t.Fatal(err)
	}
	after, _ := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if len(before) != 1 || len(after) != 1 || before[0] != after[0] {
		t.Fatalf("a same-id save after a restart must overwrite the same object: %v -> %v", before, after)
	}
	if _, digest := latestDigest(t, second); digest != "a2" {
		t.Fatalf("latest carries %q, want a2", digest)
	}

	third := open(epoch.Add(2 * time.Hour))
	if err := third.SaveSnapshot(ctx, versionSnap(2, "b")); err != nil {
		t.Fatal(err)
	}
	if got := countFSVersions(t, dir); got != 2 {
		t.Fatalf("%d objects after a new id, want 2", got)
	}
}

// Version objects written by an earlier release (a key with the generation
// time to the second) are read by the sweep like any other: they age out by the
// same rule.
func TestFSStoreSweepsObjectsFromAnEarlierRelease(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	old := versionSnap(1, "old")
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "snapshots"), 0o750); err != nil {
		t.Fatal(err)
	}
	// Three objects of the same id, as the earlier release wrote them.
	for _, ts := range []string{"20260101T000000Z", "20260101T010000Z", "20260101T020000Z"} {
		if err := os.WriteFile(filepath.Join(dir, "snapshots", ts+"-"+old.ID[:16]+".json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "snapshot-latest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := NewFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	clk := &steppingClock{now: epoch}
	f.setClock(clk.Now)

	// The same id arrives: it replaces the newest object, the two before it
	// stay history and age out.
	if err := f.SaveSnapshot(ctx, versionSnap(1, "new")); err != nil {
		t.Fatal(err)
	}
	if got := countFSVersions(t, dir); got != 3 {
		t.Fatalf("%d objects, want 3 (the newest replaced in place)", got)
	}
	n, err := f.SweepSnapshots(ctx, epoch)
	if err != nil || n != 2 {
		t.Fatalf("sweep removed %d (err %v), want the two older objects", n, err)
	}
	if got := countFSVersions(t, dir); got != 1 {
		t.Fatalf("%d objects left, want 1", got)
	}
}
