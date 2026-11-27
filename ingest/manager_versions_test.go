package ingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/go-make-bytes/trust-anchor/events"
	"github.com/go-make-bytes/trust-anchor/store"
	"github.com/go-make-bytes/trust-anchor/trust"
)

// spyStore wraps the in-memory store: it counts the calls the manager makes,
// can be made to fail, and delegates the rest so versions are counted honestly.
type spyStore struct {
	*store.Memory

	mu        sync.Mutex
	saves     int
	sweeps    []time.Time
	failSave  error
	failSweep error

	// blockSave and blockSweep make the call wait until its context ends, as
	// a store that stopped answering would.
	blockSave, blockSweep bool
	// sweepRemoved, when set, is what a sweep reports as removed.
	sweepRemoved int
}

func (s *spyStore) setBlock(save, sweep bool) {
	s.mu.Lock()
	s.blockSave, s.blockSweep = save, sweep
	s.mu.Unlock()
}

func newSpyStore() *spyStore { return &spyStore{Memory: store.NewMemory()} }

func (s *spyStore) SaveSnapshot(ctx context.Context, snap *trust.Snapshot) error {
	s.mu.Lock()
	s.saves++
	fail, block := s.failSave, s.blockSave
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	if fail != nil {
		return fail
	}

	return s.Memory.SaveSnapshot(ctx, snap)
}

func (s *spyStore) SweepSnapshots(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	s.sweeps = append(s.sweeps, before)
	fail, block, removed := s.failSweep, s.blockSweep, s.sweepRemoved
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if fail != nil {
		return 0, fail
	}
	if removed > 0 {
		return removed, nil
	}

	return s.Memory.SweepSnapshots(ctx, before)
}

func (s *spyStore) setFailSave(err error) { s.mu.Lock(); s.failSave = err; s.mu.Unlock() }
func (s *spyStore) setFailSweep(err error) {
	s.mu.Lock()
	s.failSweep = err
	s.mu.Unlock()
}

func (s *spyStore) counts() (saves, sweeps int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.saves, len(s.sweeps)
}

// versioned builds the snapshot of content version seq (the content id follows
// it) with the given change applied outside the id.
func versioned(t *testing.T, seq uint64, mutate func(*trust.Snapshot)) *trust.Snapshot {
	t.Helper()
	s := managerSnapshot(t)
	s.LOTLSequence = seq
	if mutate != nil {
		mutate(s)
	}
	s.ComputeID()

	return s
}

// versionRig is a manager over a spy store with one scripted refresher.
type versionRig struct {
	t    *testing.T
	m    *Manager
	st   *spyStore
	fake *fakeRefresher
	logs *observer.ObservedLogs
}

func newVersionRig(t *testing.T) *versionRig {
	t.Helper()
	core, logs := observer.New(zapcore.InfoLevel)
	st := newSpyStore()
	fake := &fakeRefresher{}
	m := NewManager(fake, st, events.New(zap.New(core)), zap.New(core))
	seedBootstrap(t, st.Memory)
	if err := m.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	return &versionRig{t: t, m: m, st: st, fake: fake, logs: logs}
}

// cycle runs one refresh that yields snap and requires it to complete.
func (r *versionRig) cycle(snap *trust.Snapshot) RefreshOutcome {
	r.t.Helper()
	r.fake.snap = snap
	out := r.m.Refresh(context.Background())
	if out.CycleErr != nil {
		r.t.Fatalf("cycle: %v", out.CycleErr)
	}

	return out
}

func (r *versionRig) stored() *trust.Snapshot {
	r.t.Helper()
	got, err := r.st.LoadLatestSnapshot(context.Background())
	if err != nil || got == nil {
		r.t.Fatalf("load latest: %v %v", got, err)
	}

	return got
}

func (r *versionRig) wantVersions(n int, what string) {
	r.t.Helper()
	if got := r.st.SnapshotVersions(); got != n {
		r.t.Fatalf("%s: %d stored versions, want %d", what, got, n)
	}
}

func flipCarriedOver(on bool) func(*trust.Snapshot) {
	return func(s *trust.Snapshot) {
		s.Territories[0].CarriedOver = on
		if on {
			s.Territories[0].CarriedOverReason = fmt.Sprintf("fetch failed at %d", time.Now().UnixNano())
		}
	}
}

func TestACycleWithANewIDStoresANewVersion(t *testing.T) {
	r := newVersionRig(t)
	out := r.cycle(versioned(t, 1, nil))
	if !out.Changed {
		t.Fatal("the first cycle must report a change")
	}
	r.wantVersions(1, "first cycle")

	second := versioned(t, 2, nil)
	out = r.cycle(second)
	if !out.Changed {
		t.Fatal("a new id must report a change")
	}
	r.wantVersions(2, "new id")
	if r.stored().ID != second.ID {
		t.Fatal("the newest stored version is not the new id")
	}
}

func TestACycleWithTheSameIDAndNothingMovedDoesNotCallTheStore(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))
	savesBefore, _ := r.st.counts()

	out := r.cycle(versioned(t, 1, nil))
	if out.Changed {
		t.Error("nothing moved, yet the cycle reported a change")
	}
	if saves, _ := r.st.counts(); saves != savesBefore {
		t.Fatalf("the store was called %d more time(s) for a cycle that moved nothing", saves-savesBefore)
	}
	r.wantVersions(1, "unchanged cycle")
}

// A territory's health flip under the same id is served and reported as a
// change, and is stored into the same version, not a new one.
func TestAHealthFlipUnderTheSameIDRewritesTheVersionInPlace(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))

	out := r.cycle(versioned(t, 1, flipCarriedOver(true)))
	if !out.Changed {
		t.Fatal("a health flip must still be reported as a change")
	}
	if !r.m.Active().Territory("LV").CarriedOver {
		t.Fatal("the flip is not served")
	}
	r.wantVersions(1, "health flip")
	if !r.stored().Territory("LV").CarriedOver {
		t.Fatal("the stored version does not carry the new flag")
	}
}

// Flip, flip back, flip again: still one version, carrying the last cycle's
// flag.
func TestRepeatedHealthFlipsKeepOneVersion(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))

	for i, on := range []bool{true, false, true} {
		out := r.cycle(versioned(t, 1, flipCarriedOver(on)))
		if !out.Changed {
			t.Fatalf("flip %d to %v not reported as a change", i+1, on)
		}
		r.wantVersions(1, fmt.Sprintf("flip %d", i+1))
		if got := r.stored().Territory("LV").CarriedOver; got != on {
			t.Fatalf("flip %d: stored flag %v, want %v", i+1, got, on)
		}
	}
}

// What a restart would restore differs when only a date or a digest moved:
// it is stored, in place, and not reported as a change to what is served.
func TestDatesAndDigestsMovingOnTheirOwnAreStoredButNotAChange(t *testing.T) {
	later := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*trust.Snapshot)
		check  func(*trust.Snapshot) bool
	}{
		{"a territory's next-update", func(s *trust.Snapshot) { s.Territories[0].NextUpdate = &later },
			func(s *trust.Snapshot) bool { n := s.Territories[0].NextUpdate; return n != nil && n.Equal(later) }},
		{"a territory's issue time", func(s *trust.Snapshot) { s.Territories[0].IssueTime = later },
			func(s *trust.Snapshot) bool { return s.Territories[0].IssueTime.Equal(later) }},
		{"a territory's source digest", func(s *trust.Snapshot) { s.Territories[0].SourceDigest = "d2" },
			func(s *trust.Snapshot) bool { return s.Territories[0].SourceDigest == "d2" }},
		{"the list of the lists' next-update", func(s *trust.Snapshot) { s.LOTLNextUpdate = &later },
			func(s *trust.Snapshot) bool { return s.LOTLNextUpdate != nil && s.LOTLNextUpdate.Equal(later) }},
		{"the list of the lists' issue time", func(s *trust.Snapshot) { s.LOTLIssueTime = later },
			func(s *trust.Snapshot) bool { return s.LOTLIssueTime.Equal(later) }},
		{"the list of the lists' digest", func(s *trust.Snapshot) { s.LOTLDigest = "abc" },
			func(s *trust.Snapshot) bool { return s.LOTLDigest == "abc" }},
		{"a next-update and a source digest together", func(s *trust.Snapshot) {
			s.Territories[0].NextUpdate = &later
			s.Territories[0].SourceDigest = "d3"
		}, func(s *trust.Snapshot) bool { return s.Territories[0].SourceDigest == "d3" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newVersionRig(t)
			r.cycle(versioned(t, 1, nil))

			out := r.cycle(versioned(t, 1, tc.mutate))
			if out.Changed {
				t.Error("an inputs-only move must not be reported as a change")
			}
			r.wantVersions(1, tc.name)
			if !tc.check(r.stored()) {
				t.Fatalf("the stored version does not carry the move: %+v", r.stored().Territories[0])
			}
		})
	}
}

// The free-text reason differs on every failure; on its own it is not a reason
// to save.
func TestAChangingFailureReasonAloneDoesNotSave(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, flipCarriedOver(true)))
	savesBefore, _ := r.st.counts()

	r.cycle(versioned(t, 1, flipCarriedOver(true))) // same flag, a different reason text
	if saves, _ := r.st.counts(); saves != savesBefore {
		t.Fatal("a reason text that changed alone saved a version")
	}
}

// The ids go A, B, A: three versions, the newest is A.
func TestTheIDsGoingBackToAnEarlierOneStoreAThirdVersion(t *testing.T) {
	r := newVersionRig(t)
	a := versioned(t, 1, nil)
	r.cycle(a)
	r.cycle(versioned(t, 2, nil))
	r.cycle(versioned(t, 1, nil))

	r.wantVersions(3, "A, B, A")
	if r.stored().ID != a.ID {
		t.Fatal("the newest stored version is not A")
	}
}

// The store fails on a save: the cycle completes and serves from memory; the
// next cycles keep saving until a save succeeds, even though nothing moved.
func TestAFailedSaveIsOwedUntilItSucceeds(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))
	r.wantVersions(1, "start")

	r.st.setFailSave(errors.New("store is down"))
	out := r.cycle(versioned(t, 1, flipCarriedOver(true)))
	if !out.Changed || !r.m.Active().Territory("LV").CarriedOver {
		t.Fatal("the cycle must still serve the flip from memory")
	}
	if !eventRaised(r.logs, "persist") {
		t.Fatal("no persist failure event was raised")
	}
	saves, _ := r.st.counts()

	// Nothing moved, the store still fails: the save is tried again.
	r.cycle(versioned(t, 1, flipCarriedOver(true)))
	if got, _ := r.st.counts(); got != saves+1 {
		t.Fatalf("the owed save was not tried again (%d calls, want %d)", got, saves+1)
	}
	if r.stored().Territory("LV").CarriedOver {
		t.Fatal("the failed saves must not have reached the store")
	}

	// The store answers again: the next cycle saves, once.
	r.st.setFailSave(nil)
	r.cycle(versioned(t, 1, flipCarriedOver(true)))
	r.wantVersions(1, "after the store recovered")
	if !r.stored().Territory("LV").CarriedOver {
		t.Fatal("the store does not hold what is served after it recovered")
	}
	done, _ := r.st.counts()
	r.cycle(versioned(t, 1, flipCarriedOver(true)))
	if got, _ := r.st.counts(); got != done {
		t.Fatal("the save is no longer owed, yet the store was called")
	}
}

// A new id whose save failed ends as a new version once the store answers, and
// never overwrites the previous version.
func TestAFailedSaveOfANewIDEndsAsANewVersion(t *testing.T) {
	r := newVersionRig(t)
	a := versioned(t, 1, nil)
	r.cycle(a)

	r.st.setFailSave(errors.New("store is down"))
	b := versioned(t, 2, nil)
	r.cycle(b)
	r.wantVersions(1, "while the store is down")
	if r.stored().ID != a.ID {
		t.Fatal("the failed save changed the stored version")
	}

	r.st.setFailSave(nil)
	r.cycle(versioned(t, 2, nil))
	r.wantVersions(2, "after the store recovered")
	if r.stored().ID != b.ID {
		t.Fatal("the new id is not the newest version")
	}
}

// A restart after a health flip restores the flag of the last cycle.
func TestARestartRestoresTheLastCyclesHealth(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))
	r.cycle(versioned(t, 1, flipCarriedOver(true)))

	m2 := NewManager(&fakeRefresher{}, r.st, events.New(zap.NewNop()), zap.NewNop())
	if err := m2.Initialize(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got := m2.Active(); got == nil || !got.Territory("LV").CarriedOver {
		t.Fatalf("the restored snapshot does not carry the flag: %+v", got)
	}
}

// The sweep runs at the end of every completed cycle, saved or not, with the
// cutoff the retention gives.
func TestEveryCompletedCycleSweepsWithTheRetentionCutoff(t *testing.T) {
	r := newVersionRig(t)
	clock := time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC)
	r.m.now = func() time.Time { return clock }

	r.cycle(versioned(t, 1, nil)) // saves
	r.cycle(versioned(t, 1, nil)) // saves nothing
	r.cycle(versioned(t, 1, nil)) // saves nothing

	saves, sweeps := r.st.counts()
	if saves != 1 || sweeps != 3 {
		t.Fatalf("%d saves and %d sweeps, want 1 and 3", saves, sweeps)
	}
	for i, before := range r.st.sweeps {
		if want := clock.Add(-90 * 24 * time.Hour); !before.Equal(want) {
			t.Fatalf("sweep %d cutoff = %v, want %v (90 days)", i, before, want)
		}
	}

	r.m.SetRetention(48 * time.Hour)
	r.cycle(versioned(t, 1, nil))
	if got, want := r.st.sweeps[len(r.st.sweeps)-1], clock.Add(-48*time.Hour); !got.Equal(want) {
		t.Fatalf("cutoff with a 48h retention = %v, want %v", got, want)
	}
}

// A failed cycle (nothing produced) is not a completed cycle: no sweep.
func TestAFailedCycleDoesNotSweep(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))
	_, before := r.st.counts()

	r.fake.err = errors.New("upstream down")
	if out := r.m.Refresh(context.Background()); out.CycleErr == nil {
		t.Fatal("the cycle was meant to fail")
	}
	if _, got := r.st.counts(); got != before {
		t.Fatal("a failed cycle swept")
	}
}

// A failed sweep never fails the cycle or changes what is served; it is logged
// at error level and raised as a refresh failure of its own stage; the next
// cycle sweeps again.
func TestAFailedSweepNeverFailsTheCycle(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))
	r.st.setFailSweep(errors.New("sweep refused"))

	next := versioned(t, 2, nil)
	out := r.cycle(next)
	if out.CycleErr != nil || !out.Changed || out.Snapshot.ID != next.ID || r.m.Active().ID != next.ID {
		t.Fatalf("a failing sweep changed the cycle: %+v", out)
	}
	if !eventRaised(r.logs, "sweep") {
		t.Fatal("no refresh failure event named the sweep stage")
	}
	var logged bool
	for _, e := range r.logs.FilterLevelExact(zapcore.ErrorLevel).All() {
		if strings.Contains(entryText(e), "sweep") {
			logged = true
		}
	}
	if !logged {
		t.Fatal("the sweep failure was not logged at error level")
	}

	_, before := r.st.counts()
	r.cycle(versioned(t, 2, nil))
	if _, got := r.st.counts(); got != before+1 {
		t.Fatal("the next cycle did not call the sweep again")
	}
}

// eventRaised reports whether a refresh-failure event carrying the stage was
// written to the observed logger.
func eventRaised(logs *observer.ObservedLogs, stage string) bool {
	for _, e := range logs.All() {
		if e.Message != "security_event" {
			continue
		}
		text := entryText(e)
		if strings.Contains(text, events.EventRefreshFailure) && strings.Contains(text, stage) {
			return true
		}
	}

	return false
}

// entryText renders a logged entry and all its fields as one string.
func entryText(e observer.LoggedEntry) string {
	var b strings.Builder
	b.WriteString(e.Message)
	for _, f := range e.Context {
		fmt.Fprintf(&b, " %s=%s %v", f.Key, f.String, f.Interface)
	}

	return b.String()
}
