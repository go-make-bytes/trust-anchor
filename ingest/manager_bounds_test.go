package ingest

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/go-make-bytes/trust-anchor/trust"
)

const testStoreBound = 150 * time.Millisecond

// within runs f and fails the test when it does not return in time, so a hung
// store shows as a failure and not as a stuck test run.
func within(t *testing.T, limit time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v: a store call is hanging the cycle", what, limit)
	}
}

// A store that stops answering cannot hang the cycle: the save is bounded, its
// failure is raised like any other, what is served is the new snapshot, and
// the save is owed to the next cycle.
func TestAStoreThatStopsAnsweringOnASaveDoesNotHangTheCycle(t *testing.T) {
	r := newVersionRig(t)
	r.cycle(versioned(t, 1, nil))
	r.m.storeTimeout = testStoreBound

	r.st.setBlock(true, false)
	var out RefreshOutcome
	within(t, 5*time.Second, "the cycle", func() {
		r.fake.snap = versioned(t, 1, flipCarriedOver(true))
		out = r.m.Refresh(context.Background())
	})
	if out.CycleErr != nil || !out.Changed || !r.m.Active().Territory("LV").CarriedOver {
		t.Fatalf("the cycle must complete and serve the new snapshot: %+v", out)
	}
	if !eventRaised(r.logs, "persist") {
		t.Fatal("no persist failure event was raised")
	}
	var logged bool
	for _, e := range r.logs.FilterLevelExact(zapcore.ErrorLevel).All() {
		if strings.Contains(entryText(e), "persistence failed") {
			logged = true
		}
	}
	if !logged {
		t.Fatal("the failed save was not logged at error level")
	}

	// The store answers again: the owed save happens though nothing moved.
	r.st.setBlock(false, false)
	r.cycle(versioned(t, 1, flipCarriedOver(true)))
	if !r.stored().Territory("LV").CarriedOver {
		t.Fatal("the next cycle did not save what is served")
	}
}

func TestAStoreThatStopsAnsweringOnASweepDoesNotHangTheCycle(t *testing.T) {
	r := newVersionRig(t)
	r.m.storeTimeout = testStoreBound
	r.st.setBlock(false, true)

	next := versioned(t, 1, nil)
	var out RefreshOutcome
	within(t, 5*time.Second, "the cycle", func() {
		r.fake.snap = next
		out = r.m.Refresh(context.Background())
	})
	if out.CycleErr != nil || r.m.Active().ID != next.ID {
		t.Fatalf("a hanging sweep changed the cycle: %+v", out)
	}
	if !eventRaised(r.logs, "sweep") {
		t.Fatal("no sweep failure event was raised")
	}
	_, before := r.st.counts()
	r.st.setBlock(false, false)
	r.cycle(versioned(t, 1, nil))
	if _, got := r.st.counts(); got != before+1 {
		t.Fatal("the next cycle did not sweep again")
	}
}

// Approving a held addition saves under the same bound: the call fails in time
// and nothing new is served.
func TestAStoreThatStopsAnsweringOnAnApprovalDoesNotHangIt(t *testing.T) {
	r := newVersionRig(t)
	snap := versioned(t, 1, nil)
	snap.Pending = []trust.PendingAnchor{{Anchor: trust.Anchor{
		Territory: "LV", Source: trust.SourceTL, TSPName: "LVRTC", ServiceName: "New ICA",
		Status: trust.NormalizeStatus("granted"), FingerprintSHA256: "bb22", CertDER: []byte{2},
	}, FirstSeen: time.Now().UTC()}}
	snap.ComputeID()
	r.cycle(snap)
	r.m.storeTimeout = testStoreBound

	r.st.setBlock(true, false)
	var err error
	within(t, 5*time.Second, "the approval", func() { _, err = r.m.ApprovePending(nil, "bb22", "ops") })
	if err == nil {
		t.Fatal("an approval whose save timed out reported success")
	}
	if r.m.Active().ID != snap.ID {
		t.Fatal("a snapshot whose save failed was activated")
	}
}

// A sweep that removed versions leaves a record carrying how many and the
// cutoff; a sweep that removed none leaves none.
func TestASweepThatRemovedVersionsRaisesAnEventAndOneThatRemovedNoneDoesNot(t *testing.T) {
	const eventType = "trust.snapshots_swept"
	clock := time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC)
	cutoff := clock.Add(-DefaultSnapshotRetention).Format(time.RFC3339)

	count := func(r *versionRig) (n int, text string) {
		for _, e := range r.logs.All() {
			if e.Message == "security_event" && strings.Contains(entryText(e), eventType) {
				n++
				text = entryText(e)
			}
		}
		return n, text
	}

	removed := newVersionRig(t)
	removed.m.now = func() time.Time { return clock }
	removed.st.mu.Lock()
	removed.st.sweepRemoved = 2
	removed.st.mu.Unlock()
	removed.cycle(versioned(t, 1, nil))
	n, text := count(removed)
	if n != 1 {
		t.Fatalf("%d %s events after a sweep that removed 2, want 1", n, eventType)
	}
	if !strings.Contains(text, "removed") || !strings.Contains(text, "2") || !strings.Contains(text, cutoff) {
		t.Fatalf("the event does not carry the count and the cutoff %s: %s", cutoff, text)
	}

	none := newVersionRig(t)
	none.cycle(versioned(t, 1, nil))
	if n, _ := count(none); n != 0 {
		t.Fatalf("%d %s events after a sweep that removed none, want 0", n, eventType)
	}
}
