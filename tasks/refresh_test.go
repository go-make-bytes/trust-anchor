package tasks

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/events"
	"github.com/go-make-bytes/trust-anchor/ingest"
	"github.com/go-make-bytes/trust-anchor/store"
	"github.com/go-make-bytes/trust-anchor/trust"
)

var clockNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) *time.Time {
	t := clockNow.Add(d)
	return &t
}

// snapshotDue builds a snapshot with a list of the lists due at lotl (nil =
// no date) and one territory per further date.
func snapshotDue(lotl *time.Time, territories ...*time.Time) *trust.Snapshot {
	s := &trust.Snapshot{LOTLNextUpdate: lotl}
	for _, d := range territories {
		s.Territories = append(s.Territories, &trust.Territory{Code: "XX", NextUpdate: d})
	}

	return s
}

func TestWakeAfter(t *testing.T) {
	const (
		interval = 6 * time.Hour
		overdue  = time.Hour
	)
	cases := []struct {
		name     string
		snap     *trust.Snapshot
		interval time.Duration
		overdue  time.Duration
		want     time.Duration
	}{
		{"nothing served yet", nil, interval, overdue, interval},
		{"no date known", snapshotDue(nil, nil), interval, overdue, interval},
		{"every date further ahead than the interval", snapshotDue(at(30*24*time.Hour), at(20*24*time.Hour)), interval, overdue, interval},
		{"a date exactly the interval ahead", snapshotDue(nil, at(interval)), interval, overdue, interval},
		{"nearest date 10 minutes ahead", snapshotDue(at(48*time.Hour), at(10*time.Minute)), interval, overdue, 10 * time.Minute},
		{"nearest date 30 seconds ahead is held to the floor", snapshotDue(nil, at(30*time.Second)), interval, overdue, time.Minute},
		{"one second ahead is held to the floor", snapshotDue(nil, at(time.Second)), interval, overdue, time.Minute},
		{"one second past waits the overdue interval", snapshotDue(nil, at(-time.Second)), interval, overdue, overdue},
		{"due exactly now counts as past", snapshotDue(nil, at(0)), interval, overdue, overdue},
		{"six months past, the rest months ahead", snapshotDue(at(60*24*time.Hour), at(-180*24*time.Hour), at(90*24*time.Hour)), interval, overdue, overdue},
		{"one past and another due in 10 minutes", snapshotDue(nil, at(-24*time.Hour), at(10*time.Minute)), interval, overdue, 10 * time.Minute},
		{"one past and another due in 2 hours", snapshotDue(nil, at(-24*time.Hour), at(2*time.Hour)), interval, overdue, overdue},
		{"overdue wait longer than the interval never slows the regular pace", snapshotDue(nil, at(-time.Hour)), interval, 12 * time.Hour, interval},
		{"overdue wait equal to the interval", snapshotDue(nil, at(-time.Hour)), interval, interval, interval},
		{"the list of the lists itself is past", snapshotDue(at(-48*time.Hour), at(90*24*time.Hour)), interval, overdue, overdue},
		{"the list of the lists past, a territory due in 5 minutes", snapshotDue(at(-time.Hour), at(5*time.Minute)), interval, overdue, 5 * time.Minute},
		{"overdue wait of exactly the floor", snapshotDue(nil, at(-time.Hour)), interval, time.Minute, time.Minute},
		{"interval under the floor is held to it", snapshotDue(nil, nil), 30 * time.Second, overdue, time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wakeAfter(clockNow, tc.snap, tc.interval, tc.overdue); got != tc.want {
				t.Fatalf("wake = %v, want %v", got, tc.want)
			}
		})
	}
}

// A list that stays late is asked for once an hour for as long as it is late,
// never at the floor twice in a row; once it is replaced by one with a date
// ahead the regular rule returns.
func TestWakeAfterALateListThenItsReplacement(t *testing.T) {
	const (
		interval = 6 * time.Hour
		overdue  = time.Hour
	)
	late := snapshotDue(at(30*24*time.Hour), at(-180*24*time.Hour))
	now := clockNow
	for i := 0; i < 5; i++ {
		if got := wakeAfter(now, late, interval, overdue); got != overdue {
			t.Fatalf("round %d: wake = %v, want %v", i, got, overdue)
		}
		now = now.Add(overdue)
	}

	fixed := snapshotDue(at(30*24*time.Hour), at(90*24*time.Hour))
	if got := wakeAfter(now, fixed, interval, overdue); got != interval {
		t.Fatalf("replaced by a date far ahead: wake = %v, want %v", got, interval)
	}
	soon := snapshotDue(at(30*24*time.Hour), ptr(now.Add(10*time.Minute)))
	if got := wakeAfter(now, soon, interval, overdue); got != 10*time.Minute {
		t.Fatalf("replaced by a date 10 minutes ahead: wake = %v, want 10m", got)
	}
}

func ptr(t time.Time) *time.Time { return &t }

// lateRefresher returns a snapshot whose list is past its next-update date and
// counts the cycles.
type lateRefresher struct {
	mu     sync.Mutex
	cycles int
	cycled chan struct{}
}

func (r *lateRefresher) Refresh(_ context.Context, _ *trust.Snapshot, _ *trust.Bootstrap) (*trust.Snapshot, error) {
	past := time.Now().Add(-180 * 24 * time.Hour)
	s := &trust.Snapshot{
		GeneratedAt:  time.Now().UTC(),
		LOTLSequence: 1,
		Territories:  []*trust.Territory{{Code: "XX", TLSequence: 1, NextUpdate: &past}},
	}
	s.ComputeID()
	r.mu.Lock()
	r.cycles++
	r.mu.Unlock()
	r.cycled <- struct{}{}

	return s, nil
}

func (r *lateRefresher) RefreshDeclared(*trust.Snapshot, time.Time) (*trust.Snapshot, bool, trust.DeclaredReport, error) {
	return nil, false, trust.DeclaredReport{}, nil
}

// scriptedRefresher yields a snapshot whose only next-update date is whatever
// due returns, and counts the cycles it ran.
type scriptedRefresher struct {
	mu     sync.Mutex
	cycles int
	due    func() time.Time
}

func (r *scriptedRefresher) Refresh(_ context.Context, _ *trust.Snapshot, _ *trust.Bootstrap) (*trust.Snapshot, error) {
	r.mu.Lock()
	r.cycles++
	due := r.due()
	r.mu.Unlock()
	s := &trust.Snapshot{
		GeneratedAt:  time.Now().UTC(),
		LOTLSequence: 1,
		Territories:  []*trust.Territory{{Code: "XX", TLSequence: 1, NextUpdate: &due}},
	}
	s.ComputeID()

	return s, nil
}

func (r *scriptedRefresher) RefreshDeclared(*trust.Snapshot, time.Time) (*trust.Snapshot, bool, trust.DeclaredReport, error) {
	return nil, false, trust.DeclaredReport{}, nil
}

func (r *scriptedRefresher) setDue(f func() time.Time) {
	r.mu.Lock()
	r.due = f
	r.mu.Unlock()
}

func (r *scriptedRefresher) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.cycles
}

// A refresh the task did not start (the admin route runs its cycle in the
// request, calling the manager directly) makes the task count its wait again
// from the snapshot now served, without running another cycle.
func TestARefreshTheTaskDidNotStartMakesItCountItsWaitAgain(t *testing.T) {
	const (
		interval = 6 * time.Hour
		overdue  = 30 * time.Minute
	)
	farAhead := func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }

	cases := []struct {
		name    string
		due     func() time.Time
		inRange func(time.Duration) bool
	}{
		{"a list past its next-update", func() time.Time { return time.Now().Add(-180 * 24 * time.Hour) },
			func(d time.Duration) bool { return d == overdue }},
		{"a date ten minutes ahead", func() time.Time { return time.Now().Add(10 * time.Minute) },
			func(d time.Duration) bool { return d > 9*time.Minute && d <= 10*time.Minute }},
		{"no date moved", farAhead,
			func(d time.Duration) bool { return d == interval }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &scriptedRefresher{due: farAhead}
			mgr := ingest.NewManager(fake, store.NewMemory(), events.New(zap.NewNop()), zap.NewNop())

			waits := make(chan time.Duration, 8)
			task := NewRefreshTask(mgr, interval, overdue, zap.NewNop())
			task.newTimer = func(d time.Duration) *time.Timer {
				waits <- d
				return time.NewTimer(time.Hour) // never fires inside the test
			}
			if err := task.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer task.Stop()

			next := func(what string) time.Duration {
				t.Helper()
				select {
				case d := <-waits:
					return d
				case <-time.After(2 * time.Second):
					t.Fatalf("no wait armed: %s", what)
					return 0
				}
			}

			if d := next("after the first cycle"); d != interval {
				t.Fatalf("first wait = %v, want the regular interval %v", d, interval)
			}
			if fake.count() != 1 {
				t.Fatalf("%d cycles after start, want 1", fake.count())
			}

			// What the admin route does: one cycle, in the caller's goroutine.
			fake.setDue(tc.due)
			if out := mgr.Refresh(context.Background()); out.CycleErr != nil {
				t.Fatal(out.CycleErr)
			}

			if d := next("after a refresh the task did not start"); !tc.inRange(d) {
				t.Fatalf("wait after the direct refresh = %v", d)
			}
			if fake.count() != 2 {
				t.Fatalf("%d cycles, want 2: counting the wait again must not run a cycle", fake.count())
			}
			select {
			case d := <-waits:
				t.Fatalf("an extra wait %v was armed: the task is re-arming in a loop", d)
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

// An admin-triggered refresh runs at once while the service waits out a late
// list, and the wait after it is the late-list wait again, not the floor.
func TestAdminRefreshRunsAtOnceAndTheWaitAfterItIsCountedAgain(t *testing.T) {
	const (
		interval = 6 * time.Hour
		overdue  = 30 * time.Minute
	)
	fake := &lateRefresher{cycled: make(chan struct{}, 8)}
	mgr := ingest.NewManager(fake, store.NewMemory(), events.New(zap.NewNop()), zap.NewNop())

	waits := make(chan time.Duration, 8)
	task := NewRefreshTask(mgr, interval, overdue, zap.NewNop())
	task.newTimer = func(d time.Duration) *time.Timer {
		waits <- d
		return time.NewTimer(time.Hour) // never fires inside the test
	}
	if err := task.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer task.Stop()

	recv := func(what string) {
		t.Helper()
		select {
		case <-fake.cycled:
		case <-time.After(5 * time.Second):
			t.Fatalf("no cycle: %s", what)
		}
	}
	wait := func(what string) time.Duration {
		t.Helper()
		select {
		case d := <-waits:
			return d
		case <-time.After(5 * time.Second):
			t.Fatalf("no wait set: %s", what)
			return 0
		}
	}

	recv("the first cycle runs at start")
	if d := wait("after the first cycle"); d != overdue {
		t.Fatalf("wait after the first cycle = %v, want the late-list wait %v", d, overdue)
	}

	mgr.TriggerRefresh()
	recv("the admin trigger runs a cycle at once")
	if d := wait("after the admin cycle"); d != overdue {
		t.Fatalf("wait after the admin cycle = %v, want the late-list wait %v", d, overdue)
	}
}
