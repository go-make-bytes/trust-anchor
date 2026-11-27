// Package tasks holds the service's background tasks (core.Tasker).
package tasks

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/ingest"
	"github.com/go-make-bytes/trust-anchor/trust"
)

// minWake bounds how aggressively the task can rewake on a near NextUpdate.
const minWake = time.Minute

// RefreshTask periodically runs the ingestion cycle: every interval
// (TRUST_REFRESH_INTERVAL), earlier when a TL NextUpdate still ahead is due
// sooner, earlier still (TRUST_OVERDUE_RETRY_INTERVAL) when a NextUpdate is
// already past. The admin route (/v1/refresh) runs its own cycle in the
// request; the task then counts its wait again from the snapshot that cycle
// left, without running another one. A trigger through Manager.TriggerRefresh
// runs a cycle in the task at once.
type RefreshTask struct {
	manager  *ingest.Manager
	interval time.Duration
	overdue  time.Duration
	log      *zap.Logger

	// newTimer starts the wait before the next cycle; tests replace it to
	// read the waits without sleeping them.
	newTimer func(time.Duration) *time.Timer

	cancel context.CancelFunc
	done   chan struct{}
}

// NewRefreshTask builds the refresh task. overdue is the wait before asking
// again for a list whose next-update date is already past
// (TRUST_OVERDUE_RETRY_INTERVAL).
func NewRefreshTask(manager *ingest.Manager, interval, overdue time.Duration, log *zap.Logger) *RefreshTask {
	return &RefreshTask{manager: manager, interval: interval, overdue: overdue, log: log, newTimer: time.NewTimer}
}

// Name implements core.Tasker.
func (t *RefreshTask) Name() string { return "trust-refresh" }

// Start launches the refresh loop. It must not block.
func (t *RefreshTask) Start(ctx context.Context) error {
	ctx, t.cancel = context.WithCancel(ctx)
	t.done = make(chan struct{})

	go func() {
		defer close(t.done)

		// First cycle right away when nothing is being served yet (fresh
		// install or empty store) so readiness comes up without waiting a
		// full interval.
		if t.manager.Active() == nil {
			t.run(ctx)
		}

		for {
			// A signal left by the cycle this task just ran (or one that ended
			// before the wait is counted below) is consumed here; one that
			// arrives after this point re-arms the wait.
			select {
			case <-t.manager.Refreshed():
			default:
			}
			timer := t.newTimer(t.nextWake())
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-t.manager.Refreshed():
				// A refresh the task did not start (the admin route runs its
				// cycle in the request): count the wait again from the
				// snapshot now served. No cycle runs.
				timer.Stop()
			case <-t.manager.Kick():
				timer.Stop()
				t.run(ctx)
			case <-timer.C:
				t.run(ctx)
			}
		}
	}()
	return nil
}

// Stop terminates the refresh loop.
func (t *RefreshTask) Stop() {
	if t.cancel != nil {
		t.cancel()
		<-t.done
		t.cancel = nil
	}
}

func (t *RefreshTask) run(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if out := t.manager.Refresh(ctx); out.CycleErr != nil {
		t.log.Error("scheduled refresh failed", zap.Error(out.CycleErr))
	}
}

// nextWake returns the sleep until the next cycle for the snapshot served now.
func (t *RefreshTask) nextWake() time.Duration {
	return wakeAfter(time.Now(), t.manager.Active(), t.interval, t.overdue)
}

// wakeAfter is the wait before the next cycle, a pure function of the clock and
// the snapshot served:
//
//   - the regular interval;
//   - or earlier, the time until the nearest next-update date still ahead;
//   - or earlier, the overdue wait when any date is already past — a date that is
//     past stays past, so asking for it again at the floor would repeat a cycle
//     every minute for as long as the publisher is late;
//   - never below minWake.
//
// A date that is exactly now counts as past.
func wakeAfter(now time.Time, snap *trust.Snapshot, interval, overdue time.Duration) time.Duration {
	wake := interval
	if snap != nil {
		var anyPast bool
		for _, due := range snap.NextUpdates() {
			until := due.Sub(now)
			if until <= 0 {
				anyPast = true
				continue
			}
			if until < wake {
				wake = until
			}
		}
		if anyPast && overdue < wake {
			wake = overdue
		}
	}
	if wake < minWake {
		wake = minWake
	}
	return wake
}
