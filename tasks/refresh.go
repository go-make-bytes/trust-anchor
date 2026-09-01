// Package tasks holds the service's background tasks (core.Tasker).
package tasks

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/go-make-bytes/trust-anchor/ingest"
)

// minWake bounds how aggressively the task can rewake on a near NextUpdate.
const minWake = time.Minute

// RefreshTask periodically runs the ingestion cycle: every interval
// (TRUST_REFRESH_INTERVAL), earlier when the earliest TL NextUpdate is due,
// and immediately on an admin trigger (/v1/refresh).
type RefreshTask struct {
	manager  *ingest.Manager
	interval time.Duration
	log      *zap.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

// NewRefreshTask builds the refresh task.
func NewRefreshTask(manager *ingest.Manager, interval time.Duration, log *zap.Logger) *RefreshTask {
	return &RefreshTask{manager: manager, interval: interval, log: log}
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
			timer := time.NewTimer(t.nextWake())
			select {
			case <-ctx.Done():
				timer.Stop()
				return
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

// nextWake returns the sleep until the next cycle: the regular interval,
// shortened to honor the earliest TL NextUpdate (never below minWake).
func (t *RefreshTask) nextWake() time.Duration {
	wake := t.interval
	if snap := t.manager.Active(); snap != nil {
		if due := snap.EarliestNextUpdate(); !due.IsZero() {
			if until := time.Until(due); until < wake {
				wake = until
			}
		}
	}
	if wake < minWake {
		wake = minWake
	}
	return wake
}
