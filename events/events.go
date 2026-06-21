// Package events emits the trust-anchor security events through
// go-sec-events. It adds one capability the upstream emitter lacks: emission
// from background work (the refresh Tasker) where no azugo request context
// exists — those events are stamped locally and written to the service logger
// in the exact LogSink shape ("security_event" lines), so the SIEM stream is
// uniform regardless of origin.
package events

import (
	"time"

	"azugo.io/azugo"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
)

// Event types emitted by the trust-anchor service.
const (
	EventAnchorChange          = "trust.anchor_change"
	EventBootstrapReviewNeeded = "trust.bootstrap_review_needed"
	EventBootstrapActivated    = "trust.bootstrap_activated"
	EventPendingApproved       = "trust.pending_approved"
	EventRefreshFailure        = "trust.refresh_failure"
	EventStale                 = "trust.stale"
	EventEgressViolation       = "egress.violation" // platform-standard type
)

// Emitter emits security events with or without a request context.
type Emitter struct {
	sec *secevents.Emitter
	log *zap.Logger
}

// New returns an Emitter that delivers request-scoped events through the
// go-sec-events log sink and background events through log.
func New(log *zap.Logger) *Emitter {
	return &Emitter{sec: secevents.NewEmitter(secevents.NewLogSink()), log: log}
}

// Emit delivers one security event. ctx may be nil for background work.
func (e *Emitter) Emit(ctx *azugo.Context, eventType string, sev secevents.Severity, outcome broker.Outcome, attrs map[string]any) {
	if e == nil {
		return
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs[secevents.AttrSeverity] = string(sev)

	ev := &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySecurity},
		Outcome:    outcome,
		Attributes: attrs,
	}

	if ctx != nil {
		if err := e.sec.Emit(ctx, ev); err != nil && e.log != nil {
			e.log.Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
		}
		return
	}

	// Background path: stamp locally and mirror the LogSink line shape.
	ev.EventID = ulid.Make().String()
	ev.OccurredAt = time.Now().UTC()

	if e.log == nil {
		return
	}
	fields := []zap.Field{
		zap.String("event_id", ev.EventID),
		zap.Time("occurred_at", ev.OccurredAt),
		zap.String("event_type", ev.EventType),
		zap.String("category", string(broker.CategorySecurity)),
		zap.String("outcome", string(ev.Outcome)),
		zap.String(secevents.AttrSeverity, string(sev)),
		zap.Any("attributes", ev.Attributes),
	}
	// Route the log level by severity AND outcome: reserve error for genuine
	// failures/denials. A success-outcome event (e.g. a first-ingest anchor
	// addition, which AnchorChange stamps High/success) is noteworthy, not an
	// error — cap it at warn so the SIEM stream isn't a wall of red.
	switch {
	case outcome != broker.OutcomeSuccess &&
		(sev == secevents.SeverityCritical || sev == secevents.SeverityHigh):
		e.log.Error("security_event", fields...)
	case sev == secevents.SeverityCritical || sev == secevents.SeverityHigh ||
		sev == secevents.SeverityWarning:
		e.log.Warn("security_event", fields...)
	default:
		e.log.Info("security_event", fields...)
	}
}

// AnchorChange emits one trust.anchor_change event for a diff entry.
// Additions and removals are high severity, metadata changes info (task §4
// change-governance rule).
func (e *Emitter) AnchorChange(ctx *azugo.Context, kind, territory, fingerprint, tspName, serviceName, status, detail string, pending bool) {
	sev := secevents.SeverityInfo
	if kind == "added" || kind == "removed" {
		sev = secevents.SeverityHigh
	}
	attrs := map[string]any{
		"kind":         kind,
		"territory":    territory,
		"fingerprint":  fingerprint,
		"tsp_name":     tspName,
		"service_name": serviceName,
		"status":       status,
	}
	if detail != "" {
		attrs["detail"] = detail
	}
	if pending {
		attrs["pending"] = true
	}
	e.Emit(ctx, EventAnchorChange, sev, broker.OutcomeSuccess, attrs)
}

// RefreshFailure emits the fail-safe warning: an ingestion cycle failed and
// the previous snapshot is still being served.
func (e *Emitter) RefreshFailure(ctx *azugo.Context, stage, reason string) {
	e.Emit(ctx, EventRefreshFailure, secevents.SeverityWarning, broker.OutcomeFailure, map[string]any{
		"stage":  stage,
		"reason": reason,
	})
}

// Stale emits the warning that served data is past NextUpdate + grace.
func (e *Emitter) Stale(ctx *azugo.Context, territory string, nextUpdate time.Time) {
	e.Emit(ctx, EventStale, secevents.SeverityWarning, broker.OutcomeSuccess, map[string]any{
		"territory":   territory,
		"next_update": nextUpdate.Format(time.RFC3339),
	})
}

// EgressBlocked emits the platform egress.violation event for a trusted-list
// pointer outside the https allow-list.
func (e *Emitter) EgressBlocked(ctx *azugo.Context, target, reason string) {
	e.Emit(ctx, EventEgressViolation, secevents.SeverityHigh, broker.OutcomeDenied, map[string]any{
		"target": target,
		"policy": "trusted-list-allowlist",
		"reason": reason,
	})
}

// BootstrapReviewNeeded emits the high-severity staged-bootstrap event.
func (e *Emitter) BootstrapReviewNeeded(ctx *azugo.Context, ojReference string, added, removed []string) {
	e.Emit(ctx, EventBootstrapReviewNeeded, secevents.SeverityHigh, broker.OutcomeSuccess, map[string]any{
		"oj_reference": ojReference,
		"added":        added,
		"removed":      removed,
	})
}

// BootstrapActivated records an operator-approved bootstrap activation.
func (e *Emitter) BootstrapActivated(ctx *azugo.Context, ojReference string, version int, actor string) {
	e.Emit(ctx, EventBootstrapActivated, secevents.SeverityHigh, broker.OutcomeSuccess, map[string]any{
		"oj_reference": ojReference,
		"version":      version,
		"actor_id":     actor,
	})
}

// PendingApproved records a hold-mode addition approval.
func (e *Emitter) PendingApproved(ctx *azugo.Context, fingerprint, actor, how string) {
	e.Emit(ctx, EventPendingApproved, secevents.SeverityWarning, broker.OutcomeSuccess, map[string]any{
		"fingerprint": fingerprint,
		"actor_id":    actor,
		"how":         how, // "api" | "auto-release"
	})
}
