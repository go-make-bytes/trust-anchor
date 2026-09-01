// Package events emits the trust-anchor security events through go-sec-events,
// from the request path and from background work alike — the refresh Tasker has
// no request, and the library serves both.
package events

import (
	"context"
	"time"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"
)

// Event types emitted by the trust-anchor service.
const (
	EventAnchorChange    = "trust.anchor_change"
	EventPendingApproved = "trust.pending_approved"
	EventRefreshFailure  = "trust.refresh_failure"
	EventStale           = "trust.stale"
	EventEgressViolation = "egress.violation" // platform-standard type
	// EventInternalSourceError fires when INTERNAL_TRUST_SOURCE fails to
	// load or validate — the previous internal anchor set is carried over
	// (fail-safe), same posture as EventRefreshFailure for territories: a
	// typo in an operator-declared file must never stall trusted-list
	// ingestion.
	EventInternalSourceError = "trust.internal_source_error"
)

// Emitter emits security events with or without a request context.
type Emitter struct {
	sec *secevents.Emitter
	log *zap.Logger
}

// New returns an Emitter delivering both paths through the go-sec-events log
// sink. The sink carries log because the refresh Tasker emits with no request
// whose logger it could borrow; log is also where a failure to emit is reported
// when there is no request to report it against.
func New(log *zap.Logger) *Emitter {
	if log == nil {
		log = zap.NewNop()
	}

	return &Emitter{sec: secevents.NewEmitter(secevents.NewLogSinkFor(log)), log: log}
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
		if err := e.sec.Emit(ctx, ev); err != nil {
			e.log.Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
		}

		return
	}

	// The refresh Tasker has no request. Same tagging, sanitizing, stamping and
	// rendered shape; only the correlation ids are absent, because there is no
	// request to take them from.
	if err := e.sec.EmitBackground(context.Background(), ev); err != nil {
		e.log.Error("security event emission failed", zap.String("event_type", eventType), zap.Error(err))
	}
}

// AnchorChange emits one trust.anchor_change event for a diff entry.
// Additions and removals are warnings, metadata changes info.
//
// A trust anchor appearing or disappearing is noteworthy and worth a human
// looking — but it is a successful, expected outcome of a refresh, not a
// failure. It used to be stamped high severity and then have its log level
// quietly capped at warn so the SIEM stream was not a wall of red, which left
// the two disagreeing: the line said warn while the severity field on it said
// high. Warning is what was meant all along, and now both say it.
func (e *Emitter) AnchorChange(ctx *azugo.Context, kind, territory, fingerprint, tspName, serviceName, status, detail string, pending bool) {
	sev := secevents.SeverityInfo
	if kind == "added" || kind == "removed" {
		sev = secevents.SeverityWarning
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

// InternalSourceError emits the fail-safe warning: INTERNAL_TRUST_SOURCE
// failed to load or validate and the previous internal anchor set is still
// being served. err.Error() only — never file contents or key material.
func (e *Emitter) InternalSourceError(ctx *azugo.Context, err error) {
	e.Emit(ctx, EventInternalSourceError, secevents.SeverityWarning, broker.OutcomeFailure, map[string]any{
		"error": err.Error(),
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

// PendingApproved records a hold-mode addition approval.
func (e *Emitter) PendingApproved(ctx *azugo.Context, fingerprint, actor, how string) {
	e.Emit(ctx, EventPendingApproved, secevents.SeverityWarning, broker.OutcomeSuccess, map[string]any{
		"fingerprint": fingerprint,
		"actor_id":    actor,
		"how":         how, // "api" | "auto-release"
	})
}
