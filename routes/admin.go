package routes

import (
	"azugo.io/azugo"

	"github.com/go-make-bytes/trust-anchor/routes/response"
)

// approvePending approves a hold-mode addition by fingerprint.
//
// @operationId ApprovePendingAnchor
// @title Approve held anchor addition
// @description Moves a pending (hold-mode) anchor addition into the served bundle.
// @param fingerprint path string true "SHA-256 certificate fingerprint (lowercase hex)"
// @success 200 ApprovedResponse response.Approved "Approved"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 404 string string "No such pending anchor"
// @resource Governance
// @route /v1/pending/{fingerprint}/approve [post].
func (r *router) approvePending(ctx *azugo.Context) {
	if !r.requireScope(ctx, "admin") {
		return
	}
	fingerprint := ctx.Params.String("fingerprint")

	snap, err := r.Manager().ApprovePending(ctx, fingerprint, ctx.User().ID())
	if err != nil {
		ctx.Error(notFoundError{err})
		return
	}
	ctx.JSON(&response.Approved{Snapshot: snap.ID, Fingerprint: fingerprint})
}

// refresh triggers an immediate ingestion cycle and waits for its result.
//
// @operationId TriggerRefresh
// @title Trigger refresh cycle
// @description Re-reads the operator-declared sources (applied even when the upstream is unreachable), then runs an immediate LOTL/TL ingestion cycle. Answers 200 with a per-half report — the declared outcome and the cycle outcome are stated separately, and the snapshot id is always the one being served.
// @success 200 RefreshResponse response.Refresh "Refresh report (both halves; snapshot = the id being served)"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 502 string string "Nothing is served yet and the cycle failed — no snapshot exists to report"
// @resource Governance
// @route /v1/refresh [post].
func (r *router) refresh(ctx *azugo.Context) {
	if !r.requireScope(ctx, "admin") {
		return
	}
	out := r.Manager().Refresh(ctx)
	if out.Snapshot == nil {
		// Nothing has ever been served and the cycle failed: there is no
		// snapshot id an honest report could carry.
		ctx.Error(badGatewayError{out.CycleErr})
		return
	}
	ctx.JSON(response.NewRefresh(out.Snapshot, out.Changed,
		out.DeclaredChanged, out.Declared.CarriedOver, out.Declared.Error, out.CycleErr))
}

// notFoundError maps a governance lookup failure to 404 with a safe message.
type notFoundError struct{ err error }

func (e notFoundError) Error() string   { return e.err.Error() }
func (e notFoundError) StatusCode() int { return 404 }
func (e notFoundError) SafeError() string {
	return e.err.Error()
}

// badGatewayError maps an upstream ingestion failure to 502. Reached only
// when nothing has ever been served — once a snapshot exists, a refresh
// answers 200 with the per-half report instead.
type badGatewayError struct{ err error }

func (e badGatewayError) Error() string   { return e.err.Error() }
func (e badGatewayError) StatusCode() int { return 502 }
func (e badGatewayError) SafeError() string {
	return "refresh failed and no snapshot exists yet; nothing is served"
}
