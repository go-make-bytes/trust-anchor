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
// @description Runs an immediate LOTL/TL ingestion cycle.
// @success 200 RefreshResponse response.Refresh "Cycle result"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 502 string string "Refresh failed — last good snapshot still served"
// @resource Governance
// @route /v1/refresh [post].
func (r *router) refresh(ctx *azugo.Context) {
	if !r.requireScope(ctx, "admin") {
		return
	}
	snap, changed, err := r.Manager().Refresh(ctx)
	if err != nil {
		ctx.Error(badGatewayError{err})
		return
	}
	ctx.JSON(&response.Refresh{Snapshot: snap.ID, Changed: changed})
}

// notFoundError maps a governance lookup failure to 404 with a safe message.
type notFoundError struct{ err error }

func (e notFoundError) Error() string   { return e.err.Error() }
func (e notFoundError) StatusCode() int { return 404 }
func (e notFoundError) SafeError() string {
	return e.err.Error()
}

// badGatewayError maps an upstream ingestion failure to 502.
type badGatewayError struct{ err error }

func (e badGatewayError) Error() string   { return e.err.Error() }
func (e badGatewayError) StatusCode() int { return 502 }
func (e badGatewayError) SafeError() string {
	return "refresh failed; last good snapshot still served"
}
