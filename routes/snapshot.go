package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	"github.com/go-make-bytes/trust-anchor/routes/response"
)

// healthz is the liveness probe.
func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	ctx.Text("ok")
}

// readyz reports readiness: a valid snapshot is loaded (restored from the
// store or freshly ingested).
func (r *router) readyz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	if r.Manager().Active() == nil {
		ctx.StatusCode(fasthttp.StatusServiceUnavailable)
		ctx.Text("no trust snapshot loaded")
		return
	}
	ctx.Text("ready")
}

// snapshot serves the current snapshot summary, the diff vs the previous
// snapshot and the pending set.
//
// @operationId GetSnapshot
// @title Snapshot summary
// @description Current snapshot summary + diff vs previous + pending additions.
// @success 200 SnapshotResponse response.Snapshot "Snapshot summary"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource Snapshot
// @route /v1/snapshot [get].
func (r *router) snapshot(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	snap := r.snapshotForServing(ctx)
	if snap == nil {
		return
	}
	ctx.Header.Set(headerTrustSnapshot, snap.ID)
	ctx.JSON(response.NewSnapshot(snap, r.Manager().Bootstrap(), r.Now(), r.Config().StaleGrace))
}
