// Package routes registers the trust-anchor HTTP API (task §5).
package routes

import (
	"azugo.io/azugo"
	corehttp "azugo.io/core/http"

	"github.com/gmb-sig/go-platform-kit/broker"
	"github.com/gmb-sig/go-sec-events/secevents"
	trustanchor "github.com/gmb-sig/trust-anchor"
)

type router struct {
	*trustanchor.App
}

// Init registers all routes.
func Init(a *trustanchor.App) error {
	r := &router{App: a}

	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	v1 := a.Group("/v1")
	v1.Use(a.AuthMiddleware())
	v1.Get("/anchors", r.anchorsPEM)
	v1.Get("/anchors.json", r.anchorsJSON)
	v1.Get("/snapshot", r.snapshot)
	v1.Post("/pending/{fingerprint}/approve", r.approvePending)
	v1.Post("/bootstrap/approve", r.approveBootstrap)
	v1.Post("/refresh", r.refresh)

	return nil
}

// requireScope enforces a trust:<level> scope; on denial it emits the
// platform authz.denied security event and returns false.
func (r *router) requireScope(ctx *azugo.Context, level string) bool {
	if ctx.User().HasScopeLevel("trust", level) {
		return true
	}
	r.Events().Emit(ctx, "authz.denied", secevents.SeverityWarning, broker.OutcomeDenied, map[string]any{
		"required_scope": "trust:" + level,
		"actor_id":       ctx.User().ID(),
		"path":           ctx.Path(),
	})
	ctx.Error(corehttp.ForbiddenError{})
	return false
}
