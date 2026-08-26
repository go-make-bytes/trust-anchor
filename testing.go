package trustanchor

import (
	"testing"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
)

// TestApp builds an App for tests: in-memory snapshot store and a stub auth
// middleware driven by the X-Test-Scopes request header (production wiring
// always uses the go-authbyte DPoP middleware).
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("SERVICE_NAME", "trust-anchor")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_ISSUER_URL", "http://localhost:8080")
	tb.Setenv("SERVICE_AUDIENCE", "svc:trust-anchor")

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	app.SetAuthMiddleware(TestAuthMiddleware())
	return app
}

// TestAuthMiddleware authenticates requests from the X-Test-Scopes header
// (comma-separated scopes, e.g. "trust:read"). Requests without the header
// are rejected 401 — mirroring the production middleware contract.
func TestAuthMiddleware() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			scopes := ctx.Header.Get("X-Test-Scopes")
			if scopes == "" {
				ctx.StatusCode(401)
				ctx.Text("unauthorized")
				return
			}
			ctx.SetUser(user.New(map[string]token.ClaimStrings{
				"sub":   {"svc:test-client"},
				"scope": {scopes},
			}))
			next(ctx)
		}
	}
}
