package routes

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	trustanchor "github.com/gmb-sig/trust-anchor"
	"github.com/gmb-sig/trust-anchor/trust"
)

// internalModeEnv sets the minimal environment an AUTH_MODE=internal
// deployment needs: the trustanchor.TestApp base (SERVICE_NAME /
// ENVIRONMENT / METRICS_ENABLED) plus AUTH_MODE and, when non-empty,
// TRUST_ADMIN_KEY. Deliberately NO AUTH_ISSUER_URL / SERVICE_AUDIENCE —
// internal mode must boot with no DPoP configuration at all (the fleet-side
// delta is exactly the two AUTH_MODE / TRUST_ADMIN_KEY values), so their
// absence here is itself the regression test for gating the Auth section
// out of validation (validate:"-" + mode-conditional Auth.Validate).
func internalModeEnv(tb testing.TB, adminKey string) {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("SERVICE_NAME", "trust-anchor")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_MODE", "internal")
	if adminKey != "" {
		tb.Setenv("TRUST_ADMIN_KEY", adminKey)
	}
}

// testInternalApp boots the REAL production application in AUTH_MODE=internal
// — deliberately NOT using the trustanchor.TestApp / SetAuthMiddleware test
// seam — so these tests exercise the actual internalAuthMiddleware wired up
// by (*App).init, exactly as it runs in production. Otherwise mirrors
// testApp() in router_test.go: seeded snapshot + bootstrap, refresher
// stubbed so no test hits the network.
func testInternalApp(t *testing.T, adminKey string) (*azugo.TestApp, *trustanchor.App, *trust.Snapshot) {
	t.Helper()
	internalModeEnv(t, adminKey)

	app, err := trustanchor.New(nil, "0.0.0-test")
	qt.Assert(t, qt.IsNil(err))

	snap := testSnapshot(t)
	ctx := context.Background()
	qt.Assert(t, qt.IsNil(app.Store().SaveSnapshot(ctx, snap)))
	qt.Assert(t, qt.IsNil(app.Store().SaveBootstrap(ctx, &trust.Bootstrap{
		Version: 1, OJReference: "C/2026/1944", ActivatedAt: time.Now().UTC(), Seeded: true,
	})))
	qt.Assert(t, qt.IsNil(app.Manager().Initialize(ctx, "")))

	// Never let route tests hit the network.
	app.Manager().SetRefresher(&fakeRefresher{snap: snap})

	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	return ta, app, snap
}

// TestInternalAuthAnonymousReadAllowed asserts that read routes are open to
// every request in AUTH_MODE=internal (trust:read is granted unconditionally
// — no X-API-Key needed), through the real production middleware.
func TestInternalAuthAnonymousReadAllowed(t *testing.T) {
	ta, _, _ := testInternalApp(t, "test-admin-key")
	defer ta.Stop()
	tc := ta.TestClient()

	resp, err := tc.Get("/v1/anchors.json")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Get("/v1/snapshot")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// denialBodySansTrace decodes an error body into a schemaless map and drops
// only trace_id. Every error response carries a fresh per-request ULID
// trace_id (correlation, not content), so two separate requests can never be
// byte-equal; comparing these maps is the meaningful "no oracle" assertion —
// ANY field-level difference except trace_id (including a field present in
// one body but not the other, which a typed struct projection would silently
// ignore) fails the comparison.
func denialBodySansTrace(t testing.TB, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &m)))
	delete(m, "trace_id")
	return m
}

// TestInternalAuthAdminGate asserts the admin-key gate on an admin-scoped
// route (/v1/refresh): missing and wrong keys are both denied via the
// unmodified requireScope → 403 path with an indistinguishable response (no
// oracle — a caller cannot tell "no key" from "wrong key" apart), and the
// correct key is granted trust:admin.
func TestInternalAuthAdminGate(t *testing.T) {
	ta, _, _ := testInternalApp(t, "test-admin-key")
	defer ta.Stop()
	tc := ta.TestClient()

	// No key → 403.
	respNoKey, err := tc.Post("/v1/refresh", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(respNoKey.StatusCode(), fasthttp.StatusForbidden))
	ctNoKey := string(respNoKey.Header.ContentType())
	bodyNoKey := read(t, respNoKey)

	// Wrong key → 403, same envelope (no oracle: trace_id is the only field
	// allowed to differ — see denialBodySansTrace).
	respWrongKey, err := tc.Post("/v1/refresh", nil, tc.WithHeader("X-API-Key", "not-the-admin-key"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(respWrongKey.StatusCode(), fasthttp.StatusForbidden))
	ctWrongKey := string(respWrongKey.Header.ContentType())
	bodyWrongKey := read(t, respWrongKey)

	qt.Check(t, qt.Equals(ctNoKey, ctWrongKey))
	mNoKey := denialBodySansTrace(t, bodyNoKey)
	mWrongKey := denialBodySansTrace(t, bodyWrongKey)
	qt.Check(t, qt.IsTrue(reflect.DeepEqual(mNoKey, mWrongKey)),
		qt.Commentf("denial bodies must be identical modulo trace_id:\n no-key: %#v\n wrong-key: %#v", mNoKey, mWrongKey))

	// Correct key → 2xx (trust:admin granted; requireScope passes).
	resp, err := tc.Post("/v1/refresh", nil, tc.WithHeader("X-API-Key", "test-admin-key"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(resp.StatusCode() >= 200 && resp.StatusCode() < 300))
	fasthttp.ReleaseResponse(resp)
}

// TestInternalAuthRequiresAdminKeyAtBoot asserts the fail-closed boot
// guarantee: AUTH_MODE=internal with an empty TRUST_ADMIN_KEY must error out
// of trustanchor.New before anything is served, never silently falling back
// to "admin key not required".
func TestInternalAuthRequiresAdminKeyAtBoot(t *testing.T) {
	internalModeEnv(t, "") // TRUST_ADMIN_KEY left unset.

	_, err := trustanchor.New(nil, "0.0.0-test")
	qt.Assert(t, qt.IsNotNil(err))
	// Pin the failure REASON: the missing admin key, not some other boot
	// error (e.g. Auth-section validation, which internal mode must skip).
	qt.Assert(t, qt.StringContains(err.Error(), "TRUST_ADMIN_KEY is required"))
}

// TestDPoPModeRequiresAuthConfigAtBoot pins that the default AUTH_MODE=dpop
// still fails closed when the go-authbyte Auth section is unconfigured
// (no AUTH_ISSUER_URL / SERVICE_AUDIENCE). Gating the Auth section out of
// the automatic struct-dive (validate:"-", so internal mode can boot without
// any DPoP env) must NOT weaken dpop mode: the mode-conditional
// c.Auth.Validate call is now the only enforcement, and this test proves it
// still rejects a missing Auth config.
func TestDPoPModeRequiresAuthConfigAtBoot(t *testing.T) {
	t.Setenv("METRICS_ENABLED", "false")
	t.Setenv("SERVICE_NAME", "trust-anchor")
	t.Setenv("ENVIRONMENT", "development")
	// Explicit dpop (also the default today — pinned explicitly so this test
	// survives any future default change) and no AUTH_ISSUER_URL /
	// SERVICE_AUDIENCE — boot must fail on Auth validation.
	t.Setenv("AUTH_MODE", "dpop")

	_, err := trustanchor.New(nil, "0.0.0-test")
	qt.Assert(t, qt.IsNotNil(err))
	// Pin the failure REASON: the Auth section's own required fields.
	qt.Assert(t, qt.StringContains(err.Error(), "IssuerURL"))
}
