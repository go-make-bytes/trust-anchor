package routes

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	trustanchor "github.com/gmb-sig/trust-anchor"
	"github.com/gmb-sig/trust-anchor/routes/response"
	"github.com/gmb-sig/trust-anchor/trust"
)

// conformanceSnapshot mixes legacy (untyped) CA/QC anchors, a TL-sourced
// typed anchor, and Internal (operator-declared) typed anchors, proving the
// type= exclusion rule (proposal §3.3) works across every merge source
// (territory, overlay, internal):
//   - lv-legacy-ca / ee-legacy-ca: ordinary untyped CA/QC anchors (Type "").
//   - ee-pid-tl: a TYPED anchor placed directly in a Territory — proves the
//     type gate composes with the pre-existing structural territory filter
//     (territories only ever constrain the s.Territories loop; TLSequence is
//     set so the field-name conformance check has a TL-sourced anchor with
//     tlSequence on the wire).
//   - pid-internal / eaa-internal: operator-declared Internal anchors
//     (INTERNAL_TRUST_SOURCE) — merge in unconstrained by territory, exactly
//     like Overlay always has.
func conformanceSnapshot(t *testing.T) *trust.Snapshot {
	t.Helper()

	lvCA := testAnchor(t, "LV", "lv-legacy-ca", []string{trust.UseSignature}, true)
	eeCA := testAnchor(t, "EE", "ee-legacy-ca", []string{trust.UseSignature}, false)

	eePidTL := testAnchor(t, "EE", "ee-pid-tl", nil, false)
	eePidTL.Type = "pid_provider"
	eePidTL.TLSequence = 7

	pidInternal := testAnchor(t, "LV", "pid-internal", nil, false)
	pidInternal.Source = trust.SourceInternal
	pidInternal.Type = "pid_provider"
	// testAnchor (router_test.go) doesn't populate NotBefore/NotAfter (it
	// only cares about Fingerprint/Uses/QSCD elsewhere) — set them here so
	// this anchor exercises the full field set the brief pins (notAfter
	// non-zero).
	pidInternal.NotBefore = time.Now().Add(-time.Hour)
	pidInternal.NotAfter = time.Now().Add(24 * time.Hour)

	eaaInternal := testAnchor(t, "LV", "eaa-internal", nil, false)
	eaaInternal.Source = trust.SourceInternal
	eaaInternal.Type = "eaa_provider"
	eaaInternal.UseCases = []string{"mdl"}

	snap := &trust.Snapshot{
		GeneratedAt:  time.Now().UTC(),
		LOTLSequence: 1,
		Territories: []*trust.Territory{
			{Code: "LV", TLSequence: 1, Anchors: []trust.Anchor{lvCA}},
			{Code: "EE", TLSequence: 1, Anchors: []trust.Anchor{eeCA, eePidTL}},
		},
		Internal: []trust.Anchor{pidInternal, eaaInternal},
	}
	snap.ComputeID()
	return snap
}

// conformanceApp seeds and starts a TestApp around conformanceSnapshot,
// mirroring testApp()'s construction (router_test.go).
func conformanceApp(t *testing.T) *azugo.TestApp {
	t.Helper()
	app := trustanchor.TestApp(t)

	snap := conformanceSnapshot(t)
	ctx := context.Background()
	qt.Assert(t, qt.IsNil(app.Store().SaveSnapshot(ctx, snap)))
	qt.Assert(t, qt.IsNil(app.Store().SaveBootstrap(ctx, &trust.Bootstrap{
		Version: 1, OJReference: "C/2026/1944", ActivatedAt: time.Now().UTC(), Seeded: true,
	})))
	qt.Assert(t, qt.IsNil(app.Manager().Initialize(ctx, "", "")))

	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	return ta
}

// TestAnchorsTypeFilter is the conformance test for the type= bundle filter
// (T3, proposal §3.3): the exclusion rule — anchorType == "" serves ONLY
// untyped (legacy CA/QC) anchors; anchorType != "" serves ONLY anchors of
// exactly that type, from any merge source, still territory-filtered where
// that structurally applies (Territory-sourced anchors); use/qscdOnly
// filters still apply; unknown type is rejected (422).
func TestAnchorsTypeFilter(t *testing.T) {
	ta := conformanceApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	getRaw := func(query map[string]any) *fasthttp.Response {
		t.Helper()
		resp, err := tc.Get("/v1/anchors.json",
			tc.WithHeader("X-Test-Scopes", "trust:read"),
			tc.WithQuery(query))
		qt.Assert(t, qt.IsNil(err))
		return resp
	}
	get := func(query map[string]any) *response.Anchors {
		t.Helper()
		resp := getRaw(query)
		qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
		var out response.Anchors
		qt.Assert(t, qt.IsNil(json.Unmarshal(read(t, resp), &out)))
		return &out
	}

	// type=pid_provider&territory=LV: envelope + exactly the internal pid
	// anchor (the TL-sourced ee-pid-tl is territory-scoped to EE).
	pid := get(map[string]any{"type": "pid_provider", "territory": "LV"})
	qt.Check(t, qt.Not(qt.Equals(pid.Snapshot, "")))
	qt.Check(t, qt.IsFalse(pid.GeneratedAt.IsZero()))
	qt.Assert(t, qt.Equals(len(pid.Anchors), 1))

	a := pid.Anchors[0]
	qt.Check(t, qt.Equals(a.Type, "pid_provider"))
	qt.Check(t, qt.Not(qt.HasLen(a.CertDER, 0)))
	parsed, err := x509.ParseCertificate(a.CertDER)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("certDer must be parseable base64 DER"))
	qt.Check(t, qt.Equals(a.FingerprintSHA256, trust.Fingerprint(parsed)))
	qt.Check(t, qt.Not(qt.Equals(a.Status, "")))
	qt.Check(t, qt.IsFalse(a.NotAfter.IsZero()))

	// type= combined with territory=: EE also carries a TL-sourced
	// pid_provider anchor, so territory=EE returns it PLUS the Internal one
	// (Internal merges into every bundle regardless of territory, same as
	// Overlay); territory=LV excludes the EE-scoped TL anchor.
	pidEE := get(map[string]any{"type": "pid_provider", "territory": "EE"})
	qt.Check(t, qt.Equals(len(pidEE.Anchors), 2))

	// The eaa query surfaces UseCases.
	eaa := get(map[string]any{"type": "eaa_provider"})
	qt.Assert(t, qt.Equals(len(eaa.Anchors), 1))
	qt.Check(t, qt.DeepEquals(eaa.Anchors[0].UseCases, []string{"mdl"}))

	// Invalid type -> 422.
	resp := getRaw(map[string]any{"type": "bogus"})
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)

	// Untyped query EXCLUDES both typed anchors (from any source): only the
	// two legacy CA/QC anchors come back.
	untyped := get(nil)
	qt.Check(t, qt.Equals(len(untyped.Anchors), 2))
	for _, anc := range untyped.Anchors {
		qt.Check(t, qt.Equals(anc.Type, ""))
	}

	// Typed query EXCLUDES legacy CA/QC anchors.
	for _, anc := range pid.Anchors {
		qt.Check(t, qt.Not(qt.Equals(anc.ServiceName, "lv-legacy-ca")))
		qt.Check(t, qt.Not(qt.Equals(anc.ServiceName, "ee-legacy-ca")))
	}
}

// TestConsumerFieldNameConformance pins the consumer's recorded contract
// (testdata/consumer/anchors-pid-lv-v1.json, copied from go-eudi-trust's
// testdata/trust/) against our own serialized trust.Anchor JSON: every field
// NAME present in the fixture's anchor objects must exist on a served
// TL-sourced anchor here — this is what pins tlSequence's presence (an
// omitempty field) among the rest.
func TestConsumerFieldNameConformance(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "consumer", "anchors-pid-lv-v1.json"))
	qt.Assert(t, qt.IsNil(err))
	var fixture struct {
		Anchors []map[string]json.RawMessage `json:"anchors"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &fixture)))
	qt.Assert(t, qt.Not(qt.HasLen(fixture.Anchors, 0)))

	ta := conformanceApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	resp, err := tc.Get("/v1/anchors.json",
		tc.WithHeader("X-Test-Scopes", "trust:read"),
		tc.WithQuery(map[string]any{"type": "pid_provider", "territory": "EE"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out struct {
		Anchors []map[string]json.RawMessage `json:"anchors"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(read(t, resp), &out)))

	// Pick the TL-sourced anchor: the one carrying tlSequence on the wire.
	var served map[string]json.RawMessage
	for _, anc := range out.Anchors {
		if _, ok := anc["tlSequence"]; ok {
			served = anc
			break
		}
	}
	qt.Assert(t, qt.IsNotNil(served), qt.Commentf("expected a TL-sourced anchor (tlSequence present) in the type=pid_provider&territory=EE response"))

	for _, fixtureAnchor := range fixture.Anchors {
		for field := range fixtureAnchor {
			_, ok := served[field]
			qt.Check(t, qt.IsTrue(ok), qt.Commentf("consumer contract field %q (testdata/consumer/anchors-pid-lv-v1.json) missing from served anchor JSON", field))
		}
	}
}
