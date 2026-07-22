package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	trustanchor "github.com/go-make-bytes/trust-anchor"
	"github.com/go-make-bytes/trust-anchor/routes/response"
	"github.com/go-make-bytes/trust-anchor/trust"
)

// fakeRefresher lets route tests control /v1/refresh outcomes. It returns a
// fresh clone each cycle (the manager may run it from the background refresh
// task concurrently with assertions) and stamps the active bootstrap
// reference/version onto the snapshot like the real pipeline.
type fakeRefresher struct {
	snap *trust.Snapshot
	err  error
}

func (f *fakeRefresher) Refresh(_ context.Context, prev *trust.Snapshot, boot *trust.Bootstrap) (*trust.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	b, err := json.Marshal(f.snap)
	if err != nil {
		return nil, err
	}
	var snap trust.Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, err
	}
	if boot != nil {
		snap.BootstrapOJRef = boot.OJReference
		snap.BootstrapVersion = boot.Version
	}
	if prev != nil {
		snap.PrevID = prev.ID
	}
	snap.Diff = trust.ComputeDiff(prev, &snap)
	return &snap, nil
}

func testCertDER(t testing.TB, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	qt.Assert(t, qt.IsNil(err))
	return der
}

func testAnchor(t testing.TB, territory, cn string, uses []string, qscd bool) trust.Anchor {
	t.Helper()
	der := testCertDER(t, cn)
	cert, err := x509.ParseCertificate(der)
	qt.Assert(t, qt.IsNil(err))
	return trust.Anchor{
		Territory: territory, Source: trust.SourceTL,
		TSPName: "TSP", ServiceName: cn,
		Status:            trust.NormalizeStatus("granted"),
		CertDER:           der,
		FingerprintSHA256: trust.Fingerprint(cert),
		Subject:           cert.Subject.String(),
		Uses:              uses, QCWithQSCD: qscd,
	}
}

func testSnapshot(t testing.TB) *trust.Snapshot {
	t.Helper()
	stale := time.Now().UTC().Add(30 * 24 * time.Hour)
	snap := &trust.Snapshot{
		GeneratedAt:  time.Now().UTC(),
		LOTLSequence: 388,
		Territories: []*trust.Territory{
			{Code: "EE", TLSequence: 73, NextUpdate: &stale, Anchors: []trust.Anchor{
				testAnchor(t, "EE", "ee-ca", []string{trust.UseSignature}, false),
			}},
			{Code: "LV", TLSequence: 51, NextUpdate: &stale, Anchors: []trust.Anchor{
				testAnchor(t, "LV", "lv-sig", []string{trust.UseSignature}, true),
				testAnchor(t, "LV", "lv-seal", []string{trust.UseSeal}, false),
			}},
		},
		Pending: []trust.PendingAnchor{{
			Anchor:    testAnchor(t, "LV", "lv-held", []string{trust.UseSignature}, true),
			FirstSeen: time.Now().UTC(),
		}},
	}
	snap.ComputeID()
	return snap
}

// testApp builds a started TestApp with a seeded snapshot + bootstrap.
func testApp(t *testing.T) (*azugo.TestApp, *trustanchor.App, *trust.Snapshot) {
	t.Helper()
	app := trustanchor.TestApp(t)

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

func read(t testing.TB, resp *fasthttp.Response) []byte {
	t.Helper()
	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	out := append([]byte(nil), body...)
	fasthttp.ReleaseResponse(resp)
	return out
}

func TestHealthAndReady(t *testing.T) {
	ta, _, _ := testApp(t)
	defer ta.Stop()

	resp, err := ta.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)

	resp, err = ta.TestClient().Get("/readyz")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestAnchorsRequiresAuth(t *testing.T) {
	ta, _, _ := testApp(t)
	defer ta.Stop()

	resp, err := ta.TestClient().Get("/v1/anchors")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

func TestAnchorsScopeEnforcement(t *testing.T) {
	ta, _, _ := testApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	// Wrong scope → 403.
	resp, err := tc.Get("/v1/anchors", tc.WithHeader("X-Test-Scopes", "documents:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)

	// trust:read may not call admin endpoints.
	resp, err = tc.Post("/v1/refresh", nil, tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)
}

func TestAnchorsPEMBundle(t *testing.T) {
	ta, _, snap := testApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	resp, err := tc.Get("/v1/anchors", tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	qt.Check(t, qt.Equals(string(resp.Header.ContentType()), "application/x-pem-file"))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("ETag")), `"`+snap.ID+`"`))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Trust-Snapshot")), snap.ID))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("X-Trust-Stale")), "false"))

	body := read(t, resp)
	pool := x509.NewCertPool()
	qt.Assert(t, qt.IsTrue(pool.AppendCertsFromPEM(body)), qt.Commentf("PEM bundle must parse with crypto/x509"))

	// 3 anchors served; the held one is NOT in the bundle.
	certs := 0
	for rest := body; ; {
		var block []byte
		block, rest = nextPEMBlock(rest)
		if block == nil {
			break
		}
		certs++
	}
	qt.Check(t, qt.Equals(certs, 3))
}

// nextPEMBlock counts PEM blocks without importing encoding/pem twice.
func nextPEMBlock(data []byte) (block, rest []byte) {
	const begin = "-----BEGIN CERTIFICATE-----"
	idx := indexOf(data, begin)
	if idx < 0 {
		return nil, nil
	}
	endIdx := indexOf(data[idx:], "-----END CERTIFICATE-----")
	if endIdx < 0 {
		return nil, nil
	}
	return data[idx : idx+endIdx], data[idx+endIdx+len("-----END CERTIFICATE-----"):]
}

func indexOf(data []byte, s string) int {
	for i := 0; i+len(s) <= len(data); i++ {
		if string(data[i:i+len(s)]) == s {
			return i
		}
	}
	return -1
}

func TestAnchorsETag304(t *testing.T) {
	ta, _, snap := testApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	resp, err := tc.Get("/v1/anchors",
		tc.WithHeader("X-Test-Scopes", "trust:read"),
		tc.WithHeader("If-None-Match", `"`+snap.ID+`"`))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotModified))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("ETag")), `"`+snap.ID+`"`))
	fasthttp.ReleaseResponse(resp)

	// Stale ETag → 200 with content.
	resp, err = tc.Get("/v1/anchors",
		tc.WithHeader("X-Test-Scopes", "trust:read"),
		tc.WithHeader("If-None-Match", `"old"`))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestAnchorsFilters(t *testing.T) {
	ta, _, _ := testApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	get := func(query map[string]any) *response.Anchors {
		t.Helper()
		resp, err := tc.Get("/v1/anchors.json",
			tc.WithHeader("X-Test-Scopes", "trust:read"),
			tc.WithQuery(query))
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
		var out response.Anchors
		qt.Assert(t, qt.IsNil(json.Unmarshal(read(t, resp), &out)))
		return &out
	}

	all := get(nil)
	qt.Check(t, qt.Equals(len(all.Anchors), 3))

	lv := get(map[string]any{"territory": "LV"})
	qt.Check(t, qt.Equals(len(lv.Anchors), 2))

	sig := get(map[string]any{"territory": "LV", "use": "signature"})
	qt.Check(t, qt.Equals(len(sig.Anchors), 1))
	qt.Check(t, qt.Equals(sig.Anchors[0].ServiceName, "lv-sig"))

	qscd := get(map[string]any{"qscdOnly": "true"})
	qt.Check(t, qt.Equals(len(qscd.Anchors), 1))

	// Invalid use → 422.
	resp, err := tc.Get("/v1/anchors.json",
		tc.WithHeader("X-Test-Scopes", "trust:read"),
		tc.WithQuery(map[string]any{"use": "bogus"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}

func TestSnapshotEndpoint(t *testing.T) {
	ta, _, snap := testApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	resp, err := tc.Get("/v1/snapshot", tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out response.Snapshot
	qt.Assert(t, qt.IsNil(json.Unmarshal(read(t, resp), &out)))

	qt.Check(t, qt.Equals(out.ID, snap.ID))
	qt.Check(t, qt.Equals(out.LOTLSequence, uint64(388)))
	qt.Check(t, qt.Equals(len(out.Territories), 2))
	qt.Check(t, qt.Equals(len(out.Pending), 1))
	qt.Assert(t, qt.IsNotNil(out.Bootstrap))
	qt.Check(t, qt.Equals(out.Bootstrap.OJReference, "C/2026/1944"))
}

func TestApprovePendingFlow(t *testing.T) {
	ta, app, snap := testApp(t)
	defer ta.Stop()
	tc := ta.TestClient()
	heldFP := snap.Pending[0].Anchor.FingerprintSHA256

	// Unknown fingerprint → 404.
	resp, err := tc.Post("/v1/pending/deadbeef/approve", nil, tc.WithHeader("X-Test-Scopes", "trust:admin"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Post("/v1/pending/"+heldFP+"/approve", nil, tc.WithHeader("X-Test-Scopes", "trust:admin"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)

	// The approved anchor is now served.
	active := app.Manager().Active()
	qt.Check(t, qt.Equals(len(active.Pending), 0))
	qt.Check(t, qt.Equals(len(active.Territory("LV").Anchors), 3))
	qt.Check(t, qt.Not(qt.Equals(active.ID, snap.ID)))

	resp, err = tc.Get("/v1/anchors", tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("ETag")), `"`+active.ID+`"`))
	fasthttp.ReleaseResponse(resp)
}

func TestRefreshEndpoint(t *testing.T) {
	ta, app, snap := testApp(t)
	defer ta.Stop()
	tc := ta.TestClient()

	resp, err := tc.Post("/v1/refresh", nil, tc.WithHeader("X-Test-Scopes", "trust:admin"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out response.Refresh
	qt.Assert(t, qt.IsNil(json.Unmarshal(read(t, resp), &out)))
	qt.Check(t, qt.Equals(out.Snapshot, snap.ID))

	// Upstream failure → 502, last good still served.
	app.Manager().SetRefresher(&fakeRefresher{err: errors.New("upstream down")})
	resp, err = tc.Post("/v1/refresh", nil, tc.WithHeader("X-Test-Scopes", "trust:admin"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(app.Manager().Active().ID, snap.ID))
}
