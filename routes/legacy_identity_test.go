package routes

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"

	trustanchor "github.com/go-make-bytes/trust-anchor"
	"github.com/go-make-bytes/trust-anchor/trust"
)

// THE regression guarantee (T3): GET /v1/anchors and /v1/anchors.json must
// keep serving byte-identical bodies (and the same ETag) for a snapshot with
// no typed/internal anchors, across the type= exclusion rule landing.
//
// legacyGoldenCertADER/BDER are fixed (non-random) synthetic certificates —
// reused verbatim from the go-eudi-trust consumer fixtures
// (testdata/consumer/anchors-pid-lv-v1.json) purely as valid X.509 DER
// blobs — so legacyGoldenSnapshot() is fully deterministic (no crypto/rand,
// no time.Now()) and reproduces byte-identical output on every run. That
// determinism is what makes a pre-capture/post-change comparison meaningful:
// the golden constants below (legacyGoldenETag/JSON/PEM) were captured by
// running this exact harness — TestLegacyAnchorsCapture, further down —
// against the working tree BEFORE trust.Filter (trust/filter.go) and
// routes/anchors.go were touched for the type= exclusion rule (2026-07-12,
// pre-T3 code). TestLegacyAnchorsByteIdentity re-runs the same harness
// against the current (post-change) code and asserts the bytes/ETag did not
// move a single bit.
const legacyGoldenCertADER = "MIIBzTCCAXOgAwIBAgIBATAKBggqhkjOPQQDAjBOMQswCQYDVQQGEwJMVjEgMB4GA1UEChMXV1AtMDYgc3ludGhldGljIGZpeHR1cmUxHTAbBgNVBAMTFExWIFBJRCBQcm92aWRlciBDQSAxMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowTjELMAkGA1UEBhMCTFYxIDAeBgNVBAoTF1dQLTA2IHN5bnRoZXRpYyBmaXh0dXJlMR0wGwYDVQQDExRMViBQSUQgUHJvdmlkZXIgQ0EgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDPFjuTvUA17afBartdc/wf2TPKCQPNOdG7pvY7L9vXF13wIR4wQbTWLcRjfbL67zr2cNZsPw1tSSH6CfYLxaiijQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS1J4P4uNFVsxbPO02InttW/Wb1EjAKBggqhkjOPQQDAgNIADBFAiAD1laydHzd357piS5M08LCdZopw6leo+5cIXUtX1WTCgIhAI8OGMdLvV/eJVnQRk4OHAObUlXYGJIP/4QEgdetIQEx"
const legacyGoldenCertBDER = "MIIBzDCCAXOgAwIBAgIBATAKBggqhkjOPQQDAjBOMQswCQYDVQQGEwJMVjEgMB4GA1UEChMXV1AtMDYgc3ludGhldGljIGZpeHR1cmUxHTAbBgNVBAMTFExWIFBJRCBQcm92aWRlciBDQSAyMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowTjELMAkGA1UEBhMCTFYxIDAeBgNVBAoTF1dQLTA2IHN5bnRoZXRpYyBmaXh0dXJlMR0wGwYDVQQDExRMViBQSUQgUHJvdmlkZXIgQ0EgMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABALAXXU1Pdg9VOvoOFJWAhAlDF2VxVyljllJ97uiqeIIq44+BT/hx89ZLoFD0UutbK5qOOkw9SKesiZXCtsK8RqjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRcRHkFENhorVq0syretzla6R7otjAKBggqhkjOPQQDAgNHADBEAiB136NR9bYbq+OQ5rPEM+cVyijuKLRI3P2SvrCpYXyrewIgeV/o67v3QKCOm4IG4CgIeIeU/z2UJeERtOgkbi4h/6s="

// legacyGoldenETag/JSON/PEM: captured 2026-07-12 from TestLegacyAnchorsCapture
// run against the pre-T3 trust/filter.go and routes/anchors.go (before the
// anchorType parameter / type= exclusion rule existed). See that test's
// output convention: t.Logf("ETAG=..."), t.Logf("JSON_B64=..."), t.Logf("PEM_B64=...").
// legacyGoldenCapturedAt is the serving clock the golden bodies below were
// captured under. It is not decorative: `stale` is computed when a bundle is
// served, so without pinning it this comparison is a function of the calendar.
var legacyGoldenCapturedAt = time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)

const legacyGoldenETag = `"8bbb0e8fdd7973e2b09b30c2cd21516fac3babc3bf1ea194a56c40a837eed0c5"`

const legacyGoldenJSONB64 = "eyJzbmFwc2hvdCI6IjhiYmIwZThmZGQ3OTczZTJiMDliMzBjMmNkMjE1MTZmYWMzYmFiYzNiZjFlYTE5NGE1NmM0MGE4MzdlZWQwYzUiLCJnZW5lcmF0ZWRBdCI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwic3RhbGUiOmZhbHNlLCJhbmNob3JzIjpbeyJ0ZXJyaXRvcnkiOiJFRSIsInNvdXJjZSI6InRsIiwidHNwTmFtZSI6IlRTUCBFRSIsInNlcnZpY2VOYW1lIjoiZWUtY2EiLCJzZXJ2aWNlVHlwZSI6IiIsInN0YXR1cyI6Imh0dHA6Ly91cmkuZXRzaS5vcmcvVHJzdFN2Yy9UcnVzdGVkTGlzdC9TdmNzdGF0dXMvZ3JhbnRlZCIsInN0YXR1c1N0YXJ0aW5nVGltZSI6IjAwMDEtMDEtMDFUMDA6MDA6MDBaIiwiY2VydERlciI6Ik1JSUJ6VENDQVhPZ0F3SUJBZ0lCQVRBS0JnZ3Foa2pPUFFRREFqQk9NUXN3Q1FZRFZRUUdFd0pNVmpFZ01CNEdBMVVFQ2hNWFYxQXRNRFlnYzNsdWRHaGxkR2xqSUdacGVIUjFjbVV4SFRBYkJnTlZCQU1URkV4V0lGQkpSQ0JRY205MmFXUmxjaUJEUVNBeE1CNFhEVEkyTURFd01UQXdNREF3TUZvWERUTTJNREV3TVRBd01EQXdNRm93VGpFTE1Ba0dBMVVFQmhNQ1RGWXhJREFlQmdOVkJBb1RGMWRRTFRBMklITjViblJvWlhScFl5Qm1hWGgwZFhKbE1SMHdHd1lEVlFRREV4Uk1WaUJRU1VRZ1VISnZkbWxrWlhJZ1EwRWdNVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRFBGanVUdlVBMTdhZkJhcnRkYy93ZjJUUEtDUVBOT2RHN3B2WTdMOXZYRjEzd0lSNHdRYlRXTGNSamZiTDY3enIyY05ac1B3MXRTU0g2Q2ZZTHhhaWlqUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJTMUo0UDR1TkZWc3hiUE8wMkludHRXL1diMUVqQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQUQxbGF5ZEh6ZDM1N3BpUzVNMDhMQ2Rab3B3Nmxlbys1Y0lYVXRYMVdUQ2dJaEFJOE9HTWRMdlYvZUpWblFSazRPSEFPYlVsWFlHSklQLzRRRWdkZXRJUUV4IiwiZmluZ2VycHJpbnRTaGEyNTYiOiJmNDVmNGEwOTRlNDU1ZWIzNzg2NzU0MmFjOGZhZTUwMjMwZTBjMTZjMzk1MjhmZDY2Y2JiYTQ1ZDg1YjE5MTAwIiwic3ViamVjdCI6IkNOPUxWIFBJRCBQcm92aWRlciBDQSAxLE89V1AtMDYgc3ludGhldGljIGZpeHR1cmUsQz1MViIsIm5vdEJlZm9yZSI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwibm90QWZ0ZXIiOiIyMDM2LTAxLTAxVDAwOjAwOjAwWiIsInFjV2l0aFFzY2QiOmZhbHNlLCJ1c2VzIjpbInNpZ25hdHVyZSJdfSx7InRlcnJpdG9yeSI6IkxWIiwic291cmNlIjoidGwiLCJ0c3BOYW1lIjoiVFNQIExWIiwic2VydmljZU5hbWUiOiJsdi1zaWciLCJzZXJ2aWNlVHlwZSI6IiIsInN0YXR1cyI6Imh0dHA6Ly91cmkuZXRzaS5vcmcvVHJzdFN2Yy9UcnVzdGVkTGlzdC9TdmNzdGF0dXMvZ3JhbnRlZCIsInN0YXR1c1N0YXJ0aW5nVGltZSI6IjAwMDEtMDEtMDFUMDA6MDA6MDBaIiwiY2VydERlciI6Ik1JSUJ6RENDQVhPZ0F3SUJBZ0lCQVRBS0JnZ3Foa2pPUFFRREFqQk9NUXN3Q1FZRFZRUUdFd0pNVmpFZ01CNEdBMVVFQ2hNWFYxQXRNRFlnYzNsdWRHaGxkR2xqSUdacGVIUjFjbVV4SFRBYkJnTlZCQU1URkV4V0lGQkpSQ0JRY205MmFXUmxjaUJEUVNBeU1CNFhEVEkyTURFd01UQXdNREF3TUZvWERUTTJNREV3TVRBd01EQXdNRm93VGpFTE1Ba0dBMVVFQmhNQ1RGWXhJREFlQmdOVkJBb1RGMWRRTFRBMklITjViblJvWlhScFl5Qm1hWGgwZFhKbE1SMHdHd1lEVlFRREV4Uk1WaUJRU1VRZ1VISnZkbWxrWlhJZ1EwRWdNakJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQUxBWFhVMVBkZzlWT3ZvT0ZKV0FoQWxERjJWeFZ5bGpsbEo5N3VpcWVJSXE0NCtCVC9oeDg5WkxvRkQwVXV0Yks1cU9Pa3c5U0tlc2laWEN0c0s4UnFqUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJSY1JIa0ZFTmhvclZxMHN5cmV0emxhNlI3b3RqQUtCZ2dxaGtqT1BRUURBZ05IQURCRUFpQjEzNk5SOWJZYnErT1E1clBFTStjVnlpanVLTFJJM1AyU3ZyQ3BZWHlyZXdJZ2VWL282N3YzUUtDT200SUc0Q2dJZUllVS96MlVKZUVSdE9na2JpNGgvNnM9IiwiZmluZ2VycHJpbnRTaGEyNTYiOiI4YjM1NWQzNzQxMmU3NjI0MGY2NWNmM2JlYjY5YWMzMGM4MjUxMjg1YTJhODgwNDI2ZDcyNDQ0YmI1N2MzNjQ0Iiwic3ViamVjdCI6IkNOPUxWIFBJRCBQcm92aWRlciBDQSAyLE89V1AtMDYgc3ludGhldGljIGZpeHR1cmUsQz1MViIsIm5vdEJlZm9yZSI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwibm90QWZ0ZXIiOiIyMDM2LTAxLTAxVDAwOjAwOjAwWiIsInFjV2l0aFFzY2QiOnRydWUsInVzZXMiOlsic2lnbmF0dXJlIl19XX0="

const legacyGoldenPEMB64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6VENDQVhPZ0F3SUJBZ0lCQVRBS0JnZ3Foa2pPUFFRREFqQk9NUXN3Q1FZRFZRUUdFd0pNVmpFZ01CNEcKQTFVRUNoTVhWMUF0TURZZ2MzbHVkR2hsZEdsaklHWnBlSFIxY21VeEhUQWJCZ05WQkFNVEZFeFdJRkJKUkNCUQpjbTkyYVdSbGNpQkRRU0F4TUI0WERUSTJNREV3TVRBd01EQXdNRm9YRFRNMk1ERXdNVEF3TURBd01Gb3dUakVMCk1Ba0dBMVVFQmhNQ1RGWXhJREFlQmdOVkJBb1RGMWRRTFRBMklITjViblJvWlhScFl5Qm1hWGgwZFhKbE1SMHcKR3dZRFZRUURFeFJNVmlCUVNVUWdVSEp2ZG1sa1pYSWdRMEVnTVRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OQpBd0VIQTBJQUJEUEZqdVR2VUExN2FmQmFydGRjL3dmMlRQS0NRUE5PZEc3cHZZN0w5dlhGMTN3SVI0d1FiVFdMCmNSamZiTDY3enIyY05ac1B3MXRTU0g2Q2ZZTHhhaWlqUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlYKSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCUzFKNFA0dU5GVnN4YlBPMDJJbnR0Vy9XYjFFakFLQmdncQpoa2pPUFFRREFnTklBREJGQWlBRDFsYXlkSHpkMzU3cGlTNU0wOExDZFpvcHc2bGVvKzVjSVhVdFgxV1RDZ0loCkFJOE9HTWRMdlYvZUpWblFSazRPSEFPYlVsWFlHSklQLzRRRWdkZXRJUUV4Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6RENDQVhPZ0F3SUJBZ0lCQVRBS0JnZ3Foa2pPUFFRREFqQk9NUXN3Q1FZRFZRUUdFd0pNVmpFZ01CNEcKQTFVRUNoTVhWMUF0TURZZ2MzbHVkR2hsZEdsaklHWnBlSFIxY21VeEhUQWJCZ05WQkFNVEZFeFdJRkJKUkNCUQpjbTkyYVdSbGNpQkRRU0F5TUI0WERUSTJNREV3TVRBd01EQXdNRm9YRFRNMk1ERXdNVEF3TURBd01Gb3dUakVMCk1Ba0dBMVVFQmhNQ1RGWXhJREFlQmdOVkJBb1RGMWRRTFRBMklITjViblJvWlhScFl5Qm1hWGgwZFhKbE1SMHcKR3dZRFZRUURFeFJNVmlCUVNVUWdVSEp2ZG1sa1pYSWdRMEVnTWpCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OQpBd0VIQTBJQUJBTEFYWFUxUGRnOVZPdm9PRkpXQWhBbERGMlZ4VnlsamxsSjk3dWlxZUlJcTQ0K0JUL2h4ODlaCkxvRkQwVXV0Yks1cU9Pa3c5U0tlc2laWEN0c0s4UnFqUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlYKSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCUmNSSGtGRU5ob3JWcTBzeXJldHpsYTZSN290akFLQmdncQpoa2pPUFFRREFnTkhBREJFQWlCMTM2TlI5YllicStPUTVyUEVNK2NWeWlqdUtMUkkzUDJTdnJDcFlYeXJld0lnCmVWL282N3YzUUtDT200SUc0Q2dJZUllVS96MlVKZUVSdE9na2JpNGgvNnM9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"

func legacyGoldenParseCert(t testing.TB, b64 string) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	qt.Assert(t, qt.IsNil(err))
	cert, err := x509.ParseCertificate(der)
	qt.Assert(t, qt.IsNil(err))
	return cert
}

func legacyGoldenDecode(t testing.TB, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	qt.Assert(t, qt.IsNil(err))
	return raw
}

// legacyGoldenSnapshot builds a fully deterministic snapshot (fixed certs,
// fixed timestamps, no random keys) with NO typed and NO internal anchors —
// the "standard test snapshot" this regression test pins. Deterministic by
// construction so the same bytes/ETag are produced whenever this function
// runs, before or after the T3 change.
func legacyGoldenSnapshot(t testing.TB) *trust.Snapshot {
	t.Helper()
	certA := legacyGoldenParseCert(t, legacyGoldenCertADER)
	certB := legacyGoldenParseCert(t, legacyGoldenCertBDER)

	generatedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	issueTime := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	nextUpdate := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	anchorEE := trust.Anchor{
		Territory: "EE", Source: trust.SourceTL,
		TSPName: "TSP EE", ServiceName: "ee-ca",
		Status:            trust.NormalizeStatus("granted"),
		CertDER:           certA.Raw,
		FingerprintSHA256: trust.Fingerprint(certA),
		Subject:           certA.Subject.String(),
		NotBefore:         certA.NotBefore,
		NotAfter:          certA.NotAfter,
		Uses:              []string{trust.UseSignature},
		QCWithQSCD:        false,
	}
	anchorLV := trust.Anchor{
		Territory: "LV", Source: trust.SourceTL,
		TSPName: "TSP LV", ServiceName: "lv-sig",
		Status:            trust.NormalizeStatus("granted"),
		CertDER:           certB.Raw,
		FingerprintSHA256: trust.Fingerprint(certB),
		Subject:           certB.Subject.String(),
		NotBefore:         certB.NotBefore,
		NotAfter:          certB.NotAfter,
		Uses:              []string{trust.UseSignature},
		QCWithQSCD:        true,
	}

	snap := &trust.Snapshot{
		GeneratedAt:  generatedAt,
		LOTLSequence: 100,
		Territories: []*trust.Territory{
			{Code: "EE", TLSequence: 10, IssueTime: issueTime, NextUpdate: &nextUpdate, Anchors: []trust.Anchor{anchorEE}},
			{Code: "LV", TLSequence: 20, IssueTime: issueTime, NextUpdate: &nextUpdate, Anchors: []trust.Anchor{anchorLV}},
		},
	}
	snap.ComputeID()
	return snap
}

// legacyGoldenApp seeds a TestApp with legacyGoldenSnapshot, mirroring
// testApp()'s construction (router_test.go) exactly, but with the
// deterministic snapshot above instead of testSnapshot's random certs.
func legacyGoldenApp(t *testing.T) *trustanchor.App {
	t.Helper()
	app := trustanchor.TestApp(t)

	// Pin the serving clock to the moment the golden bodies were captured.
	// Staleness is evaluated when a bundle is served, so `stale` is the one
	// field in the response that is not derivable from the snapshot — left on
	// the real clock, this comparison starts failing on a date rather than on
	// a change. (The snapshot's NextUpdate is 2026-08-01; with the default 24h
	// grace the flag flips on 2026-08-02.)
	app.SetClock(func() time.Time { return legacyGoldenCapturedAt })

	snap := legacyGoldenSnapshot(t)
	ctx := context.Background()
	qt.Assert(t, qt.IsNil(app.Store().SaveSnapshot(ctx, snap)))
	qt.Assert(t, qt.IsNil(app.Store().SaveBootstrap(ctx, &trust.Bootstrap{
		Version: 1, OJReference: "C/2026/1944",
		ActivatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Seeded: true,
	})))
	qt.Assert(t, qt.IsNil(app.Manager().Initialize(ctx, "")))

	return app
}

// TestLegacyAnchorsCapture is the (disabled) capture harness used to produce
// the legacyGolden* constants above. It is NOT part of the regression gate —
// re-enable manually (`t.Skip` removed) only to re-capture golden output
// against a specific tree state, then restore the skip.
func TestLegacyAnchorsCapture(t *testing.T) {
	t.Skip("capture-only harness; see legacyGolden* constants for the recorded output")

	app := legacyGoldenApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()
	tc := ta.TestClient()

	respJSON, err := tc.Get("/v1/anchors.json", tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	bodyJSON := read(t, respJSON)

	respPEM, err := tc.Get("/v1/anchors", tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	etag := string(respPEM.Header.Peek("ETag"))
	bodyPEM := read(t, respPEM)

	t.Logf("ETAG=%s", etag)
	t.Logf("JSON_B64=%s", base64.StdEncoding.EncodeToString(bodyJSON))
	t.Logf("PEM_B64=%s", base64.StdEncoding.EncodeToString(bodyPEM))
}

// TestLegacyAnchorsByteIdentity is THE regression guarantee (T3 hard rule):
// GET /v1/anchors.json and GET /v1/anchors, for a snapshot with no
// typed/internal anchors, must produce byte-identical bodies and an
// unchanged ETag across the type= exclusion rule landing in trust.Filter and
// routes/anchors.go.
func TestLegacyAnchorsByteIdentity(t *testing.T) {
	app := legacyGoldenApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()
	tc := ta.TestClient()

	respJSON, err := tc.Get("/v1/anchors.json", tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(respJSON.Header.Peek("ETag")), legacyGoldenETag))
	bodyJSON := read(t, respJSON)
	qt.Check(t, qt.DeepEquals(bodyJSON, legacyGoldenDecode(t, legacyGoldenJSONB64)),
		qt.Commentf("GET /v1/anchors.json body changed for an untyped/internal-free snapshot — the type= exclusion rule must not affect legacy responses"))

	respPEM, err := tc.Get("/v1/anchors", tc.WithHeader("X-Test-Scopes", "trust:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(respPEM.Header.Peek("ETag")), legacyGoldenETag))
	bodyPEM := read(t, respPEM)
	qt.Check(t, qt.DeepEquals(bodyPEM, legacyGoldenDecode(t, legacyGoldenPEMB64)),
		qt.Commentf("GET /v1/anchors body changed for an untyped/internal-free snapshot — the type= exclusion rule must not affect legacy responses"))
}
