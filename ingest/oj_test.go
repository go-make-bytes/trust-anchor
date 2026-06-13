package ingest

import (
	"context"
	"encoding/base64"
	"testing"
	"time"
)

func TestAdvertisedOJReference(t *testing.T) {
	uris := []string{
		"https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html",
		"https://eur-lex.europa.eu/eli/C/2026/1944/oj",
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-378.xml",
	}
	if got := advertisedOJReference(uris); got != "C/2026/1944" {
		t.Errorf("advertised OJ = %q, want C/2026/1944", got)
	}
	if got := advertisedOJReference([]string{"https://example.com"}); got != "" {
		t.Errorf("advertised OJ = %q, want empty", got)
	}
}

// syntheticOJNotice builds an HTML page resembling an OJ notice with the
// given certs embedded as base64 blocks.
func syntheticOJNotice(t *testing.T, certsDER ...[]byte) []byte {
	t.Helper()
	html := "<html><body><p>Commission notice — list of trusted list signing certificates</p>"
	for _, der := range certsDER {
		b64 := base64.StdEncoding.EncodeToString(der)
		// wrap lines like EUR-Lex does
		html += "<table><td>"
		for len(b64) > 76 {
			html += b64[:76] + "\n"
			b64 = b64[76:]
		}
		html += b64 + "</td></table>"
	}
	html += "</body></html>"
	return []byte(html)
}

func TestExtractCertificates(t *testing.T) {
	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	notice := syntheticOJNotice(t, boot.CertsDER...)

	certs := extractCertificates(notice)
	if len(certs) != len(boot.CertsDER) {
		t.Fatalf("extracted %d certs, want %d", len(certs), len(boot.CertsDER))
	}

	if got := extractCertificates([]byte("<html>no certs here</html>")); len(got) != 0 {
		t.Fatalf("extracted %d certs from empty notice", len(got))
	}
}

func TestStageBootstrapUpdate(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)

	newSet := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	active := fixtureBootstrap(t, "eu-lotl-pivot-282.xml")
	active.OJReference = "C/2019/0001"

	// The CELLAR notice for the advertised reference serves the new set.
	ft.body["https://publications.europa.eu/resource/eli/C/2026/1944/oj"] = syntheticOJNotice(t, newSet.CertsDER...)

	staged := p.stageBootstrapUpdate(context.Background(), "C/2026/1944", active, nil, time.Now().UTC())
	if staged == nil {
		t.Fatal("no bootstrap staged")
	}
	if staged.OJReference != "C/2026/1944" {
		t.Errorf("staged reference = %q", staged.OJReference)
	}
	if len(staged.Fingerprints) != len(newSet.CertsDER) {
		t.Errorf("staged %d certs, want %d", len(staged.Fingerprints), len(newSet.CertsDER))
	}
	if len(staged.Added) == 0 || len(staged.Removed) == 0 {
		t.Errorf("expected a non-trivial diff vs the active set: added=%d removed=%d", len(staged.Added), len(staged.Removed))
	}

	// Same reference as active → nothing staged.
	if got := p.stageBootstrapUpdate(context.Background(), "C/2019/0001", active, nil, time.Now().UTC()); got != nil {
		t.Fatal("staged an update for the active reference")
	}

	// Fetch failure → treated as no change, existing staging preserved.
	delete(ft.body, "https://publications.europa.eu/resource/eli/C/2026/1944/oj")
	if got := p.stageBootstrapUpdate(context.Background(), "C/2026/1944", active, staged, time.Now().UTC()); got != staged {
		t.Fatal("existing staging not preserved on re-detection")
	}
	if got := p.stageBootstrapUpdate(context.Background(), "C/2030/5555", active, nil, time.Now().UTC()); got != nil {
		t.Fatal("staged an update despite fetch failure")
	}
}

// TestRefreshStagesBootstrapWhenOJDiffers runs a full cycle with an active
// bootstrap pinned to an older OJ reference: the advertised C/2026/1944 must
// be detected, fetched (via the stubbed CELLAR) and staged — never activated.
func TestRefreshStagesBootstrapWhenOJDiffers(t *testing.T) {
	ft := newFixtureTransport()
	p := testPipeline(t, ft, ModeAuto)

	boot := fixtureBootstrap(t, "eu-lotl-pivot-378.xml")
	boot.OJReference = "C/2019/0001" // pretend the pinned set predates the current OJ notice

	ft.body["https://publications.europa.eu/resource/eli/C/2026/1944/oj"] = syntheticOJNotice(t, boot.CertsDER...)

	snap, err := p.Refresh(context.Background(), nil, boot)
	if err != nil {
		t.Fatal(err)
	}
	if snap.PendingBootstrap == nil {
		t.Fatal("no staged bootstrap update")
	}
	if snap.PendingBootstrap.OJReference != "C/2026/1944" {
		t.Errorf("staged reference = %q", snap.PendingBootstrap.OJReference)
	}
	// Staged, NOT activated: the active bootstrap reference is unchanged.
	if snap.BootstrapOJRef != "C/2019/0001" {
		t.Errorf("active bootstrap reference changed to %q without approval", snap.BootstrapOJRef)
	}
}
