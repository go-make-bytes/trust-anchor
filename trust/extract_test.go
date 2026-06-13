package trust

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmb-sig/trust-anchor/tsl"
)

func parseFixture(t *testing.T, name string) *tsl.TrustedList {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	tl, err := tsl.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

// Expected unique granted CA/QC certificates in the recorded fixtures
// (independently computed from the XML).
const (
	expectedLVAnchors = 5
	expectedEEAnchors = 11
)

func TestExtractAnchorsLV(t *testing.T) {
	tl := parseFixture(t, "lv-tsl.xml")
	anchors, _, err := ExtractAnchors(tl, "LV", []string{"granted"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != expectedLVAnchors {
		t.Fatalf("got %d anchors, want %d", len(anchors), expectedLVAnchors)
	}

	fps := map[string]bool{}
	for _, a := range anchors {
		fps[a.FingerprintSHA256] = true
		if a.Territory != "LV" || a.Source != SourceTL {
			t.Errorf("anchor %s: territory=%q source=%q", a.FingerprintSHA256, a.Territory, a.Source)
		}
		if a.Status != "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" {
			t.Errorf("anchor %s: status %q", a.FingerprintSHA256, a.Status)
		}
		if a.Subject == "" || len(a.CertDER) == 0 {
			t.Errorf("anchor %s: missing certificate detail", a.FingerprintSHA256)
		}
	}
	// Independently computed from the recorded fixture.
	for _, want := range []string{
		"a14385c34d57b964850541e52292b9d7b81b130ad6723b207f7fbbc4e76352cc",
		"c77d1608332a8440dce2d561acde123b8c5c14aaf2c2bbb87c0dada644869e25",
		"292efebd081f3c5de8d263b72096aa385ff65efa4d3b0fb0a1f821b54679a431",
		"adecfba900af836536a21d4f30fba95628ae18bf2c139cd9a59af131e4497cf9",
		"b3cd228247f1afaac539d80b4a610e03cf90f0dc845d89ade62ec4a7eac00bae",
	} {
		if !fps[want] {
			t.Errorf("expected fingerprint %s missing", want)
		}
	}

	// Use mapping: every granted LV CA/QC service carries ForeSignatures.
	var sigUse int
	for _, a := range anchors {
		for _, u := range a.Uses {
			if u == UseSignature {
				sigUse++
			}
		}
	}
	if sigUse != len(anchors) {
		t.Errorf("ForeSignatures-derived use on %d of %d anchors", sigUse, len(anchors))
	}
	// The recorded granted LV services carry no QCWithQSCD qualification
	// (only historical entries do) — see TestQualificationMappingQSCD.
	for _, a := range anchors {
		if a.QCWithQSCD {
			t.Errorf("unexpected QCWithQSCD on granted anchor %s", a.FingerprintSHA256)
		}
	}
}

// TestQualificationMappingQSCD exercises the QCWithQSCD mapping using the
// historical (withdrawn) LV services, which carry the qualifier in the
// recorded fixture.
func TestQualificationMappingQSCD(t *testing.T) {
	tl := parseFixture(t, "lv-tsl.xml")
	anchors, _, err := ExtractAnchors(tl, "LV", []string{"granted", "withdrawn"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var qscd int
	for _, a := range anchors {
		if a.QCWithQSCD {
			qscd++
			var found bool
			for _, q := range a.Qualifiers {
				if q == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD" {
					found = true
				}
			}
			if !found {
				t.Errorf("anchor %s: QCWithQSCD flag set but qualifier URI missing", a.FingerprintSHA256)
			}
		}
	}
	if qscd == 0 {
		t.Error("no QCWithQSCD-qualified anchors found in granted+withdrawn LV extraction")
	}
}

func TestExtractAnchorsEE(t *testing.T) {
	tl := parseFixture(t, "ee-tsl.xml")
	anchors, _, err := ExtractAnchors(tl, "EE", []string{"granted"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != expectedEEAnchors {
		t.Fatalf("got %d anchors, want %d", len(anchors), expectedEEAnchors)
	}
}

func TestExtractAnchorsStatusFilter(t *testing.T) {
	tl := parseFixture(t, "lv-tsl.xml")
	// Accepting an unused status returns nothing.
	anchors, _, err := ExtractAnchors(tl, "LV", []string{"accredited"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 0 {
		t.Fatalf("got %d anchors for accredited-only filter, want 0", len(anchors))
	}

	// Accepting withdrawn as well yields more than granted alone.
	more, _, err := ExtractAnchors(tl, "LV", []string{"granted", "withdrawn"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(more) <= expectedLVAnchors {
		t.Fatalf("granted+withdrawn returned %d anchors, want more than %d", len(more), expectedLVAnchors)
	}
}

func TestNormalizeStatus(t *testing.T) {
	if got := NormalizeStatus("granted"); got != "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" {
		t.Errorf("NormalizeStatus(granted) = %q", got)
	}
	full := "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
	if got := NormalizeStatus(full); got != full {
		t.Errorf("NormalizeStatus(full URI) = %q", got)
	}
}
