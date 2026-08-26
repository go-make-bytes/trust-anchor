package trust

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// internalFixture builds the path to a testdata/internal-trust-*.yaml fixture.
func internalFixture(name string) string {
	return filepath.Join("..", "testdata", name)
}

// TestLoadInternalValid covers the full-featured file: inline PEM +
// certificateFile, a lower-case territory (must be upper-cased), an omitted
// status (defaults to the granted URI), useCases carried through, and a
// validUntil declared LATER than the second entry's certificate NotAfter
// (must be capped to the certificate's own NotAfter).
func TestLoadInternalValid(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	anchors, err := LoadInternal(internalFixture("internal-trust-valid.yaml"), now)
	if err != nil {
		t.Fatalf("LoadInternal: %v", err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2", len(anchors))
	}

	// Sorted by fingerprint.
	if anchors[0].FingerprintSHA256 >= anchors[1].FingerprintSHA256 {
		t.Errorf("anchors not sorted by fingerprint: %s, %s", anchors[0].FingerprintSHA256, anchors[1].FingerprintSHA256)
	}

	byName := map[string]Anchor{}
	for _, a := range anchors {
		byName[a.TSPName] = a
	}

	one, ok := byName["Internal Test CA One"]
	if !ok {
		t.Fatal("missing 'Internal Test CA One' anchor")
	}
	if one.Source != SourceInternal {
		t.Errorf("Source = %q, want %q", one.Source, SourceInternal)
	}
	if one.Type != "pid_provider" {
		t.Errorf("Type = %q, want pid_provider", one.Type)
	}
	if one.Territory != "LV" {
		t.Errorf("Territory = %q, want upper-cased LV", one.Territory)
	}
	if one.Status != grantedStatusURI {
		t.Errorf("Status = %q, want default granted URI %q", one.Status, grantedStatusURI)
	}
	if one.ServiceType != TypeIdentifier("pid_provider") || one.ServiceType == "" {
		t.Errorf("ServiceType = %q", one.ServiceType)
	}
	if len(one.UseCases) != 1 || one.UseCases[0] != "pid-issuance" {
		t.Errorf("UseCases = %v, want [pid-issuance]", one.UseCases)
	}
	if one.NotAfter.Year() != 2035 {
		t.Errorf("NotAfter = %v, want the certificate's own NotAfter (2035, no validUntil declared)", one.NotAfter)
	}
	if one.CertDER == nil || one.FingerprintSHA256 == "" {
		t.Error("missing certificate material")
	}

	two, ok := byName["Internal Test CA Two"]
	if !ok {
		t.Fatal("missing 'Internal Test CA Two' anchor")
	}
	if two.Territory != "EU" {
		t.Errorf("Territory = %q, want EU", two.Territory)
	}
	wantCap := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	if !two.NotAfter.Equal(wantCap) {
		t.Errorf("NotAfter = %v, want capped to the certificate's NotAfter %v (validUntil 2032 was declared LATER)", two.NotAfter, wantCap)
	}
	if len(two.UseCases) != 2 {
		t.Errorf("UseCases = %v, want 2 entries", two.UseCases)
	}
}

// TestLoadInternalUnsetPath: an unconfigured INTERNAL_TRUST_SOURCE is not an
// error — the source is optional.
func TestLoadInternalUnsetPath(t *testing.T) {
	anchors, err := LoadInternal("", time.Now())
	if err != nil {
		t.Fatalf("LoadInternal(\"\"): %v", err)
	}
	if anchors != nil {
		t.Errorf("anchors = %v, want nil", anchors)
	}
}

// assertLoadInternalFails loads a known-bad fixture and checks fail-closed
// behavior: an error is returned, no anchors, and the error names the
// offending entry (never file contents).
func assertLoadInternalFails(t *testing.T, fixture, wantNameSubstr string) {
	t.Helper()
	anchors, err := LoadInternal(internalFixture(fixture), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatalf("LoadInternal(%s): got nil error, want failure", fixture)
	}
	if len(anchors) != 0 {
		t.Errorf("LoadInternal(%s): got %d anchors on failure, want 0 (whole file rejected)", fixture, len(anchors))
	}
	if !strings.Contains(err.Error(), wantNameSubstr) {
		t.Errorf("error %q does not name the failing entry %q", err.Error(), wantNameSubstr)
	}
}

func TestLoadInternalUnknownType(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-unknown-type.yaml", "Unknown Type Anchor")
}

func TestLoadInternalBadPEM(t *testing.T) {
	fixture := "internal-trust-bad-pem.yaml"
	assertLoadInternalFails(t, fixture, "Bad Pem Anchor")

	// Never embed the raw (bogus) certificate content in the error.
	_, err := LoadInternal(internalFixture(fixture), time.Now())
	if strings.Contains(err.Error(), "this is not a certificate") {
		t.Error("error embeds the raw certificate field content")
	}
}

func TestLoadInternalExpiredCert(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-expired.yaml", "Expired Anchor")
}

func TestLoadInternalMissingCertSource(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-missing-cert-source.yaml", "No Cert Anchor")
}

func TestLoadInternalBothCertSources(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-both-cert-sources.yaml", "Both Sources Anchor")
}

func TestLoadInternalBadTerritory(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-bad-territory.yaml", "Bad Territory Anchor")
}

func TestLoadInternalMissingFile(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-missing-file.yaml", "Missing File Anchor")
}

// TestLoadInternalMultipleCertsInEntry: exactly ONE certificate is required
// per entry, even when a PEM blob with two CERTIFICATE blocks would each
// parse fine individually.
func TestLoadInternalMultipleCertsInEntry(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-multi-cert.yaml", "Multi Cert Anchor")
}

// TestLoadInternalDuplicateFingerprint: two entries declaring the same
// certificate is an operator mistake — rejected, not silently deduped.
func TestLoadInternalDuplicateFingerprint(t *testing.T) {
	assertLoadInternalFails(t, "internal-trust-duplicate.yaml", "Dup Two")
}

// TestLoadInternalMalformedYAMLNoContentLeak: a top-level YAML type-mismatch
// error must never echo the raw offending file content — yaml.v3 embeds the
// scalar text in its own error message, and that error flows into the
// trust.internal_source_error security event. The fix returns a static
// error message instead of wrapping the yaml library error.
func TestLoadInternalMalformedYAMLNoContentLeak(t *testing.T) {
	const sentinel = "SENTINEL-DO-NOT-LEAK-9f3a"
	bad := []byte("anchors: [{name: A, validUntil: " + sentinel + "}]")

	_, err := loadInternalBytes(bad, ".", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("loadInternalBytes: got nil error, want failure on malformed validUntil")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("error %q leaks the raw file content (sentinel %q)", err.Error(), sentinel)
	}
}

// TestLoadInternalMalformedYAMLUseCasesNoContentLeak covers the other
// type-mismatch shape called out in the fix: useCases declared as a scalar
// instead of a list.
func TestLoadInternalMalformedYAMLUseCasesNoContentLeak(t *testing.T) {
	const sentinel = "SENTINEL-DO-NOT-LEAK-USECASES"
	bad := []byte("anchors: [{name: A, useCases: " + sentinel + "}]")

	_, err := loadInternalBytes(bad, ".", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("loadInternalBytes: got nil error, want failure on malformed useCases")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("error %q leaks the raw file content (sentinel %q)", err.Error(), sentinel)
	}
}

// TestLoadInternalEmptySource pins that "no anchors declared" is valid, not
// an error: both a wholly empty file and an explicit empty anchors list must
// load successfully with zero anchors.
func TestLoadInternalEmptySource(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty file", []byte("")},
		{"empty object", []byte("{}")},
		{"explicit empty anchors list", []byte("anchors: []")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchors, err := loadInternalBytes(tc.raw, ".", now)
			if err != nil {
				t.Fatalf("loadInternalBytes(%q): %v", tc.raw, err)
			}
			if len(anchors) != 0 {
				t.Errorf("loadInternalBytes(%q): got %d anchors, want 0", tc.raw, len(anchors))
			}
		})
	}
}
