package trust

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-make-bytes/trust-anchor/tsl"
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
	anchors, _, err := ExtractAnchors(tl, "LV", []string{"granted"}, nil, time.Now())
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
	anchors, _, err := ExtractAnchors(tl, "LV", []string{"granted", "withdrawn"}, nil, time.Now())
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
	anchors, _, err := ExtractAnchors(tl, "EE", []string{"granted"}, nil, time.Now())
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
	anchors, _, err := ExtractAnchors(tl, "LV", []string{"accredited"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 0 {
		t.Fatalf("got %d anchors for accredited-only filter, want 0", len(anchors))
	}

	// Accepting withdrawn as well yields more than granted alone.
	more, _, err := ExtractAnchors(tl, "LV", []string{"granted", "withdrawn"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(more) <= expectedLVAnchors {
		t.Fatalf("granted+withdrawn returned %d anchors, want more than %d", len(more), expectedLVAnchors)
	}
}

// TestServiceQualificationsUseMapping pins the use derivation to the
// registered additionalServiceInformation URIs
// [ETSI TS 119 612 V2.4.1 §5.5.9.4]. The URIs are spelled out as literals on
// purpose: the wire values come from the standard, so a drifted constant
// fails here instead of silently matching nothing on a real trusted list.
func TestServiceQualificationsUseMapping(t *testing.T) {
	exts := []tsl.Extension{
		{AdditionalServiceInformation: &tsl.ASI{URI: "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"}},
		{AdditionalServiceInformation: &tsl.ASI{URI: "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals"}},
		{AdditionalServiceInformation: &tsl.ASI{URI: "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"}},
	}
	_, uses, _ := serviceQualifications(exts)
	want := []string{UseSignature, UseSeal, UseWebsite}
	if len(uses) != len(want) {
		t.Fatalf("uses = %v, want %v", uses, want)
	}
	for i := range want {
		if uses[i] != want[i] {
			t.Errorf("uses[%d] = %q, want %q", i, uses[i], want[i])
		}
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

// The extractor admits a configured service-type set, not a hard-coded
// constant: with TSA/QTST admitted alongside CA/QC, the EE fixture's granted
// timestamp services are extracted; without it they are reported as skipped
// rather than silently dropped.
func TestExtractorAdmitsConfiguredStiSet(t *testing.T) {
	tl := parseFixture(t, "ee-tsl.xml")

	both, _, err := ExtractAnchors(tl, "EE",
		[]string{"granted"},
		[]string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC", "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"},
		time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tsa := 0
	for _, a := range both {
		if a.ServiceType == "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST" {
			tsa++
			if a.Type != "" {
				t.Fatalf("TL-sourced anchor carries an EUDI type %q", a.Type)
			}
		}
	}
	if tsa == 0 {
		t.Fatal("no TSA/QTST anchors extracted with the type admitted")
	}

	// Default (CA/QC only): the same services are skipped LOUDLY — one
	// aggregated warning per unaccepted type present in the list.
	_, warnings, err := ExtractAnchors(tl, "EE",
		[]string{"granted"},
		[]string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
		time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w.Reason, "TSA/QTST") {
			found = true
		}
	}
	if !found {
		t.Fatalf("skipped TSA/QTST services not reported: %+v", warnings)
	}
}

// Status vocabularies follow the service-type plane: a national-level type
// carries recognised/deprecatedatnationallevel, never granted/withdrawn —
// admitting the type must admit the MATCHING statuses, or the widening
// re-creates the silent drop one layer down. The EE fixture's
// Certstatus/OCSP services are deprecatedatnationallevel: they surface when
// withdrawn is accepted (its national equivalent), and not on granted alone.
func TestNationalLevelStatusEquivalence(t *testing.T) {
	tl := parseFixture(t, "ee-tsl.xml")
	const ocsp = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"

	got, _, err := ExtractAnchors(tl, "EE", []string{"granted", "withdrawn"}, []string{ocsp}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range got {
		if a.ServiceType == ocsp {
			n++
			if !strings.Contains(a.Status, "deprecatedatnationallevel") {
				t.Fatalf("unexpected status %q", a.Status)
			}
		}
	}
	if n == 0 {
		t.Fatal("national-level services not admitted via the status equivalence")
	}

	got, _, err = ExtractAnchors(tl, "EE", []string{"granted"}, []string{ocsp}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range got {
		if a.ServiceType == ocsp {
			t.Fatal("deprecated national-level service admitted on granted alone")
		}
	}
}

// The QSCD flag follows the standard's determination table, not one
// qualifier: QCQSCDManagedOnBehalf (a QSCD managed on the subscriber's
// behalf — remote/cloud signing) is QSCD-positive exactly like QCWithQSCD.
// The captured EE list carries granted services with ManagedOnBehalf and
// WITHOUT QCWithQSCD (SK's remote-signing certification), so this is pinned
// against real data, not a synthetic fixture.
func TestQSCDFlagCountsManagedOnBehalf(t *testing.T) {
	tl := parseFixture(t, "ee-tsl.xml")
	anchors, _, err := ExtractAnchors(tl, "EE", []string{"granted"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var managed int
	for _, a := range anchors {
		hasManaged := false
		for _, q := range a.Qualifiers {
			if q == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf" {
				hasManaged = true
			}
		}
		if hasManaged {
			managed++
			if !a.QCWithQSCD {
				t.Errorf("anchor %s: QCQSCDManagedOnBehalf present but QSCD flag false", a.FingerprintSHA256)
			}
		}
	}
	if managed == 0 {
		t.Fatal("no ManagedOnBehalf-qualified granted anchors in the EE fixture — the fixture premise broke")
	}
}

// dupCertTL builds a synthetic trusted list with one certificate under two
// service entries — the duplication shape the standard classifies instead of
// silently collapsing.
func dupCertTL(t *testing.T, statusA, statusB, asiA, asiB string) *tsl.TrustedList {
	t.Helper()
	cert := testCert(t, "Shared CA")
	der := base64.StdEncoding.EncodeToString(cert.Raw)
	mk := func(name, status, asi string) tsl.Service {
		info := tsl.ServiceInformation{
			TypeIdentifier: tsl.ServiceTypeCAQC,
			Name:           tsl.LocalizedText{Names: []tsl.LocalizedName{{Lang: "en", Value: name}}},
			Status:         NormalizeStatus(status),
			DigitalIdentity: tsl.ServiceDigitalIdentity{DigitalIDs: []tsl.DigitalID{
				{X509Certificate: der},
			}},
		}
		if asi != "" {
			info.Extensions = []tsl.Extension{{AdditionalServiceInformation: &tsl.ASI{URI: asi}}}
		}
		return tsl.Service{Information: info}
	}
	return &tsl.TrustedList{ProviderList: &tsl.ProviderList{Providers: []tsl.Provider{{
		Information: tsl.ProviderInformation{Name: tsl.LocalizedText{Names: []tsl.LocalizedName{{Lang: "en", Value: "TSP"}}}},
		Services:    []tsl.Service{mk("svc-a", statusA, asiA), mk("svc-b", statusB, asiB)},
	}}}}
}

// One certificate under two entries with AGREEING statuses merges — the
// second entry's uses/qualifiers are unioned, never silently dropped
// (previously first-entry-won and a use=seal bundle missed the CA).
func TestDuplicateCertEntriesMergeUses(t *testing.T) {
	tl := dupCertTL(t, "granted", "granted",
		"http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures",
		"http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals")
	anchors, _, err := ExtractAnchors(tl, "LV", []string{"granted"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 {
		t.Fatalf("anchors = %d, want 1 (one certificate)", len(anchors))
	}
	a := anchors[0]
	if !a.MatchesUse(UseSignature) || !a.MatchesUse(UseSeal) {
		t.Fatalf("merged anchor uses = %v, want signature AND seal", a.Uses)
	}
}

// One certificate under two entries with CONFLICTING statuses is the
// standard's duplication ERROR: the anchor is dropped (fail closed) and the
// conflict is reported — never served on the friendlier status.
func TestDuplicateCertStatusConflictFailsClosed(t *testing.T) {
	tl := dupCertTL(t, "granted", "withdrawn", "", "")
	anchors, warnings, err := ExtractAnchors(tl, "LV", []string{"granted"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 0 {
		t.Fatalf("anchors = %d, want 0 (status conflict fails closed)", len(anchors))
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w.Reason, "conflicting statuses") {
			found = true
		}
	}
	if !found {
		t.Fatalf("status conflict not reported: %+v", warnings)
	}
}

// serviceTL builds a one-provider list from ready-made services.
func serviceTL(services ...tsl.Service) *tsl.TrustedList {
	return &tsl.TrustedList{ProviderList: &tsl.ProviderList{Providers: []tsl.Provider{{
		Information: tsl.ProviderInformation{Name: tsl.LocalizedText{Names: []tsl.LocalizedName{{Lang: "en", Value: "D-Trust GmbH"}}}},
		Services:    services,
	}}}}
}

func grantedCAQC(name string, ids ...tsl.DigitalID) tsl.Service {
	return tsl.Service{Information: tsl.ServiceInformation{
		TypeIdentifier:  tsl.ServiceTypeCAQC,
		Name:            tsl.LocalizedText{Names: []tsl.LocalizedName{{Lang: "en", Value: name}}},
		Status:          NormalizeStatus("granted"),
		DigitalIdentity: tsl.ServiceDigitalIdentity{DigitalIDs: ids},
	}}
}

func skipFor(t *testing.T, warnings []ExtractionWarning, service string) ExtractionWarning {
	t.Helper()
	for _, w := range warnings {
		if w.ServiceName == service && w.Code != "" {
			return w
		}
	}
	t.Fatalf("no skip reported for %q: %+v", service, warnings)
	return ExtractionWarning{}
}

// A granted CA/QC service whose certificate carries a key the parser cannot
// interpret is skipped AS DATA: named, fingerprinted over the listed bytes,
// its key algorithm and curve read structurally, under the closed reason
// unsupported-key — while a sibling service with a parseable key is
// extracted as before. This is the German-list shape (twelve brainpool
// services among hundreds), reproduced with one synthetic certificate.
func TestExtractReportsUnsupportedKeyAsSkippedService(t *testing.T) {
	bp := brainpoolCertDER(t, "D-TRUST Qualified CA brainpool")
	good := testCert(t, "D-TRUST Qualified CA P-256")
	tl := serviceTL(
		grantedCAQC("D-Trust remote signature service (sign-me)", tsl.DigitalID{X509Certificate: base64.StdEncoding.EncodeToString(bp)}),
		grantedCAQC("D-Trust qualified CA", tsl.DigitalID{X509Certificate: base64.StdEncoding.EncodeToString(good.Raw)}),
	)

	anchors, warnings, err := ExtractAnchors(tl, "DE", []string{"granted"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 || anchors[0].FingerprintSHA256 != Fingerprint(good) {
		t.Fatalf("anchors = %+v, want exactly the parseable sibling", anchors)
	}

	w := skipFor(t, warnings, "D-Trust remote signature service (sign-me)")
	sum := sha256.Sum256(bp)
	want := ExtractionWarning{
		TSPName: "D-Trust GmbH", ServiceName: "D-Trust remote signature service (sign-me)",
		Code: SkipUnsupportedKey, FingerprintSHA256: hex.EncodeToString(sum[:]),
		KeyAlgorithm: KeyAlgorithmECDSA, Curve: "brainpoolP256r1",
	}
	if w.TSPName != want.TSPName || w.Code != want.Code || w.FingerprintSHA256 != want.FingerprintSHA256 ||
		w.KeyAlgorithm != want.KeyAlgorithm || w.Curve != want.Curve {
		t.Fatalf("skip = %+v\nwant  %+v (reason text aside)", w, want)
	}
	if !strings.Contains(w.Reason, unsupportedCurveMessage) {
		t.Fatalf("skip reason %q does not carry the parser's message", w.Reason)
	}

	skipped := Skipped(warnings)
	if len(skipped) != 1 || skipped[0].Reason != SkipUnsupportedKey || skipped[0].Curve != "brainpoolP256r1" ||
		skipped[0].FingerprintSHA256 != want.FingerprintSHA256 || skipped[0].Detail != w.Reason {
		t.Fatalf("Skipped() = %+v", skipped)
	}
}

// The other two per-service reasons: bytes that are not a certificate at all
// (fingerprinted, no key detail — nothing to read) and an identity with no
// X509Certificate element (no fingerprint — there are no bytes). Aggregate
// unaccepted-type warnings stay out of the skipped set.
func TestExtractReportsInvalidAndMissingCertificates(t *testing.T) {
	junk := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	tl := serviceTL(
		grantedCAQC("junk identity", tsl.DigitalID{X509Certificate: base64.StdEncoding.EncodeToString(junk)}),
		grantedCAQC("ski only", tsl.DigitalID{X509SKI: "AQID"}),
		tsl.Service{Information: tsl.ServiceInformation{
			TypeIdentifier: "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
			Name:           tsl.LocalizedText{Names: []tsl.LocalizedName{{Lang: "en", Value: "timestamp"}}},
			Status:         NormalizeStatus("granted"),
		}},
	)
	anchors, warnings, err := ExtractAnchors(tl, "DE", []string{"granted"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 0 {
		t.Fatalf("anchors = %+v, want none", anchors)
	}

	sum := sha256.Sum256(junk)
	j := skipFor(t, warnings, "junk identity")
	if j.Code != SkipInvalidCertificate || j.FingerprintSHA256 != hex.EncodeToString(sum[:]) || j.KeyAlgorithm != "" {
		t.Fatalf("junk skip = %+v", j)
	}
	s := skipFor(t, warnings, "ski only")
	if s.Code != SkipNoCertificate || s.FingerprintSHA256 != "" {
		t.Fatalf("ski-only skip = %+v", s)
	}
	if got := Skipped(warnings); len(got) != 2 {
		t.Fatalf("Skipped() = %+v, want the two per-service skips and not the type aggregate", got)
	}
}

// A duplicated certificate with conflicting statuses is a skipped service
// too — the anchor the list declares twice and the bundle carries never.
func TestStatusConflictIsASkippedService(t *testing.T) {
	tl := dupCertTL(t, "granted", "withdrawn", "", "")
	_, warnings, err := ExtractAnchors(tl, "LV", []string{"granted"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	skipped := Skipped(warnings)
	if len(skipped) != 1 || skipped[0].Reason != SkipStatusConflict || skipped[0].FingerprintSHA256 == "" {
		t.Fatalf("Skipped() = %+v, want one status-conflict entry with its fingerprint", skipped)
	}
}
