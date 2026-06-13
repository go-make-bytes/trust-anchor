package tsl

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// lotlSigners extracts the LOTL signer set advertised by a (pivot) LOTL's
// self pointer. Test-setup only: parses without verification.
func lotlSigners(t *testing.T, raw []byte) []*x509.Certificate {
	t.Helper()
	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	self, err := tl.SelfPointer()
	if err != nil {
		t.Fatalf("self pointer: %v", err)
	}
	certs, err := self.Certificates()
	if err != nil {
		t.Fatalf("self pointer certs: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("no signer certs in self pointer")
	}
	return certs
}

// TestVerifyLOTLAgainstPivotSigners is the core spike: the real LOTL must
// verify against the signer set published by the newest pivot, and the
// pivot chain must verify link by link.
func TestVerifyLOTLAgainstPivotSigners(t *testing.T) {
	lotlRaw := readFixture(t, "eu-lotl.xml")
	signers := lotlSigners(t, readFixture(t, "eu-lotl-pivot-378.xml"))

	tl, err := VerifyAndParse(lotlRaw, signers)
	if err != nil {
		t.Fatalf("LOTL verification failed: %v", err)
	}
	if got := tl.SchemeInformation.TSLType; got != TSLTypeEUListOfTheLists {
		t.Errorf("TSLType = %q", got)
	}
	if tl.SchemeInformation.TSLSequenceNumber != 388 {
		t.Errorf("sequence = %d, want 388", tl.SchemeInformation.TSLSequenceNumber)
	}
}

// TestVerifyPivotChain verifies each pivot against the signer set of the
// previous pivot (282 → 300 → 335 → 341 → 378), exercising the pivot-walk
// mechanics on real data. (Pivot 282 itself would verify against the prior
// OJ-published set, which is not recorded here.)
func TestVerifyPivotChain(t *testing.T) {
	chain := []string{"eu-lotl-pivot-282.xml", "eu-lotl-pivot-300.xml", "eu-lotl-pivot-335.xml", "eu-lotl-pivot-341.xml", "eu-lotl-pivot-378.xml"}

	signers := lotlSigners(t, readFixture(t, chain[0]))
	for _, next := range chain[1:] {
		raw := readFixture(t, next)
		// Pre-parse (unverified) for the issue time, verify the signature at
		// that time, then confirm the verified content carries the same time.
		pre, err := Parse(raw)
		if err != nil {
			t.Fatalf("pre-parse %s: %v", next, err)
		}
		verified, err := VerifyAt(raw, signers, pre.SchemeInformation.ListIssueDateTime)
		if err != nil {
			t.Fatalf("verify %s: %v", next, err)
		}
		tl, err := Parse(verified)
		if err != nil {
			t.Fatalf("parse verified %s: %v", next, err)
		}
		if !tl.SchemeInformation.ListIssueDateTime.Equal(pre.SchemeInformation.ListIssueDateTime) {
			t.Fatalf("%s: issue time mismatch between unverified and verified content", next)
		}
		self, err := tl.SelfPointer()
		if err != nil {
			t.Fatalf("%s self pointer: %v", next, err)
		}
		signers, err = self.Certificates()
		if err != nil {
			t.Fatalf("%s signer certs: %v", next, err)
		}
	}
}

// TestVerifyNationalTLs verifies the LV and EE lists against the signer
// certs carried in their LOTL pointers.
func TestVerifyNationalTLs(t *testing.T) {
	lotl, err := Parse(readFixture(t, "eu-lotl.xml"))
	if err != nil {
		t.Fatalf("parse LOTL: %v", err)
	}

	for _, tc := range []struct {
		territory, fixture string
		sequence           uint64
	}{
		{"LV", "lv-tsl.xml", 51},
		{"EE", "ee-tsl.xml", 73},
	} {
		t.Run(tc.territory, func(t *testing.T) {
			ptr, err := lotl.PointerFor(tc.territory)
			if err != nil {
				t.Fatal(err)
			}
			signers, err := ptr.Certificates()
			if err != nil {
				t.Fatal(err)
			}
			tl, err := VerifyAndParse(readFixture(t, tc.fixture), signers)
			if err != nil {
				t.Fatalf("verify %s TL: %v", tc.territory, err)
			}
			if tl.SchemeInformation.SchemeTerritory != tc.territory {
				t.Errorf("territory = %q", tl.SchemeInformation.SchemeTerritory)
			}
			if tl.SchemeInformation.TSLSequenceNumber != tc.sequence {
				t.Errorf("sequence = %d, want %d", tl.SchemeInformation.TSLSequenceNumber, tc.sequence)
			}
		})
	}
}

// TestVerifyRejectsTamperedContent flips one byte of signed content.
func TestVerifyRejectsTamperedContent(t *testing.T) {
	lotl, err := Parse(readFixture(t, "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := lotl.PointerFor("LV")
	if err != nil {
		t.Fatal(err)
	}
	signers, err := ptr.Certificates()
	if err != nil {
		t.Fatal(err)
	}

	raw := readFixture(t, "lv-tsl.xml")
	tampered := bytes.Replace(raw, []byte("<SchemeTerritory>LV</SchemeTerritory>"), []byte("<SchemeTerritory>XX</SchemeTerritory>"), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("tampering had no effect — marker not found")
	}
	if _, err := Verify(tampered, signers); err == nil {
		t.Fatal("tampered TL verified successfully — MUST fail")
	}
}

// TestVerifyRejectsUnexpectedSigner verifies that a TL signed by a cert
// outside the pinned set fails (EE list vs LV pointer certs).
func TestVerifyRejectsUnexpectedSigner(t *testing.T) {
	lotl, err := Parse(readFixture(t, "eu-lotl.xml"))
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := lotl.PointerFor("LV")
	if err != nil {
		t.Fatal(err)
	}
	lvSigners, err := ptr.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(readFixture(t, "ee-tsl.xml"), lvSigners); err == nil {
		t.Fatal("EE TL verified against LV signer certs — MUST fail")
	}
}
