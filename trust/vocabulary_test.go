package trust

import (
	"testing"
	"time"
)

// The served type identifiers are published ones — the registered Svctype
// URIs of [ETSI TS 119 612 V2.4.1 §5.5.1.1] and [ETSI TS 119 612 V2.4.1 §5.5.1.2]
// for TL-plane types, the [ETSI TS 119 602 V1.1.1 §C.2.1] EU LoTE
// list identities for EUDI actor types — never an invented URI space.
func TestTypeIdentifiersArePublished(t *testing.T) {
	want := map[string]string{
		"":                 "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
		"qeaa_provider":    "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
		"eaa_provider":     "http://uri.etsi.org/TrstSvc/Svctype/EAA",
		"pid_provider":     "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
		"wallet_provider":  "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
		"access_ca":        "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList",
		"wrprc_issuer":     "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList",
		"pub_eaa_provider": "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList",
		// Status-list signer types: no identifier is registered anywhere for
		// these yet — an empty identifier is honest, a minted one is not.
		"pid_provider_status":     "",
		"qeaa_provider_status":    "",
		"pub_eaa_provider_status": "",
		"eaa_provider_status":     "",
	}
	for key, uri := range want {
		if got := TypeIdentifier(key); got != uri {
			t.Errorf("TypeIdentifier(%q) = %q, want %q", key, got, uri)
		}
	}
	// Nothing may serve the retired invented space.
	for key := range AnchorTypes {
		if got := TypeIdentifier(key); len(got) > 0 && got[:min(len(got), 41)] == "http://uri.etsi.org/TrstSvc/Svctype/EUDI/" {
			t.Errorf("TypeIdentifier(%q) still mints the retired EUDI URI space: %q", key, got)
		}
	}
	// Every taxonomy value has a row (a taxonomy addition without one is
	// visibly incomplete), and LoTE-borne types are identifiable as such.
	for key := range AnchorTypes {
		if _, ok := typeIdentifiers[key]; !ok {
			t.Errorf("taxonomy value %q has no identifier row", key)
		}
	}
	for _, lote := range []string{"pid_provider", "wallet_provider", "access_ca", "wrprc_issuer", "pub_eaa_provider"} {
		if !TypeAwaitsLoTE(lote) {
			t.Errorf("TypeAwaitsLoTE(%q) = false, want true", lote)
		}
	}
	if TypeAwaitsLoTE("qeaa_provider") || TypeAwaitsLoTE("") {
		t.Error("non-LoTE types reported as awaiting a LoTE")
	}
}

// A declaration without a type (or with the explicit tsl_ca alias) lands in
// the untyped TSL plane: no EUDI type, the CA/QC identifier, served in the
// legacy (untyped) bundle alongside trusted-list anchors.
func TestInternalUntypedDeclarationLandsInLegacyBundle(t *testing.T) {
	anchors, err := loadInternalBytes([]byte(untypedOneAnchor), "", time.Now().UTC())
	if err != nil {
		t.Fatalf("untyped declaration rejected: %v", err)
	}
	if len(anchors) != 1 {
		t.Fatalf("anchors = %d, want 1", len(anchors))
	}
	a := anchors[0]
	if a.Type != "" {
		t.Fatalf("untyped declaration got Type %q, want empty (TSL plane)", a.Type)
	}
	if a.ServiceType != "http://uri.etsi.org/TrstSvc/Svctype/CA/QC" {
		t.Fatalf("untyped declaration ServiceType = %q, want the CA/QC identifier", a.ServiceType)
	}

	// And it is served in the legacy bundle (type filter empty), exactly like
	// a TL-sourced CA/QC anchor.
	s := &Snapshot{Internal: []Anchor{a}}
	got, err := Filter(s, nil, "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("legacy bundle anchors = %d, want 1 (untyped internal must merge)", len(got))
	}
	// A typed request must NOT see it.
	got, err = Filter(s, nil, "", false, "pid_provider")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("untyped internal anchor leaked into a typed bundle")
	}
}

// The tsl_ca alias is accepted and normalizes to the untyped plane.
func TestInternalTslCaAliasNormalizes(t *testing.T) {
	anchors, err := loadInternalBytes([]byte(tslCaAliasAnchor), "", time.Now().UTC())
	if err != nil {
		t.Fatalf("tsl_ca declaration rejected: %v", err)
	}
	if len(anchors) != 1 || anchors[0].Type != "" {
		t.Fatalf("tsl_ca alias did not normalize to untyped: %+v", anchors)
	}
}

// The config layer only admits trusted-list service types with a serving
// route: CA/QC and the keyed TL-plane identifiers pass; a registered type
// with no bundle vocabulary (TSA/QTST today) and a LoTE list identity (not
// a TL Svctype) are refused rather than extracted-and-never-served.
func TestServableServiceType(t *testing.T) {
	for _, ok := range []string{
		"http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
		"http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
		"http://uri.etsi.org/TrstSvc/Svctype/EAA",
	} {
		if !ServableServiceType(ok) {
			t.Errorf("ServableServiceType(%q) = false, want true", ok)
		}
	}
	for _, no := range []string{
		"http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
		"http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
		"http://uri.etsi.org/TrstSvc/Svctype/EUDI/PidProvider",
		"",
	} {
		if ServableServiceType(no) {
			t.Errorf("ServableServiceType(%q) = true, want false", no)
		}
	}
}

// The service-status URIs are published ones too — the registered Svcstatus
// URIs of [ETSI TS 119 612 V2.4.1]. Pinned here as LITERALS on purpose:
// asserting a produced status against the very constant that produced it is
// self-referential and passes no matter what the constant says, so it cannot
// catch a mistyped or invented status URI.
func TestStatusIdentifiersArePublished(t *testing.T) {
	if got, want := statusBase, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/"; got != want {
		t.Errorf("statusBase = %q, want %q", got, want)
	}
	if got, want := grantedStatusURI, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"; got != want {
		t.Errorf("grantedStatusURI = %q, want %q", got, want)
	}
	// The default assigned to a declared anchor must be the granted URI the
	// base composes — the two constants are declared separately and could drift.
	if grantedStatusURI != statusBase+"granted" {
		t.Errorf("grantedStatusURI %q disagrees with statusBase+\"granted\" %q", grantedStatusURI, statusBase+"granted")
	}
}
