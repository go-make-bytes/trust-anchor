package trust

// This file is the single mapping between the request/type taxonomy (the
// `type=` bundle-filter vocabulary and the declaration file's `type:` keys)
// and the published identifier each type serves. There is deliberately no
// second identifier space: TL-plane types carry their registered service-type
// URI [ETSI TS 119 612 V2.4.1 §5.5.1.1] / [ETSI TS 119 612 V2.4.1 §5.5.1.2],
// and EUDI actor types carry the EU LoTE list identity registered in
// [ETSI TS 119 602 V1.1.1 §C.2.1] — in the EU LoTE profiles each list is
// single-purpose, so the list identity is the type discriminator.
const (
	loteTypeBase = "http://uri.etsi.org/19602/LoTEType/"
	svctypeBase  = "http://uri.etsi.org/TrstSvc/Svctype/"
)

// typeIdentifiers maps every taxonomy value (plus "" — the untyped TSL
// plane) to its published identifier. Status-list signer types map to "" on
// purpose: no identifier is registered anywhere for them yet, and an empty
// identifier is honest where a minted one would not be.
var typeIdentifiers = map[string]string{
	"":                 svctypeBase + "CA/QC",
	"qeaa_provider":    svctypeBase + "EAA/Q",
	"eaa_provider":     svctypeBase + "EAA",
	"pid_provider":     loteTypeBase + "EUPIDProvidersList",
	"wallet_provider":  loteTypeBase + "EUWalletProvidersList",
	"access_ca":        loteTypeBase + "EUWRPACProvidersList",
	"wrprc_issuer":     loteTypeBase + "EUWRPRCProvidersList",
	"pub_eaa_provider": loteTypeBase + "EUPubEAAProvidersList",

	"pid_provider_status":     "",
	"qeaa_provider_status":    "",
	"pub_eaa_provider_status": "",
	"eaa_provider_status":     "",
}

// TypeIdentifier returns the published identifier served for a taxonomy
// value ("" = the untyped TSL plane → CA/QC). Unknown types return "";
// callers reject unknown types before asking (ValidAnchorType).
func TypeIdentifier(key string) string { return typeIdentifiers[key] }

// identifierKeys is the reverse of typeIdentifiers for non-empty
// identifiers: it is what makes the type dimension ONE dimension — an
// anchor's taxonomy key is always derived from its identifier, never
// assigned independently, so a trusted-list-sourced EAA/Q anchor and a
// declared qeaa_provider anchor are the same kind of object.
var identifierKeys = func() map[string]string {
	out := make(map[string]string, len(typeIdentifiers))
	for k, id := range typeIdentifiers {
		if id != "" {
			out[id] = k
		}
	}
	return out
}()

// TypeKey derives the taxonomy key for a published identifier ("" for the
// CA/QC untyped plane and for identifiers with no key — those anchors stay
// on the untyped plane).
func TypeKey(identifier string) string { return identifierKeys[identifier] }

// ServableServiceType reports whether a service-type identifier extracted
// from a trusted list has a serving route — a taxonomy key (or the untyped
// plane) a bundle request can reach it through. The configuration layer
// rejects accepted types without one: extracting anchors nothing can ever
// serve would re-create the silent drop this widening exists to end.
func ServableServiceType(identifier string) bool {
	if identifier == svctypeBase+"CA/QC" {
		return true
	}
	k, ok := identifierKeys[identifier]
	return ok && k != "" && len(identifier) > len(svctypeBase) && identifier[:len(svctypeBase)] == svctypeBase
}

// TypeAwaitsLoTE reports whether the type's mandated distribution channel is
// an EU LoTE that has not been published yet — anchors of these types can
// only be operator-declared today, and the inventory marks them so the gap
// stays visible instead of silently normalized.
func TypeAwaitsLoTE(key string) bool {
	id := typeIdentifiers[key]
	return len(id) > len(loteTypeBase) && id[:len(loteTypeBase)] == loteTypeBase
}

// qualifiedSvctypes is the [ETSI TS 119 612 V2.4.1 §5.5.1.1] set — service
// types approved at EU level, whose status vocabulary is granted/withdrawn.
// Every other registered Svctype is national-level —
// [ETSI TS 119 612 V2.4.1 §5.5.1.2] and [ETSI TS 119 612 V2.4.1 §5.5.1.3] —
// and carries the national status vocabulary instead.
var qualifiedSvctypes = map[string]bool{
	svctypeBase + "CA/QC":                     true,
	svctypeBase + "Certstatus/OCSP/QC":        true,
	svctypeBase + "Certstatus/CRL/QC":         true,
	svctypeBase + "TSA/QTST":                  true,
	svctypeBase + "EDS/Q":                     true,
	svctypeBase + "EDS/REM/Q":                 true,
	svctypeBase + "PSES/Q":                    true,
	svctypeBase + "QESValidation/Q":           true,
	svctypeBase + "RemoteQSigCDManagement/Q":  true,
	svctypeBase + "RemoteQSealCDManagement/Q": true,
	svctypeBase + "EAA/Q":                     true,
	svctypeBase + "ElectronicArchiving/Q":     true,
	svctypeBase + "Ledgers/Q":                 true,
}

// nationalStatusEquivalent maps each EU-qualified status URI onto its
// national-level counterpart [ETSI TS 119 612 V2.4.1 §5.5.4]: a service of a
// national-level type never carries granted/withdrawn, so admitting such a
// type must admit the matching vocabulary or the type widening silently
// drops every one of its services one layer down.
var nationalStatusEquivalent = map[string]string{
	statusBase + "granted":   statusBase + "recognisedatnationallevel",
	statusBase + "withdrawn": statusBase + "deprecatedatnationallevel",
}
