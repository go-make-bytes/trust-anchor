package tsl

import "testing"

// The trusted-list vocabulary constants this package exposes are published
// identifiers — the registered service-status and AdditionalServiceInformation
// URIs of [ETSI TS 119 612 V2.4.1]. They are pinned as LITERALS so that
// mistyping one fails a test instead of silently matching nothing on a real
// list: an AdditionalServiceInformation URI that matches no service produces
// no error anywhere, it just quietly yields an empty use set.
func TestPublishedURIConstants(t *testing.T) {
	for _, c := range []struct{ name, got, want string }{
		{"StatusGranted", StatusGranted, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"},
		{"ASIForeSignatures", ASIForeSignatures, "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"},
		{"ASIForeSeals", ASIForeSeals, "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals"},
		{"ASIForWebSiteAuthentication", ASIForWebSiteAuthentication, "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}
