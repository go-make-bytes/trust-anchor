package ingest

import "regexp"

// ojELIRe extracts the OJ notice reference from an EUR-Lex ELI URI, e.g.
// https://eur-lex.europa.eu/eli/C/2026/1944/oj -> C/2026/1944.
var ojELIRe = regexp.MustCompile(`/eli/([A-Z]+/\d{4}/\d+)/oj`)

// advertisedOJReference finds the OJ reference advertised inside the LOTL
// SchemeInformationURI list. Empty when none is advertised. It is recorded on
// the snapshot as an observability signal only: comparing it to the pinned
// bootstrap reference tells an operator when the published signer set has moved
// on. It drives no automatic trust decision — the trusted signer set is the
// operator-pinned one.
func advertisedOJReference(uris []string) string {
	for _, u := range uris {
		if m := ojELIRe.FindStringSubmatch(u); m != nil {
			return m[1]
		}
	}
	return ""
}
