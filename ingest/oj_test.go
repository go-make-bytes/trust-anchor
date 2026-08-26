package ingest

import "testing"

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
