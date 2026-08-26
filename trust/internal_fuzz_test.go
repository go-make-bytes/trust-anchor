package trust

import (
	"os"
	"testing"
	"time"
)

// FuzzLoadInternal feeds arbitrary bytes to the byte-level parser
// (loadInternalBytes) directly, without a filesystem round-trip. It must
// never panic — INTERNAL_TRUST_SOURCE is untrusted-input territory: an
// operator's YAML edit is a config file, but the parser must still fail
// closed (return an error) rather than crash on malformed content.
func FuzzLoadInternal(f *testing.F) {
	valid, err := os.ReadFile(internalFixture("internal-trust-valid.yaml"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("{}"))
	f.Add([]byte(""))
	f.Add([]byte("anchors:\n  - name: x\n    type: pid_pro"))       // truncated
	f.Add([]byte("anchors: [1, 2, 3]"))                             // wrong shape
	f.Add([]byte("anchors:\n  - &a\n    name: *a\n    type: *a\n")) // self-referential alias

	baseDir := internalFixture("")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = loadInternalBytes(data, baseDir, now)
	})
}
