package trustanchor

import (
	"path/filepath"
	"strings"
	"testing"
)

// A secret file that is named but missing must stop the start. Left alone, the
// empty address would silently select a weaker snapshot store.
func TestAMissingDatabaseAddressFileStopsTheStart(t *testing.T) {
	t.Setenv("TRUST_STORE_DSN_FILE", filepath.Join(t.TempDir(), "absent"))

	err := boundForFileSecrets(t).Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "TRUST_STORE_DSN_FILE") {
		t.Fatalf("Validate = %v, want an error naming TRUST_STORE_DSN_FILE", err)
	}
}
