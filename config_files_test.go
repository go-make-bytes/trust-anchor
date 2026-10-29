package trustanchor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// boundForFileSecrets reads the configuration from the environment the way the service does at start.
func boundForFileSecrets(t *testing.T) *Configuration {
	t.Helper()

	c := NewConfiguration()
	v := viper.New()
	c.Bind("", v)
	if err := v.Unmarshal(c); err != nil {
		t.Fatal(err)
	}

	return c
}

func secretFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// The snapshot store's credential pair may arrive as files the secret store's agent writes.
func TestTheSnapshotStoreKeysAreReadFromFiles(t *testing.T) {
	t.Setenv("TRUST_SNAPSHOT_ACCESS_KEY_FILE", secretFile(t, "AKIAEXAMPLE\n"))
	t.Setenv("TRUST_SNAPSHOT_SECRET_KEY_FILE", secretFile(t, "s3cr3t\n"))

	c := boundForFileSecrets(t)
	if c.SnapshotAccessKey != "AKIAEXAMPLE" {
		t.Fatalf("access key = %q, want the file's content", c.SnapshotAccessKey)
	}

	if c.SnapshotSecretKey != "s3cr3t" {
		t.Fatalf("secret key = %q, want the file's content", c.SnapshotSecretKey)
	}
}

// An explicit environment value still wins over the file.
func TestTheSnapshotStoreKeysFromTheEnvironmentWinOverTheFiles(t *testing.T) {
	t.Setenv("TRUST_SNAPSHOT_SECRET_KEY_FILE", secretFile(t, "from-file"))
	t.Setenv("TRUST_SNAPSHOT_SECRET_KEY", "from-env")

	if got := boundForFileSecrets(t).SnapshotSecretKey; got != "from-env" {
		t.Fatalf("secret key = %q, want the environment value", got)
	}
}
