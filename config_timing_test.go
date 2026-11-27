package trustanchor

import (
	"strings"
	"testing"
	"time"

	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// validatedWith reads the configuration from the environment the way the
// service does at start, with the given settings added, and validates it.
func validatedWith(t *testing.T, env map[string]string) (*Configuration, error) {
	t.Helper()

	t.Setenv("METRICS_ENABLED", "false")
	t.Setenv("SERVICE_NAME", "trust-anchor")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("AUTH_MODE", "internal")
	t.Setenv("TRUST_ADMIN_KEY", "test-key")
	for k, v := range env {
		t.Setenv(k, v)
	}

	c := NewConfiguration()
	v := viper.New()
	c.Bind("", v)
	if err := v.Unmarshal(c); err != nil {
		t.Fatal(err)
	}

	return c, c.Validate(validation.New())
}

func TestTheNewTimingSettingsHaveTheirDefaults(t *testing.T) {
	c, err := validatedWith(t, nil)
	if err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if c.OverdueRetryInterval != time.Hour {
		t.Errorf("TRUST_OVERDUE_RETRY_INTERVAL default = %v, want 1h", c.OverdueRetryInterval)
	}
	if c.SnapshotRetention != 2160*time.Hour {
		t.Errorf("TRUST_SNAPSHOT_RETENTION default = %v, want 2160h (90 days)", c.SnapshotRetention)
	}
}

// The wait before asking again for a late list: under one minute, zero or
// negative refuses the start and names the setting; exactly one minute starts.
func TestOverdueRetryIntervalIsValidatedAtStart(t *testing.T) {
	const setting = "TRUST_OVERDUE_RETRY_INTERVAL"
	for _, tc := range []struct {
		value   string
		refused bool
	}{
		{"0", true},
		{"0s", true},
		{"-5m", true},
		{"59s", true},
		{"1m", false},
		{"90m", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			_, err := validatedWith(t, map[string]string{setting: tc.value})
			switch {
			case tc.refused && err == nil:
				t.Fatalf("%s=%s started, want a refusal", setting, tc.value)
			case tc.refused && !strings.Contains(err.Error(), setting):
				t.Fatalf("the refusal does not name %s: %v", setting, err)
			case !tc.refused && err != nil:
				t.Fatalf("%s=%s refused: %v", setting, tc.value, err)
			}
		})
	}
}

// How long a replaced version is kept: under a day refuses the start and names
// the setting; a day starts; there is no value that switches the sweep off.
func TestSnapshotRetentionIsValidatedAtStart(t *testing.T) {
	const setting = "TRUST_SNAPSHOT_RETENTION"
	for _, tc := range []struct {
		value   string
		refused bool
	}{
		{"0", true},
		{"0s", true},
		{"-24h", true},
		{"23h", true},
		{"23h59m59s", true},
		{"24h", false},
		{"2160h", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			_, err := validatedWith(t, map[string]string{setting: tc.value})
			switch {
			case tc.refused && err == nil:
				t.Fatalf("%s=%s started, want a refusal", setting, tc.value)
			case tc.refused && !strings.Contains(err.Error(), setting):
				t.Fatalf("the refusal does not name %s: %v", setting, err)
			case !tc.refused && err != nil:
				t.Fatalf("%s=%s refused: %v", setting, tc.value, err)
			}
		})
	}
}
