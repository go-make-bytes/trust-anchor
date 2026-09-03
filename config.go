package trustanchor

import (
	"errors"
	"fmt"
	"strings"
	"time"

	azugocfg "azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"

	"github.com/go-make-bytes/trust-anchor/trust"
)

// errTrustAdminKeyRequired is returned by Validate when AUTH_MODE=internal
// and TRUST_ADMIN_KEY is empty. Value-free by construction — the key itself
// must never appear in an error message.
var errTrustAdminKeyRequired = errors.New("trust-anchor: config: TRUST_ADMIN_KEY is required when AUTH_MODE=internal")

// errExtraAnchorsRetired refuses to boot on the retired overlay variable: a
// deployment still setting it expects anchors this service would no longer
// serve, and silently dropping trust is the one failure mode this service
// never accepts. Migration: declare the same certificates in the
// INTERNAL_TRUST_SOURCE file (entries without a type land in the untyped
// bundle exactly as the overlay did).
var errExtraAnchorsRetired = errors.New("trust-anchor: config: TRUST_EXTRA_ANCHORS_PATH is retired — declare these certificates in the INTERNAL_TRUST_SOURCE file instead (a typeless entry serves in the untyped bundle); refusing to boot rather than silently drop declared trust")

// errAuthConfigRequired is returned by Validate when AUTH_MODE=dpop and the
// auth section was never bound (defensive: Bind always allocates it).
var errAuthConfigRequired = errors.New("trust-anchor: config: auth section is required when AUTH_MODE=dpop")

// Inbound authentication modes (AuthMode).
const (
	AuthModeDPoP     = "dpop"
	AuthModeInternal = "internal"
)

// Snapshot store backends.
const (
	StoreBackendPostgres = "postgres"
	StoreBackendS3       = "s3"
	StoreBackendFS       = "fs"
	StoreBackendMemory   = "memory"
)

// Configuration is the trust-anchor service configuration.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// Auth is the go-authbyte inbound DPoP validation config
	// (AUTH_ISSUER_URL / SERVICE_AUDIENCE=svc:trust-anchor / …). Only
	// consulted (and validated) when AuthMode is "dpop": validate:"-" keeps
	// the automatic struct-dive out of this section so AUTH_MODE=internal
	// boots with no DPoP environment at all; the mode-conditional
	// c.Auth.Validate call in Validate below is the dpop-mode enforcement
	// (it runs valid.Struct on this same section, so no tag is lost).
	Auth *authclient.Configuration `mapstructure:"auth" validate:"-"`

	// AuthMode selects the /v1 inbound authentication strategy: "dpop"
	// (default) validates DPoP-bound tokens via Auth using the existing
	// go-authbyte middleware; "internal" is for co-located, network-trusted
	// deployments — every request is granted trust:read, and trust:admin is
	// granted additionally on a matching X-API-Key (see internalAuthMiddleware
	// in app.go). Routes and requireScope are identical in both modes.
	AuthMode string `mapstructure:"auth_mode" validate:"oneof=dpop internal"`

	// TrustAdminKey is the constant-time-compared X-API-Key value that grants
	// trust:admin scope in AUTH_MODE=internal. Required (non-empty) when
	// AuthMode is "internal"; ignored otherwise. Secret — must never appear
	// in logs, events, or error messages.
	TrustAdminKey string `mapstructure:"trust_admin_key"`

	// LOTLURL is the EU List of Trusted Lists location.
	LOTLURL string `mapstructure:"lotl_url" validate:"required,url"`
	// BootstrapCertsPath seeds the OJEU-published LOTL signer certificates at
	// first install: a signer manifest (lotl-signers.yaml — which carries its
	// own OJ reference), a PEM/DER file, or a directory of PEM/DER files. This
	// is the supported install path (the image bakes a default). Afterwards the
	// store is authoritative and this path is ignored.
	BootstrapCertsPath string `mapstructure:"lotl_bootstrap_certs_path"`

	// TerritoriesRaw is the comma-separated territory list: ISO 3166-1 alpha-2
	// codes and/or the group "EU" (every territory the verified LOTL points
	// to). Default "EU".
	TerritoriesRaw string `mapstructure:"trust_territories" validate:"required"`
	// AllowHTTPTerritoriesRaw is the comma-separated list of territories whose
	// trusted list may be fetched over plain http (default empty — https
	// required). Integrity comes from the XMLDSig verification against the
	// LOTL-pinned signers, never from transport; this waives only the
	// defense-in-depth https rule, per named territory. Never applies to the
	// LOTL itself.
	AllowHTTPTerritoriesRaw string `mapstructure:"trust_allow_http_territories"`
	// AcceptedStatusesRaw is the comma-separated accepted service statuses
	// (names or full URIs; default granted).
	AcceptedStatusesRaw string `mapstructure:"trust_accepted_statuses" validate:"required"`

	RefreshInterval time.Duration `mapstructure:"trust_refresh_interval" validate:"required,gt=0"`
	ActivationMode  string        `mapstructure:"trust_activation_mode" validate:"required,oneof=auto hold"`
	HoldAutoRelease time.Duration `mapstructure:"trust_hold_auto_release" validate:"gte=0"`
	StaleGrace      time.Duration `mapstructure:"trust_stale_grace" validate:"gte=0"`

	// AcceptedServiceTypesRaw is the comma-separated accepted trusted-list
	// service-type identifiers (full registered Svctype URIs, or shorthand
	// suffixes like "CA/QC" expanded against the Svctype base). Default
	// CA/QC. Every accepted type must have a serving route — a bundle filter
	// that can reach its anchors — or the boot fails: extracting anchors
	// nothing can serve would be a silent drop.
	AcceptedServiceTypesRaw string `mapstructure:"trust_service_types" validate:"required"`

	// legacyExtraAnchorsPath catches the RETIRED overlay variable
	// (TRUST_EXTRA_ANCHORS_PATH). The overlay is gone; a deployment still
	// setting it expects anchors this service would silently not serve, so
	// boot fails with a migration pointer instead (fail closed, loud).
	LegacyExtraAnchorsPath string `mapstructure:"trust_extra_anchors_path"`

	// InternalTrustSource is the operator-declared anchor file (YAML —
	// INTERNAL_TRUST_SOURCE): typed EUDI actor anchors and untyped card/QC
	// CA declarations alike. Parsed fail-closed via trust.LoadInternal and
	// merged into every snapshot; empty means no declared anchors.
	InternalTrustSource string `mapstructure:"internal_trust_source"`

	// Snapshot store (platform standard: S3 API). Backend is derived: bucket
	// set → s3, dir set → fs, neither → memory (development only).
	SnapshotBucket    string `mapstructure:"trust_snapshot_bucket"`
	SnapshotEndpoint  string `mapstructure:"trust_snapshot_endpoint" validate:"required_with=SnapshotBucket"`
	SnapshotAccessKey string `mapstructure:"trust_snapshot_access_key"`
	SnapshotSecretKey string `mapstructure:"trust_snapshot_secret_key"`
	SnapshotPrefix    string `mapstructure:"trust_snapshot_prefix"`
	SnapshotUseSSL    bool   `mapstructure:"trust_snapshot_use_ssl"`
	SnapshotDir       string `mapstructure:"trust_snapshot_dir"`

	// StoreDSN selects and configures the PostgreSQL backend — the dual-mode
	// scaled / multi-DC store (spec P1b), the `trust_anchor` schema reached via
	// SECURITY DEFINER procedures. When set it takes precedence over the
	// S3/FS/memory selection. Points at the EXECUTE-only `trust_anchor_public`
	// role; source it from Vault in production (it carries a password).
	StoreDSN string `mapstructure:"trust_store_dsn"`

	FetchTimeout time.Duration `mapstructure:"trust_fetch_timeout" validate:"required,gt=0"`
	MaxTLBytes   int64         `mapstructure:"max_tl_bytes" validate:"required,gt=0"`
}

// NewConfiguration returns the configuration skeleton for binding.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// ServerCore returns the embedded azugo configuration.
func (c *Configuration) ServerCore() *azugocfg.Configuration {
	return c.Configuration
}

// Bind registers defaults and environment bindings.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)
	c.Auth = azugocfg.Bind(c.Auth, "auth", v)

	v.SetDefault("auth_mode", AuthModeDPoP)
	_ = v.BindEnv("auth_mode", "AUTH_MODE")
	loadSecret(v, "trust_admin_key", "TRUST_ADMIN_KEY")
	_ = v.BindEnv("trust_admin_key", "TRUST_ADMIN_KEY")

	v.SetDefault("lotl_url", "https://ec.europa.eu/tools/lotl/eu-lotl.xml")
	v.SetDefault("trust_territories", "EU")
	v.SetDefault("trust_accepted_statuses", "granted")
	v.SetDefault("trust_service_types", "CA/QC")
	v.SetDefault("trust_refresh_interval", 6*time.Hour)
	v.SetDefault("trust_activation_mode", "auto")
	v.SetDefault("trust_hold_auto_release", 72*time.Hour)
	v.SetDefault("trust_stale_grace", 24*time.Hour)
	v.SetDefault("trust_fetch_timeout", 30*time.Second)
	v.SetDefault("max_tl_bytes", int64(20*1024*1024))
	v.SetDefault("trust_snapshot_use_ssl", true)

	_ = v.BindEnv("lotl_url", "LOTL_URL")
	_ = v.BindEnv("lotl_bootstrap_certs_path", "LOTL_BOOTSTRAP_CERTS_PATH")
	_ = v.BindEnv("trust_territories", "TRUST_TERRITORIES")
	_ = v.BindEnv("trust_allow_http_territories", "TRUST_ALLOW_HTTP_TERRITORIES")
	_ = v.BindEnv("trust_accepted_statuses", "TRUST_ACCEPTED_STATUSES")
	_ = v.BindEnv("trust_refresh_interval", "TRUST_REFRESH_INTERVAL")
	_ = v.BindEnv("trust_activation_mode", "TRUST_ACTIVATION_MODE")
	_ = v.BindEnv("trust_hold_auto_release", "TRUST_HOLD_AUTO_RELEASE")
	_ = v.BindEnv("trust_stale_grace", "TRUST_STALE_GRACE")
	_ = v.BindEnv("trust_service_types", "TRUST_SERVICE_TYPES")
	_ = v.BindEnv("trust_extra_anchors_path", "TRUST_EXTRA_ANCHORS_PATH")
	_ = v.BindEnv("internal_trust_source", "INTERNAL_TRUST_SOURCE")
	_ = v.BindEnv("trust_snapshot_bucket", "TRUST_SNAPSHOT_BUCKET")
	_ = v.BindEnv("trust_snapshot_endpoint", "TRUST_SNAPSHOT_ENDPOINT")
	_ = v.BindEnv("trust_snapshot_access_key", "TRUST_SNAPSHOT_ACCESS_KEY")
	_ = v.BindEnv("trust_snapshot_secret_key", "TRUST_SNAPSHOT_SECRET_KEY")
	_ = v.BindEnv("trust_snapshot_prefix", "TRUST_SNAPSHOT_PREFIX")
	_ = v.BindEnv("trust_snapshot_use_ssl", "TRUST_SNAPSHOT_USE_SSL")
	_ = v.BindEnv("trust_snapshot_dir", "TRUST_SNAPSHOT_DIR")
	loadSecret(v, "trust_store_dsn", "TRUST_STORE_DSN")
	_ = v.BindEnv("trust_store_dsn", "TRUST_STORE_DSN")
	_ = v.BindEnv("trust_fetch_timeout", "TRUST_FETCH_TIMEOUT")
	_ = v.BindEnv("max_tl_bytes", "MAX_TL_BYTES")
}

// loadSecret resolves a secret via the Vault-agent <NAME>_FILE convention (the
// referenced file's content) and registers it as a viper default, so an explicit
// plain <NAME> environment variable still overrides it. Used for the values that
// carry credentials — the store DSN (its password) and the admin key — so they
// can be delivered as mounted secret files rather than raw environment values.
func loadSecret(v *viper.Viper, key, name string) {
	if secret, err := corecfg.LoadRemoteSecret(name); err == nil && secret != "" {
		v.SetDefault(key, secret)
	}
}

// Validate validates the configuration.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := valid.Struct(c); err != nil {
		return err
	}
	if c.LegacyExtraAnchorsPath != "" {
		return errExtraAnchorsRetired
	}
	for _, st := range c.AcceptedServiceTypes() {
		if !trust.ServableServiceType(st) {
			return fmt.Errorf("trust-anchor: TRUST_SERVICE_TYPES entry %q has no serving route — anchors of that type could be extracted but never served; admit only service types the bundle vocabulary can reach", st)
		}
	}
	if c.AuthMode != AuthModeDPoP {
		if c.TrustAdminKey == "" {
			return errTrustAdminKeyRequired
		}
		return nil
	}
	// Intentionally defensive — unreachable today: Bind unconditionally
	// allocates Auth via azugocfg.Bind.
	if c.Auth == nil {
		return errAuthConfigRequired
	}
	return c.Auth.Validate(valid)
}

// Territories returns the parsed territory codes.
func (c *Configuration) Territories() []string {
	return splitTrim(c.TerritoriesRaw)
}

// AllowHTTPTerritories returns the parsed plain-http opt-in territory codes
// (default none).
func (c *Configuration) AllowHTTPTerritories() []string {
	return splitTrim(c.AllowHTTPTerritoriesRaw)
}

// AcceptedStatuses returns the parsed accepted service statuses.
func (c *Configuration) AcceptedStatuses() []string {
	return splitTrim(c.AcceptedStatusesRaw)
}

// AcceptedServiceTypes returns the parsed accepted service-type identifiers,
// shorthand suffixes expanded to full registered Svctype URIs.
func (c *Configuration) AcceptedServiceTypes() []string {
	parts := splitTrim(c.AcceptedServiceTypesRaw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if !strings.Contains(p, "://") {
			p = "http://uri.etsi.org/TrstSvc/Svctype/" + p
		}
		out = append(out, p)
	}
	return out
}

// StoreBackend derives the snapshot-store backend from configuration.
func (c *Configuration) StoreBackend() string {
	switch {
	case c.StoreDSN != "":
		return StoreBackendPostgres
	case c.SnapshotBucket != "":
		return StoreBackendS3
	case c.SnapshotDir != "":
		return StoreBackendFS
	default:
		return StoreBackendMemory
	}
}

func splitTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
