// Package trustanchor is the eSignature-Portal trust-anchor service: it
// ingests the EU LOTL and the configured national trusted lists (ETSI TS
// 119 612), verifies their XML signatures against pinned signer sets,
// extracts the qualified CA certificates and serves versioned PEM bundles to
// consuming services over an authenticated API.
package trustanchor

import (
	"fmt"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gmb-sig/go-authbyte/authclient"
	"github.com/gmb-sig/go-platform-kit/platform"

	"github.com/gmb-sig/trust-anchor/events"
	"github.com/gmb-sig/trust-anchor/ingest"
	"github.com/gmb-sig/trust-anchor/store"
	"github.com/gmb-sig/trust-anchor/tasks"
)

// App is the trust-anchor application container.
type App struct {
	*azugo.App

	config *Configuration

	events     *events.Emitter
	store      store.Store
	manager    *ingest.Manager
	authClient *authclient.Client
	authMW     azugo.RequestHandlerFunc
}

// New creates the application: configuration, platform cross-cutting setup,
// snapshot store, ingestion pipeline + manager, inbound auth and the refresh
// task.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Trust Anchor Service",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}
	return app, nil
}

func (a *App) init() error {
	cfg := a.config

	if err := platform.Setup(a.App, platform.Options{
		Config: cfg.BaseConfiguration,
	}); err != nil {
		return err
	}

	a.events = events.New(a.Log())

	var err error
	switch cfg.StoreBackend() {
	case StoreBackendPostgres:
		a.store, err = store.NewPostgres(a.BackgroundContext(), cfg.StoreDSN)
		if err != nil {
			return err
		}
	case StoreBackendS3:
		a.store, err = store.NewS3(store.S3Options{
			Endpoint:  cfg.SnapshotEndpoint,
			AccessKey: cfg.SnapshotAccessKey,
			SecretKey: cfg.SnapshotSecretKey,
			UseSSL:    cfg.SnapshotUseSSL,
			Bucket:    cfg.SnapshotBucket,
			Prefix:    cfg.SnapshotPrefix,
		})
		if err != nil {
			return err
		}
	case StoreBackendFS:
		a.store, err = store.NewFS(cfg.SnapshotDir)
		if err != nil {
			return err
		}
	default:
		a.Log().Warn("no snapshot store configured (TRUST_SNAPSHOT_BUCKET / TRUST_SNAPSHOT_DIR) — using in-memory store, snapshots will not survive restarts")
		a.store = store.NewMemory()
	}

	fetcher := ingest.NewFetcher(cfg.FetchTimeout, cfg.MaxTLBytes)
	pipeline := ingest.NewPipeline(ingest.Config{
		LOTLURL:          cfg.LOTLURL,
		Territories:      cfg.Territories(),
		AcceptedStatuses: cfg.AcceptedStatuses(),
		ActivationMode:   cfg.ActivationMode,
		HoldAutoRelease:  cfg.HoldAutoRelease,
		ExtraAnchorsPath: cfg.ExtraAnchorsPath,
		OJNoticeURL:      cfg.OJNoticeURL,
		StaleGrace:       cfg.StaleGrace,
	}, fetcher, a.events, a.Log())
	a.manager = ingest.NewManager(pipeline, a.store, a.events, a.Log())

	a.authClient, err = authclient.New(cfg.Auth)
	if err != nil {
		return fmt.Errorf("trust-anchor: auth client: %w", err)
	}
	a.authMW = a.authClient.Authenticate()

	if err := a.AddTask(tasks.NewRefreshTask(a.manager, cfg.RefreshInterval, a.Log())); err != nil {
		return err
	}
	return nil
}

// Start initializes persisted state (bootstrap + last snapshot) and starts
// the server and background tasks.
func (a *App) Start() error {
	if err := a.manager.Initialize(a.BackgroundContext(), a.config.BootstrapCertsPath, a.config.OJPinnedReference); err != nil {
		return err
	}
	if snap := a.manager.Active(); snap == nil {
		a.Log().Info("no persisted snapshot — the refresh task will build the first one on start")
	} else {
		a.Log().Info("serving restored snapshot", zap.String("snapshot", snap.ID))
	}
	return a.App.Start()
}

// Config returns the loaded configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}
	return a.config
}

// Manager returns the snapshot/ingestion manager.
func (a *App) Manager() *ingest.Manager { return a.manager }

// Events returns the security-event emitter.
func (a *App) Events() *events.Emitter { return a.events }

// Store returns the snapshot store.
func (a *App) Store() store.Store { return a.store }

// AuthMiddleware returns the inbound authentication middleware.
func (a *App) AuthMiddleware() azugo.RequestHandlerFunc { return a.authMW }

// SetAuthMiddleware overrides the inbound authentication middleware. Test use
// only — production wiring always uses the go-authbyte DPoP middleware.
func (a *App) SetAuthMiddleware(mw azugo.RequestHandlerFunc) { a.authMW = mw }
