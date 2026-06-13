package main

import (
	"azugo.io/azugo/server"
	"azugo.io/core/cli"

	app "github.com/gmb-sig/trust-anchor"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Trust Anchor Service",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
