package main

import (
	"fmt"
	"log/slog"

	"github.com/tg123/sshpiper/registry"
	"github.com/urfave/cli/v2"
)

// relayFlags returns the options of the registry mode. Without --registry
// the daemon behaves exactly like upstream sshpiperd.
func relayFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "registry",
			Usage:   "path of the registry database; enables per-address identities (host keys, version, algorithms) and closes connections to addresses not in service",
			EnvVars: []string{"SSHPIPERD_REGISTRY"},
		},
		&cli.StringSliceFlag{
			Name:    "registry-verify-from",
			Usage:   "source addresses served for entries in state ready (not yet exposed), to check an identity before exposing it",
			Value:   cli.NewStringSlice("127.0.0.1", "::1"),
			EnvVars: []string{"SSHPIPERD_REGISTRY_VERIFY_FROM"},
		},
	}
}

// setupPersonas opens the registry and installs the per-address identity
// selection. It must be called after the plugins were installed, since the
// identities are copies of the plugin-aware base configuration.
func (d *daemon) setupPersonas(ctx *cli.Context) error {
	path := ctx.String("registry")
	if path == "" {
		return nil
	}

	db, err := registry.Open(path, registry.Options{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("cannot open registry: %w", err)
	}

	store, err := newPersonaStore(db, d.config.PiperConfig, ctx.StringSlice("registry-verify-from"))
	if err != nil {
		_ = db.Close()
		return err
	}

	d.personas = store
	slog.Info("registry mode", "registry", path)
	return nil
}
