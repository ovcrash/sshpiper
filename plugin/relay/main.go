//go:build full || e2e

// Package main is the relay plugin: it routes every login on an external
// address to the backend of the registry entry for that address, forwarding
// the user name and the password as typed. The backend decides.
package main

import (
	"fmt"
	"log/slog"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/registry"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "relay",
		Usage: "sshpiperd relay plugin: route by destination address using the registry",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "registry",
				Usage:    "path of the registry database",
				EnvVars:  []string{"SSHPIPERD_RELAY_REGISTRY", "SSHPIPERD_REGISTRY"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			db, err := registry.Open(c.String("registry"), registry.Options{ReadOnly: true})
			if err != nil {
				return nil, fmt.Errorf("cannot open registry: %w", err)
			}

			return newRouter(db).config(), nil
		},
	})
}

// config returns the plugin callbacks of the router.
func (r *router) config() *libplugin.SshPiperPluginConfig {
	return &libplugin.SshPiperPluginConfig{
		NewConnectionCallback:   r.newConnection,
		NextAuthMethodsCallback: r.nextAuthMethods,
		PasswordCallback:        r.password,
		PublicKeyCallback:       r.publicKey,
		UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, method string, err error, allowed []string) {
			slog.Debug("backend refused", "id", conn.UniqueID(), "method", method, "allowed", allowed, "error", err)
		},
		PipeStartCallback: func(conn libplugin.ConnMetadata) {
			slog.Debug("pipe started", "id", conn.UniqueID())
		},
		PipeErrorCallback: func(conn libplugin.ConnMetadata, err error) {
			slog.Debug("pipe ended", "id", conn.UniqueID(), "error", err)
		},
	}
}
