// Command registryctl manages the SQLite registry read by sshpiperd.
//
//	registryctl --registry relay-registry.db init
//	registryctl add --ip 203.0.113.10 --user alice --backend 10.0.0.21 --password-file pw.txt
//	registryctl list
//	registryctl retire --id 1
//
// Changes are picked up by a running daemon without restart.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/tg123/sshpiper/registry"
	"github.com/urfave/cli/v2"
)

const defaultRegistry = "relay-registry.db"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := newApp().RunContext(ctx, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "registryctl: %v\n", err)
		os.Exit(1)
	}
}

func newApp() *cli.App {
	return &cli.App{
		Name:  "registryctl",
		Usage: "manage the relay registry",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "registry",
				Usage:   "path of the registry database",
				Value:   defaultRegistry,
				EnvVars: []string{"SSHPIPERD_REGISTRY"},
			},
		},
		Commands: []*cli.Command{
			initCommand(),
			addCommand(),
			listCommand(),
			showCommand(),
			personaCommand(),
			probeCommand(),
			verifyFrontCommand(),
			exposeCommand(),
			retireCommand(),
			exportCommand(),
		},
	}
}

// idFlags select an entry by id or by external IP.
func idFlags() []cli.Flag {
	return []cli.Flag{
		&cli.Int64Flag{Name: "id", Usage: "entry id"},
		&cli.StringFlag{Name: "ip", Usage: "external IP of the entry"},
	}
}

func openDB(c *cli.Context, readOnly bool) (*registry.DB, error) {
	return registry.Open(c.String("registry"), registry.Options{ReadOnly: readOnly})
}

// findEntry resolves --id or --ip.
func findEntry(c *cli.Context, db *registry.DB) (*registry.Entry, error) {
	switch {
	case c.IsSet("id") && c.IsSet("ip"):
		return nil, fmt.Errorf("use either --id or --ip")
	case c.IsSet("id"):
		return db.ByID(c.Context, c.Int64("id"))
	case c.IsSet("ip"):
		return db.ByExternalIP(c.Context, c.String("ip"))
	}
	return nil, fmt.Errorf("--id or --ip is required")
}

func methods(e *registry.Entry) string {
	var m []string
	if e.AuthPassword {
		m = append(m, "password")
	}
	if e.AuthKey {
		m = append(m, "key")
	}
	return strings.Join(m, "+")
}

func backend(e *registry.Entry) string {
	return e.BackendHost + ":" + strconv.Itoa(e.BackendPort)
}
