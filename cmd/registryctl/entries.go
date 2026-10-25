package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/registry"
	"github.com/urfave/cli/v2"
)

func initCommand() *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "create the registry file (mode 0600) if missing",
		Action: func(c *cli.Context) error {
			db, err := openDB(c, false)
			if err != nil {
				return err
			}
			defer db.Close()
			fmt.Printf("registry ready: %s\n", db.Path())
			return nil
		},
	}
}

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func addCommand() *cli.Command {
	return &cli.Command{
		Name:  "add",
		Usage: "add an entry (state draft)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "ip", Usage: "external IP address", Required: true},
			&cli.StringFlag{Name: "user", Usage: "user name of the credential", Required: true},
			&cli.StringFlag{Name: "backend", Usage: "backend HOST[:PORT]", Required: true},
			&cli.StringFlag{Name: "password", Usage: "password (visible in the process list; prefer --password-file)"},
			&cli.StringFlag{Name: "password-file", Usage: "file holding the password"},
			&cli.StringFlag{Name: "public-key", Usage: "public key file (authorized_keys format)"},
			&cli.StringFlag{Name: "private-key", Usage: "private key file (OpenSSH format, no passphrase)"},
		},
		Action: func(c *cli.Context) error {
			host, port, err := libplugin.SplitHostPortForSSH(c.String("backend"))
			if err != nil {
				return fmt.Errorf("invalid --backend: %w", err)
			}

			n := registry.NewEntry{
				ExternalIP:  c.String("ip"),
				Username:    c.String("user"),
				BackendHost: host,
				BackendPort: port,
				Password:    c.String("password"),
			}
			if f := c.String("password-file"); f != "" {
				if n.Password != "" {
					return fmt.Errorf("use either --password or --password-file")
				}
				if n.Password, err = readSecretFile(f); err != nil {
					return err
				}
			}
			if f := c.String("public-key"); f != "" {
				if n.PublicKey, err = readSecretFile(f); err != nil {
					return err
				}
			}
			if f := c.String("private-key"); f != "" {
				b, err := os.ReadFile(f)
				if err != nil {
					return err
				}
				n.PrivateKey = string(b)
			}

			db, err := openDB(c, false)
			if err != nil {
				return err
			}
			defer db.Close()

			e, err := db.Create(c.Context, n)
			if err != nil {
				return err
			}
			fmt.Printf("added %s\n", e)
			return nil
		},
	}
}

func listCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "list entries",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "state", Usage: "only these states"},
		},
		Action: func(c *cli.Context) error {
			var states []registry.State
			for _, s := range c.StringSlice("state") {
				if !registry.State(s).Valid() {
					return fmt.Errorf("unknown state %q", s)
				}
				states = append(states, registry.State(s))
			}

			db, err := openDB(c, true)
			if err != nil {
				return err
			}
			defer db.Close()

			entries, err := db.List(c.Context, states...)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tEXTERNAL IP\tUSER\tBACKEND\tAUTH\tSTATE\tUPDATED")
			for _, e := range entries {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.ExternalIP, e.Username, backend(e), methods(e), e.State, e.UpdatedAt)
			}
			return w.Flush()
		},
	}
}

func showCommand() *cli.Command {
	return &cli.Command{
		Name:  "show",
		Usage: "show an entry, its persona summary and events",
		Flags: idFlags(),
		Action: func(c *cli.Context) error {
			db, err := openDB(c, true)
			if err != nil {
				return err
			}
			defer db.Close()

			e, err := findEntry(c, db)
			if err != nil {
				return err
			}
			fmt.Printf("id:          %d\nexternal ip: %s\nuser:        %s\nbackend:     %s\nauth:        %s\nstate:       %s\ncreated:     %s\nupdated:     %s\n",
				e.ID, e.ExternalIP, e.Username, backend(e), methods(e), e.State, e.CreatedAt, e.UpdatedAt)
			if e.RetiredAt != "" {
				fmt.Printf("retired:     %s\n", e.RetiredAt)
			}

			if p, err := db.Persona(c.Context, e.ID); err == nil {
				fmt.Printf("persona:     host keys %t, version %q, hassh_server %q, probed %q\n", p.HasHostKeys(), p.SSHVersion, p.HASSHServer, p.ProbedAt)
			} else {
				fmt.Println("persona:     none")
			}

			events, err := db.Events(c.Context, e.ID)
			if err != nil {
				return err
			}
			fmt.Println("events:")
			for _, ev := range events {
				fmt.Printf("  %s  %-18s %s\n", ev.At, ev.Event, ev.Detail)
			}
			return nil
		},
	}
}

type exportEntry struct {
	registry.Entry
	Persona *registry.Persona `json:"persona,omitempty"`
}

func exportCommand() *cli.Command {
	return &cli.Command{
		Name:  "export",
		Usage: "write all entries as JSON (secrets only with --with-secrets)",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "with-secrets", Usage: "include passwords and private keys"},
		},
		Action: func(c *cli.Context) error {
			db, err := openDB(c, true)
			if err != nil {
				return err
			}
			defer db.Close()

			entries, err := db.List(c.Context)
			if err != nil {
				return err
			}

			secrets := c.Bool("with-secrets")
			out := make([]exportEntry, 0, len(entries))
			for _, e := range entries {
				x := exportEntry{Entry: *e}
				if p, err := db.Persona(c.Context, e.ID); err == nil {
					x.Persona = p
				}
				if !secrets {
					x.Password, x.PrivateKey = "", ""
					if x.Persona != nil {
						x.Persona.HostKeyED25519, x.Persona.HostKeyECDSA, x.Persona.HostKeyRSA = "", "", ""
					}
				}
				out = append(out, x)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
}
