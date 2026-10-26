package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/relayadmin"
	"github.com/tg123/sshpiper/sshprobe"
	"github.com/urfave/cli/v2"
)

func probeCommand() *cli.Command {
	return &cli.Command{
		Name:  "probe",
		Usage: "read what the backend announces, check its host keys and the credential, and record the persona",
		Flags: append(idFlags(), &cli.BoolFlag{Name: "all", Usage: "probe every entry that is not retired"}),
		Action: func(c *cli.Context) error {
			db, err := openDB(c, false)
			if err != nil {
				return err
			}
			defer db.Close()
			svc := relayadmin.New(db)

			var entries []*registry.Entry
			if c.Bool("all") {
				all, err := db.List(c.Context)
				if err != nil {
					return err
				}
				for _, e := range all {
					if e.State != registry.StateRetired {
						entries = append(entries, e)
					}
				}
			} else {
				e, err := findEntry(c, db)
				if err != nil {
					return err
				}
				entries = append(entries, e)
			}

			failed := 0
			for _, e := range entries {
				res, err := svc.Probe(c.Context, e)
				switch {
				case err != nil:
					failed++
					fmt.Printf("entry %d (%s): %v\n", e.ID, e.ExternalIP, err)
				case len(res.Problems) > 0:
					failed++
					fmt.Printf("entry %d (%s) not ready:\n    %s\n", e.ID, e.ExternalIP, strings.Join(res.Problems, "\n    "))
				default:
					fmt.Printf("entry %d (%s): %s, hassh_server %s, methods %s\n",
						e.ID, e.ExternalIP, res.Version, res.HASSHServer, res.AuthMethods)
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d entries not ready", failed, len(entries))
			}
			return nil
		},
	}
}

func verifyFrontCommand() *cli.Command {
	return &cli.Command{
		Name:  "verify-front",
		Usage: "probe the proxy as if it were the backend and compare with the recorded persona",
		Flags: append(idFlags(), &cli.StringFlag{Name: "proxy", Usage: "proxy HOST[:PORT], reached from a source allowed by --registry-verify-from", Required: true}),
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
			p, err := db.Persona(c.Context, e.ID)
			if err != nil {
				return fmt.Errorf("entry %d has no persona: %w", e.ID, err)
			}
			if p.ProbedAt == "" {
				return fmt.Errorf("entry %d was never probed: run probe first", e.ID)
			}
			want, err := sshprobe.FromPersona(p)
			if err != nil {
				return err
			}

			host, port, err := splitHostPort(c.String("proxy"))
			if err != nil {
				return err
			}
			got, err := sshprobe.Take(c.Context, host, port, e.Username)
			if err != nil {
				return fmt.Errorf("cannot probe the proxy: %w", err)
			}

			diffs := sshprobe.Diff(want, got)
			fmt.Printf("persona hassh_server: %s\nproxy   hassh_server: %s\n", want.HASSHServer, got.HASSHServer)
			if len(diffs) == 0 {
				fmt.Println("OK: the proxy announces exactly what the backend announced")
				return nil
			}
			for _, d := range diffs {
				fmt.Printf("DIFF %s\n    backend: %s\n    proxy:   %s\n", d.Field, d.Want, d.Got)
			}
			return fmt.Errorf("%d difference(s) between the backend and the proxy", len(diffs))
		},
	}
}

func splitHostPort(s string) (string, int, error) {
	if !strings.Contains(s, ":") || strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "[") {
		return strings.Trim(s, "[]"), 22, nil
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %q: %w", s, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", s)
	}
	return h, n, nil
}
