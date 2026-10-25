package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/sshprobe"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
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
				if err := probeEntry(c.Context, db, e); err != nil {
					failed++
					fmt.Printf("entry %d (%s): %v\n", e.ID, e.ExternalIP, err)
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d entries not ready", failed, len(entries))
			}
			return nil
		},
	}
}

// moveTo changes state when the transition is allowed and the entry is not
// already there.
func moveTo(ctx context.Context, db *registry.DB, e *registry.Entry, to registry.State, detail string) error {
	if e.State == to {
		return nil
	}
	if err := db.SetState(ctx, e.ID, to, detail); err != nil {
		return err
	}
	e.State = to
	return nil
}

// probeEntry probes the backend of e. A first probe moves a draft entry to
// ready; a probe of a ready or exposed entry detects drift and moves it back
// (ready -> probing, exposed -> needs_check).
func probeEntry(ctx context.Context, db *registry.DB, e *registry.Entry) error {
	if e.State == registry.StateRetired {
		return errors.New("retired")
	}

	p, err := db.Persona(ctx, e.ID)
	if errors.Is(err, registry.ErrNotFound) || (err == nil && !p.HasHostKeys()) {
		return errors.New("no host keys: run persona gen (then give them to the backend) or persona import first")
	}
	if err != nil {
		return err
	}
	want, err := sshprobe.FromPersona(p)
	if err != nil {
		return err
	}

	live := e.State == registry.StateReady || e.State == registry.StateExposed
	if !live {
		if e.State == registry.StateDraft || e.State == registry.StateNeedsCheck {
			if err := moveTo(ctx, db, e, registry.StateProbing, "probe started"); err != nil {
				return err
			}
		}
	}

	problems := probeProblems(ctx, e, want)
	snap, snapErr := sshprobe.Take(ctx, e.BackendHost, e.BackendPort, e.Username)

	switch {
	case snapErr != nil:
		problems = append(problems, "probe: "+snapErr.Error())
	default:
		// the backend must present exactly the persona's host keys
		for _, d := range sshprobe.Diff(&sshprobe.Snapshot{HostKeys: want.HostKeys}, &sshprobe.Snapshot{HostKeys: snap.HostKeys}) {
			if strings.HasPrefix(d.Field, "host key ") {
				problems = append(problems, fmt.Sprintf("%s: persona %s, backend %s", d.Field, d.Want, d.Got))
			}
		}
	}

	if len(problems) > 0 {
		if e.State == registry.StateExposed {
			_ = moveTo(ctx, db, e, registry.StateNeedsCheck, strings.Join(problems, "; "))
		} else if e.State == registry.StateReady {
			_ = moveTo(ctx, db, e, registry.StateProbing, strings.Join(problems, "; "))
		}
		return errors.New(strings.Join(problems, "\n    "))
	}

	p.SSHVersion = snap.Version
	p.Kex = snap.Kex
	p.HostKeyAlgs = snap.HostKeyAlgs
	p.Ciphers = snap.Ciphers
	p.MACs = snap.MACs
	p.Compression = snap.Compression
	p.AuthMethods = strings.Join(snap.AuthMethods, ",")
	p.HASSHServer = snap.HASSHServer
	p.ProbedAt = time.Now().UTC().Format(time.RFC3339)
	snap.HostKeys = want.HostKeys
	p.ProbeHash = snap.Hash()

	changed := p.ProbeHash != want.Hash()
	if err := db.SetPersona(ctx, *p, "probed", fmt.Sprintf("hassh_server=%s changed=%t", p.HASSHServer, changed)); err != nil {
		return err
	}
	if err := moveTo(ctx, db, e, registry.StateReady, "probe ok"); err != nil {
		return err
	}

	fmt.Printf("entry %d (%s): backend %s, %s, hassh_server %s, methods %s\n",
		e.ID, e.ExternalIP, e.BackendHost, p.SSHVersion, p.HASSHServer, p.AuthMethods)
	return nil
}

// probeProblems checks that the entry's credential works on the backend.
func probeProblems(ctx context.Context, e *registry.Entry, want *sshprobe.Snapshot) []string {
	addr := net.JoinHostPort(e.BackendHost, strconv.Itoa(e.BackendPort))

	var pinned []ssh.PublicKey
	for _, k := range want.HostKeys {
		pinned = append(pinned, k)
	}

	var problems []string
	if e.AuthPassword {
		if err := sshprobe.Login(ctx, addr, e.Username, ssh.Password(e.Password), pinned); err != nil {
			problems = append(problems, "password login: "+err.Error())
		}
	}
	if e.AuthKey {
		signer, err := ssh.ParsePrivateKey([]byte(e.PrivateKey))
		if err != nil {
			problems = append(problems, "private key: "+err.Error())
		} else if err := sshprobe.Login(ctx, addr, e.Username, ssh.PublicKeys(signer), pinned); err != nil {
			problems = append(problems, "key login: "+err.Error())
		}
	}
	return problems
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
