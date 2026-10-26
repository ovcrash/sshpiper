package relayadmin

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
	"golang.org/x/crypto/ssh"
)

// ProbeResult reports what a probe found. Problems is empty on success (the
// entry is then ready); otherwise the entry stays probing (or needs_check).
type ProbeResult struct {
	Version     string
	HASSHServer string
	AuthMethods string
	Changed     bool
	Problems    []string
}

// Probe reads what the backend announces, checks the entry's credential and
// that the backend presents the persona's host keys, records the persona and
// moves the entry to ready on success. A first probe of a draft entry moves
// it through probing; a probe of a ready/exposed entry re-checks in place.
func (s *Service) Probe(ctx context.Context, e *registry.Entry) (*ProbeResult, error) {
	if e.State == registry.StateRetired {
		return nil, errors.New("retired")
	}

	p, err := s.db.Persona(ctx, e.ID)
	if errors.Is(err, registry.ErrNotFound) || (err == nil && !p.HasHostKeys()) {
		return nil, errors.New("no host keys: generate or import them first")
	}
	if err != nil {
		return nil, err
	}
	want, err := sshprobe.FromPersona(p)
	if err != nil {
		return nil, err
	}

	if e.State == registry.StateDraft || e.State == registry.StateNeedsCheck {
		if err := s.moveTo(ctx, e, registry.StateProbing, "probe started"); err != nil {
			return nil, err
		}
	}

	problems := s.loginProblems(ctx, e, want)
	snap, snapErr := sshprobe.Take(ctx, e.BackendHost, e.BackendPort, e.Username)
	if snapErr != nil {
		problems = append(problems, "probe: "+snapErr.Error())
	} else {
		for _, d := range sshprobe.Diff(&sshprobe.Snapshot{HostKeys: want.HostKeys}, &sshprobe.Snapshot{HostKeys: snap.HostKeys}) {
			if strings.HasPrefix(d.Field, "host key ") {
				problems = append(problems, fmt.Sprintf("%s: persona %s, backend %s", d.Field, d.Want, d.Got))
			}
		}
	}

	if len(problems) > 0 {
		switch e.State {
		case registry.StateExposed:
			_ = s.moveTo(ctx, e, registry.StateNeedsCheck, strings.Join(problems, "; "))
		case registry.StateReady:
			_ = s.moveTo(ctx, e, registry.StateProbing, strings.Join(problems, "; "))
		}
		return &ProbeResult{Problems: problems}, nil
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
	if err := s.db.SetPersona(ctx, *p, "probed", fmt.Sprintf("hassh_server=%s changed=%t", p.HASSHServer, changed)); err != nil {
		return nil, err
	}
	if err := s.moveTo(ctx, e, registry.StateReady, "probe ok"); err != nil {
		return nil, err
	}

	return &ProbeResult{
		Version:     p.SSHVersion,
		HASSHServer: p.HASSHServer,
		AuthMethods: p.AuthMethods,
		Changed:     changed,
	}, nil
}

// loginProblems checks the entry's credential works on the backend.
func (s *Service) loginProblems(ctx context.Context, e *registry.Entry, want *sshprobe.Snapshot) []string {
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

func (s *Service) moveTo(ctx context.Context, e *registry.Entry, to registry.State, detail string) error {
	if e.State == to {
		return nil
	}
	if err := s.db.SetState(ctx, e.ID, to, detail); err != nil {
		return err
	}
	e.State = to
	return nil
}
