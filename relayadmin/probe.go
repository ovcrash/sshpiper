package relayadmin

import (
	"context"
	"errors"
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

// Probe captures what the backend announces, checks the account's credential
// works on it, stores the backend's real public host keys on the account (the
// pin), updates the site persona's identity (version/algorithms/HASSH) and
// moves the account to ready on success. The site persona's presented host keys
// are set separately (generated/imported); the backend need not carry them. A
// first probe of a draft account moves it through probing; a probe of a
// ready/exposed account re-checks in place.
func (s *Service) Probe(ctx context.Context, e *registry.Entry) (*ProbeResult, error) {
	if e.State == registry.StateRetired {
		return nil, errors.New("retired")
	}

	if e.State == registry.StateDraft || e.State == registry.StateNeedsCheck {
		if err := s.moveTo(ctx, e, registry.StateProbing, "probe started"); err != nil {
			return nil, err
		}
	}

	var problems []string
	snap, snapErr := sshprobe.Take(ctx, e.BackendHost, e.BackendPort, e.Username)
	if snapErr != nil {
		problems = append(problems, "probe: "+snapErr.Error())
	} else {
		problems = s.loginProblems(ctx, e, &sshprobe.Snapshot{HostKeys: snap.HostKeys})
	}

	if len(problems) > 0 {
		switch e.State {
		case registry.StateExposed:
			_ = s.moveTo(ctx, e, registry.StateNeedsCheck, strings.Join(problems, "; "))
		case registry.StateReady, registry.StateProbing:
			_ = s.moveTo(ctx, e, registry.StateProbing, strings.Join(problems, "; "))
		}
		return &ProbeResult{Problems: problems}, nil
	}

	// store the backend's real public host keys on the account (the pin)
	ed, ec, rsa := backendAuthKeys(snap.HostKeys)
	if err := s.db.SetBackendHostKeys(ctx, e.ID, ed, ec, rsa); err != nil {
		return nil, err
	}

	// update the site persona's identity (version/algorithms); keep its
	// presented host keys, which are set generated/imported, not from the backend.
	sp, err := s.loadOrNewSitePersona(ctx, e.ExternalIP)
	if err != nil {
		return nil, err
	}
	oldHash := sp.ProbeHash
	sp.SSHVersion = snap.Version
	sp.Kex = snap.Kex
	sp.HostKeyAlgs = snap.HostKeyAlgs
	sp.Ciphers = snap.Ciphers
	sp.MACs = snap.MACs
	sp.Compression = snap.Compression
	sp.AuthMethods = strings.Join(snap.AuthMethods, ",")
	sp.HASSHServer = snap.HASSHServer
	sp.ProbedAt = time.Now().UTC().Format(time.RFC3339)
	sp.ProbeHash = snap.Hash()
	if err := s.db.SetSitePersona(ctx, e.ExternalIP, *sp); err != nil {
		return nil, err
	}
	if err := s.moveTo(ctx, e, registry.StateReady, "probe ok"); err != nil {
		return nil, err
	}

	return &ProbeResult{
		Version:     sp.SSHVersion,
		HASSHServer: sp.HASSHServer,
		AuthMethods: sp.AuthMethods,
		Changed:     oldHash != "" && oldHash != sp.ProbeHash,
	}, nil
}

// backendAuthKeys returns the authorized-key lines of a backend's captured
// public host keys, by type.
func backendAuthKeys(keys map[string]ssh.PublicKey) (ed, ec, rsa string) {
	for _, k := range keys {
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
		switch t := k.Type(); {
		case strings.Contains(t, "ed25519"):
			ed = line
		case strings.Contains(t, "ecdsa"):
			ec = line
		case strings.Contains(t, "rsa"):
			rsa = line
		}
	}
	return ed, ec, rsa
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
