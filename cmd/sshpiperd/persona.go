package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
)

// Key exchange markers that the SSH library appends itself.
var kexMarkers = map[string]bool{
	"ext-info-s":                   true,
	"kex-strict-s-v00@openssh.com": true,
}

// personaStore chooses, for each accepted connection, the SSH configuration
// matching the address the client connected to. Host keys are presented at KEX
// before the username, so the persona is per external IP (a "site"), shared by
// every account on it. Configurations are cached by external IP; the site's
// cache key changes when the persona or any account on the IP changes.
type personaStore struct {
	db         *registry.DB
	base       ssh.PiperConfig
	verifyFrom map[netip.Addr]bool

	mu    sync.RWMutex
	cache map[string]*cachedPersona
}

type cachedPersona struct {
	updatedAt string
	cfg       *ssh.PiperConfig
}

func newPersonaStore(db *registry.DB, base ssh.PiperConfig, verifyFrom []string) (*personaStore, error) {
	s := &personaStore{
		db:         db,
		base:       base,
		verifyFrom: make(map[netip.Addr]bool),
		cache:      make(map[string]*cachedPersona),
	}
	for _, v := range verifyFrom {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q in --registry-verify-from: %w", v, err)
		}
		s.verifyFrom[a.Unmap()] = true
	}
	return s, nil
}

func addrOf(a net.Addr) (netip.Addr, bool) {
	if a == nil {
		return netip.Addr{}, false
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// configFor returns the configuration for a connection, or nil when the
// connection must be closed without any answer: unknown address, entry not
// in service, or no persona.
func (s *personaStore) configFor(ctx context.Context, local, remote net.Addr) *ssh.PiperConfig {
	dst, ok := addrOf(local)
	if !ok {
		return nil
	}
	src, _ := addrOf(remote)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	ip := dst.String()
	route, err := s.db.SiteByExternalIP(ctx, ip)
	if err != nil {
		if !errors.Is(err, registry.ErrNotFound) {
			slog.Error("registry lookup failed", "dst", dst, "error", err)
		}
		return nil
	}

	switch {
	case route.Servable:
	case route.Ready && s.verifyFrom[src]:
	default:
		return nil
	}

	s.mu.RLock()
	c := s.cache[ip]
	s.mu.RUnlock()
	if c != nil && c.updatedAt == route.CacheKey {
		return c.cfg
	}

	p, err := s.db.SitePersona(ctx, ip)
	if err != nil {
		slog.Error("cannot load site persona", "ip", ip, "error", err)
		return nil
	}
	cfg, err := buildPersonaConfig(s.base, p)
	if err != nil {
		slog.Error("cannot build persona configuration", "ip", ip, "error", err)
		return nil
	}

	s.mu.Lock()
	s.cache[ip] = &cachedPersona{updatedAt: route.CacheKey, cfg: cfg}
	s.mu.Unlock()

	return cfg
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// hostKeyKind maps a host key signature algorithm to the key type holding it.
func hostKeyKind(alg string) string {
	switch {
	case strings.HasPrefix(alg, "ssh-rsa"), strings.HasPrefix(alg, "rsa-sha2-"):
		return "rsa"
	case strings.HasPrefix(alg, "ecdsa-sha2-"):
		return "ecdsa"
	case alg == "ssh-ed25519":
		return "ed25519"
	}
	return ""
}

// buildPersonaConfig copies base and applies the identity of a persona:
// version, algorithm lists and host keys, the keys being added in the order
// in which the persona announces their algorithms.
func buildPersonaConfig(base ssh.PiperConfig, p *registry.Persona) (*ssh.PiperConfig, error) {
	if !p.HasHostKeys() {
		return nil, errors.New("persona has no host keys")
	}

	cfg := base // by value: callbacks are shared, lists and host keys are replaced below

	if p.SSHVersion != "" {
		cfg.ServerVersion = p.SSHVersion
	}

	if kex := splitList(p.Kex); len(kex) > 0 {
		cfg.KeyExchanges = nil
		for _, k := range kex {
			if !kexMarkers[k] {
				cfg.KeyExchanges = append(cfg.KeyExchanges, k)
			}
		}
	}
	if l := splitList(p.Ciphers); len(l) > 0 {
		cfg.Ciphers = l
	}
	if l := splitList(p.MACs); len(l) > 0 {
		cfg.MACs = l
	}

	keys := map[string]string{"rsa": p.HostKeyRSA, "ecdsa": p.HostKeyECDSA, "ed25519": p.HostKeyED25519}
	order := []string{}
	seen := map[string]bool{}
	for _, alg := range splitList(p.HostKeyAlgs) {
		if k := hostKeyKind(alg); k != "" && !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}
	for _, k := range []string{"rsa", "ecdsa", "ed25519"} {
		if !seen[k] {
			order = append(order, k)
		}
	}

	for _, kind := range order {
		signer, err := ssh.ParsePrivateKey([]byte(keys[kind]))
		if err != nil {
			return nil, fmt.Errorf("%s host key: %w", kind, err)
		}
		cfg.AddHostKey(signer)
	}

	cfg.SetDefaults()
	return &cfg, nil
}
