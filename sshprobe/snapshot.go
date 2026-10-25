package sshprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
)

// Snapshot is everything announced by a server before authentication. The
// lists are the raw comma-separated name-lists, in the order received.
type Snapshot struct {
	Version     string
	Kex         string
	HostKeyAlgs string
	Ciphers     string // server to client
	MACs        string // server to client
	Compression string // server to client
	AuthMethods []string
	HASSHServer string
	HostKeys    map[string]ssh.PublicKey
}

// Take probes host:port. user is only used to ask for the authentication
// methods.
func Take(ctx context.Context, host string, port int, user string) (*Snapshot, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	b, err := ReadBanner(ctx, addr)
	if err != nil {
		return nil, err
	}
	keys, err := HostKeys(ctx, addr)
	if err != nil {
		return nil, err
	}
	methods, err := AuthMethods(ctx, host, port, user)
	if err != nil {
		return nil, err
	}

	return &Snapshot{
		Version:     b.Version,
		Kex:         b.Kex.KexAlgos,
		HostKeyAlgs: b.Kex.ServerHostKeyAlgos,
		Ciphers:     b.Kex.CiphersServerClient,
		MACs:        b.Kex.MACsServerClient,
		Compression: b.Kex.CompressionServerClient,
		AuthMethods: methods,
		HASSHServer: b.Kex.HASSHServer(),
		HostKeys:    keys,
	}, nil
}

// FromPersona rebuilds the snapshot stored in a persona. Host keys come from
// the persona's private keys.
func FromPersona(p *registry.Persona) (*Snapshot, error) {
	s := &Snapshot{
		Version:     p.SSHVersion,
		Kex:         p.Kex,
		HostKeyAlgs: p.HostKeyAlgs,
		Ciphers:     p.Ciphers,
		MACs:        p.MACs,
		Compression: p.Compression,
		HASSHServer: p.HASSHServer,
		HostKeys:    make(map[string]ssh.PublicKey),
	}
	for _, m := range strings.Split(p.AuthMethods, ",") {
		if m = strings.TrimSpace(m); m != "" {
			s.AuthMethods = append(s.AuthMethods, m)
		}
	}
	for _, pem := range []string{p.HostKeyED25519, p.HostKeyECDSA, p.HostKeyRSA} {
		if pem == "" {
			continue
		}
		signer, err := ssh.ParsePrivateKey([]byte(pem))
		if err != nil {
			return nil, fmt.Errorf("sshprobe: persona host key: %w", err)
		}
		s.HostKeys[signer.PublicKey().Type()] = signer.PublicKey()
	}
	return s, nil
}

// Hash is a digest of the whole snapshot, to detect drift.
func (s *Snapshot) Hash() string {
	h := sha256.New()
	for _, f := range []string{s.Version, s.Kex, s.HostKeyAlgs, s.Ciphers, s.MACs, s.Compression, strings.Join(s.AuthMethods, ",")} {
		fmt.Fprintf(h, "%d:%s\n", len(f), f)
	}
	types := make([]string, 0, len(s.HostKeys))
	for t := range s.HostKeys {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Fprintf(h, "%s %s\n", t, ssh.FingerprintSHA256(s.HostKeys[t]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Difference describes one field that differs.
type Difference struct {
	Field string
	Want  string
	Got   string
}

// Diff lists the fields of got that differ from want. An empty result means
// both announce exactly the same thing.
func Diff(want, got *Snapshot) []Difference {
	var d []Difference
	add := func(field, w, g string) {
		if w != g {
			d = append(d, Difference{field, w, g})
		}
	}

	add("version", want.Version, got.Version)
	add("kex_algorithms", want.Kex, got.Kex)
	add("host_key_algorithms", want.HostKeyAlgs, got.HostKeyAlgs)
	add("ciphers (server to client)", want.Ciphers, got.Ciphers)
	add("macs (server to client)", want.MACs, got.MACs)
	add("compression (server to client)", want.Compression, got.Compression)
	add("auth methods", strings.Join(want.AuthMethods, ","), strings.Join(got.AuthMethods, ","))
	add("hassh server", want.HASSHServer, got.HASSHServer)

	for _, t := range []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSA} {
		add("host key "+t, fingerprint(want.HostKeys[t]), fingerprint(got.HostKeys[t]))
	}
	return d
}

func fingerprint(k ssh.PublicKey) string {
	if k == nil {
		return "(none)"
	}
	return ssh.FingerprintSHA256(k)
}
