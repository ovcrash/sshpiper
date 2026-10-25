package main

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
)

const (
	versionA = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20"
	versionB = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
)

// seedEntry creates an entry with a persona and moves it to state.
func seedEntry(t *testing.T, db *registry.DB, ip, version string, state registry.State) (*registry.Entry, *registry.HostKeys) {
	t.Helper()
	ctx := context.Background()

	e, err := db.Create(ctx, registry.NewEntry{ExternalIP: ip, Username: "u", BackendHost: "127.0.0.1", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	hk, err := registry.GenerateHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	p := registry.Persona{
		EntryID:     e.ID,
		SSHVersion:  version,
		Ciphers:     "aes256-ctr,aes128-ctr",
		MACs:        "hmac-sha2-256,hmac-sha2-512",
		Kex:         "curve25519-sha256,ecdh-sha2-nistp256,ext-info-s,kex-strict-s-v00@openssh.com",
		HostKeyAlgs: "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
	}
	p.SetHostKeys(*hk)
	if err := db.SetPersona(ctx, p, "persona_generated", ""); err != nil {
		t.Fatal(err)
	}
	for _, to := range statePath(state) {
		if err := db.SetState(ctx, e.ID, to, ""); err != nil {
			t.Fatal(err)
		}
	}
	return e, hk
}

func statePath(to registry.State) []registry.State {
	switch to {
	case registry.StateReady:
		return []registry.State{registry.StateProbing, registry.StateReady}
	case registry.StateExposed:
		return []registry.State{registry.StateProbing, registry.StateReady, registry.StateExposed}
	}
	return nil
}

func openTempRegistry(t *testing.T) (rw, ro *registry.DB) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.db")
	rw, err := registry.Open(p, registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ro, err = registry.Open(p, registry.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close(); _ = rw.Close() })
	return rw, ro
}

// handshake connects to addr and returns the server version line and host key
// seen by a client, without authenticating.
func handshake(t *testing.T, addr string) (version string, key ssh.PublicKey, err error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	cfg := &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return nil
		},
	}
	_, _, _, herr := ssh.NewClientConn(c, addr, cfg)
	_ = herr // authentication is expected to fail

	// the version line is read on a second connection, as a raw peer would
	r, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", key, err
	}
	defer r.Close()
	_ = r.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.Write([]byte("SSH-2.0-test\r\n")); err != nil {
		return "", key, err
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return "", key, err
	}
	return strings.TrimRight(line, "\r\n"), key, nil
}

func TestBuildPersonaConfig(t *testing.T) {
	rw, _ := openTempRegistry(t)
	e, hk := seedEntry(t, rw, "192.0.2.10", versionA, registry.StateExposed)
	p, err := rw.Persona(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := buildPersonaConfig(ssh.PiperConfig{}, p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerVersion != versionA {
		t.Errorf("ServerVersion = %q", cfg.ServerVersion)
	}
	for _, k := range cfg.KeyExchanges {
		if kexMarkers[k] {
			t.Errorf("marker %q must not be configured: the library adds it", k)
		}
	}
	if got := cfg.Ciphers; len(got) != 2 || got[0] != "aes256-ctr" {
		t.Errorf("Ciphers = %v", got)
	}
	_ = hk

	// the base configuration must be left untouched
	base := ssh.PiperConfig{}
	if _, err := buildPersonaConfig(base, p); err != nil {
		t.Fatal(err)
	}
	if base.ServerVersion != "" || len(base.Ciphers) != 0 {
		t.Error("buildPersonaConfig modified its input")
	}

	p.HostKeyRSA = ""
	if _, err := buildPersonaConfig(ssh.PiperConfig{}, p); err == nil {
		t.Error("persona without host keys accepted")
	}
}

// TestPersonaPerAddress serves two identities on two loopback addresses of the
// same port and checks what a client sees on each.
func TestPersonaPerAddress(t *testing.T) {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer l1.Close()
	// a second local address on the same host; skip where 127.0.0.2 is not local
	l2, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 not available: %v", err)
	}
	defer l2.Close()

	rw, ro := openTempRegistry(t)
	_, hkA := seedEntry(t, rw, "127.0.0.1", versionA, registry.StateExposed)
	_, hkB := seedEntry(t, rw, "127.0.0.2", versionB, registry.StateExposed)

	store, err := newPersonaStore(ro, ssh.PiperConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	serve := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				cfg := store.configFor(context.Background(), c.LocalAddr(), c.RemoteAddr())
				if cfg == nil {
					return
				}
				// no plugin is installed: the handshake completes, authentication cannot
				if p, err := ssh.NewSSHPiperConn(c, cfg); err == nil {
					p.Close()
				}
			}()
		}
	}
	go serve(l1)
	go serve(l2)

	check := func(l net.Listener, wantVersion string, hk *registry.HostKeys) {
		t.Helper()
		v, key, err := handshake(t, l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if v != wantVersion {
			t.Errorf("%s: version %q, want %q", l.Addr(), v, wantVersion)
		}
		if key == nil {
			t.Fatalf("%s: no host key seen", l.Addr())
		}
		var want string
		switch key.Type() {
		case ssh.KeyAlgoED25519:
			want = hk.ED25519
		case ssh.KeyAlgoECDSA256:
			want = hk.ECDSA
		default:
			want = hk.RSA
		}
		s, err := ssh.ParsePrivateKey([]byte(want))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			t.Errorf("%s: host key is not the persona's %s key", l.Addr(), key.Type())
		}
	}
	check(l1, versionA, hkA)
	check(l2, versionB, hkB)
}

func TestConfigForServability(t *testing.T) {
	ctx := context.Background()
	rw, ro := openTempRegistry(t)
	seedEntry(t, rw, "192.0.2.10", versionA, registry.StateExposed)
	ready, _ := seedEntry(t, rw, "192.0.2.11", versionA, registry.StateReady)
	seedEntry(t, rw, "192.0.2.12", versionA, registry.StateDraft)

	store, err := newPersonaStore(ro, ssh.PiperConfig{}, []string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}

	addr := func(s string) net.Addr {
		a, _ := net.ResolveTCPAddr("tcp", s)
		return a
	}
	attacker := addr("198.51.100.7:40000")
	verifier := addr("127.0.0.1:40000")

	cases := []struct {
		name         string
		local, from  net.Addr
		wantServable bool
	}{
		{"exposed, any source", addr("192.0.2.10:22"), attacker, true},
		{"ready, outside source", addr("192.0.2.11:22"), attacker, false},
		{"ready, verification source", addr("192.0.2.11:22"), verifier, true},
		{"draft", addr("192.0.2.12:22"), verifier, false},
		{"unknown address", addr("192.0.2.99:22"), verifier, false},
		{"no local address", nil, verifier, false},
	}
	for _, c := range cases {
		if got := store.configFor(ctx, c.local, c.from) != nil; got != c.wantServable {
			t.Errorf("%s: servable = %v, want %v", c.name, got, c.wantServable)
		}
	}

	// retiring takes effect without any restart
	if err := rw.SetState(ctx, ready.ID, registry.StateExposed, ""); err != nil {
		t.Fatal(err)
	}
	if store.configFor(ctx, addr("192.0.2.11:22"), attacker) == nil {
		t.Error("entry exposed after the daemon started is not served")
	}
	if err := rw.SetState(ctx, ready.ID, registry.StateRetired, ""); err != nil {
		t.Fatal(err)
	}
	if store.configFor(ctx, addr("192.0.2.11:22"), attacker) != nil {
		t.Error("retired entry still served")
	}
}

func TestPersonaCacheInvalidation(t *testing.T) {
	ctx := context.Background()
	rw, ro := openTempRegistry(t)
	e, _ := seedEntry(t, rw, "192.0.2.10", versionA, registry.StateExposed)
	store, _ := newPersonaStore(ro, ssh.PiperConfig{}, nil)

	local, _ := net.ResolveTCPAddr("tcp", "192.0.2.10:22")
	remote, _ := net.ResolveTCPAddr("tcp", "198.51.100.7:1")

	first := store.configFor(ctx, local, remote)
	if again := store.configFor(ctx, local, remote); again != first {
		t.Error("configuration not cached between connections")
	}

	// a registry write must be visible: updated_at has second resolution
	time.Sleep(1100 * time.Millisecond)
	p, _ := rw.Persona(ctx, e.ID)
	p.SSHVersion = versionB
	if err := rw.SetPersona(ctx, *p, "probed", ""); err != nil {
		t.Fatal(err)
	}
	if got := store.configFor(ctx, local, remote); got == nil || got.ServerVersion != versionB {
		t.Errorf("configuration not refreshed after a persona change: %+v", got)
	}
}

func TestAddrOf(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.1:22": "192.0.2.1", "[::ffff:192.0.2.1]:22": "192.0.2.1", "[2001:db8::1]:22": "2001:db8::1"} {
		a, _ := net.ResolveTCPAddr("tcp", in)
		got, ok := addrOf(a)
		if !ok || got.String() != want {
			t.Errorf("addrOf(%s) = %v, %v; want %s", in, got, ok, want)
		}
	}
	if _, ok := addrOf(nil); ok {
		t.Error("addrOf(nil) = ok")
	}
}
