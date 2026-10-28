package main

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
)

// startBackend runs an in-process SSH server with the given host keys and a
// password account u / pw. It returns host and port.
func startBackend(t *testing.T, hk *registry.HostKeys) (string, string) {
	t.Helper()

	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20",
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "u" && string(pw) == "pw" {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	for _, pem := range []string{hk.ED25519, hk.ECDSA, hk.RSA} {
		s, err := ssh.ParsePrivateKey([]byte(pem))
		if err != nil {
			t.Fatal(err)
		}
		cfg.AddHostKey(s)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if conn, _, _, err := ssh.NewServerConn(c, cfg); err == nil {
					_ = conn.Close()
				}
			}()
		}
	}()

	h, p, _ := net.SplitHostPort(l.Addr().String())
	return h, p
}

func TestProbeMovesEntryToReady(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "r.db")

	backendKeys, err := registry.GenerateHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	host, port := startBackend(t, backendKeys)

	if _, err := run(t, "--registry", dbPath, "add", "--ip", "203.0.113.10", "--user", "u", "--backend", net.JoinHostPort(host, port), "--password", "pw"); err != nil {
		t.Fatal(err)
	}

	// probe captures the backend's keys and checks the credential -> ready
	out, err := run(t, "--registry", dbPath, "probe", "--id", "1")
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}

	db, _ := registry.Open(dbPath, registry.Options{ReadOnly: true})
	defer db.Close()
	e, _ := db.ByID(ctx, 1)
	if e.State != registry.StateReady {
		t.Fatalf("state = %s, want ready", e.State)
	}
	if e.BackendHostED25519 == "" {
		t.Fatal("backend host keys not captured by probe")
	}
	p, _ := db.SitePersona(ctx, "203.0.113.10")
	if p.SSHVersion != "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20" || p.HASSHServer == "" || p.ProbeHash == "" || p.AuthMethods == "" || p.ProbedAt == "" {
		t.Fatalf("site persona not recorded: %+v", p)
	}
}

func TestProbeWrongPassword(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	dbPath := filepath.Join(t.TempDir(), "r.db")
	keys, _ := registry.GenerateHostKeys()
	host, port := startBackend(t, keys)

	if _, err := run(t, "--registry", dbPath, "add", "--ip", "203.0.113.10", "--user", "u", "--backend", net.JoinHostPort(host, port), "--password", "not-the-password"); err != nil {
		t.Fatal(err)
	}

	if _, err := run(t, "--registry", dbPath, "probe", "--id", "1"); err == nil {
		t.Fatal("probe accepted a credential the backend refuses")
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := map[string]struct {
		host string
		port int
		ok   bool
	}{
		"proxy.example":      {"proxy.example", 22, true},
		"proxy.example:2222": {"proxy.example", 2222, true},
		"10.0.0.1":           {"10.0.0.1", 22, true},
		"[2001:db8::1]:22":   {"2001:db8::1", 22, true},
		"2001:db8::1":        {"2001:db8::1", 22, true},
		"host:notaport":      {"", 0, false},
		"host:70000":         {"", 0, false},
	}
	for in, want := range cases {
		h, p, err := splitHostPort(in)
		if (err == nil) != want.ok || (want.ok && (h != want.host || p != want.port)) {
			t.Errorf("splitHostPort(%q) = %q, %d, %v", in, h, p, err)
		}
	}
}
