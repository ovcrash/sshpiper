package relayadmin

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
)

// startBackend runs an in-process SSH server with the given host keys and a
// password account u / pw. Returns host and port.
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

func openTemp(t *testing.T) *registry.DB {
	t.Helper()
	db, err := registry.Open(t.TempDir()+"/r.db", registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestLifecycle(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	ctx := context.Background()
	db := openTemp(t)
	svc := New(db)

	hk, err := registry.GenerateHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	host, port := startBackend(t, hk)
	bport, _ := strconv.Atoi(port)

	e, err := svc.AddEntry(ctx, registry.NewEntry{ExternalIP: "203.0.113.10", Username: "u", BackendHost: host, BackendPort: bport, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if e.State != registry.StateDraft {
		t.Fatalf("state = %s", e.State)
	}

	// probe before host keys: refused
	if _, err := svc.Probe(ctx, e); err == nil {
		t.Fatal("probe without host keys should fail")
	}

	// install the backend's real keys as the persona, then probe
	if err := svc.ImportPersonaKeys(ctx, e, *hk); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Probe(ctx, e)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("probe problems: %v", res.Problems)
	}
	if e.State != registry.StateReady {
		t.Fatalf("state after probe = %s, want ready", e.State)
	}

	if err := svc.Expose(ctx, e); err != nil {
		t.Fatalf("expose: %v", err)
	}
	if got, _ := svc.Get(ctx, "203.0.113.10"); got.State != registry.StateExposed {
		t.Fatalf("not exposed: %s", got.State)
	}

	// generating keys on an exposed entry is refused
	if err := svc.GenPersona(ctx, e, true); err == nil {
		t.Fatal("key change on an exposed entry should be refused")
	}

	if err := svc.Retire(ctx, e); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if got, _ := svc.Get(ctx, "203.0.113.10"); got.State != registry.StateRetired {
		t.Fatalf("not retired: %s", got.State)
	}
}

func TestProbeWrongCredential(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	ctx := context.Background()
	db := openTemp(t)
	svc := New(db)
	hk, _ := registry.GenerateHostKeys()
	host, port := startBackend(t, hk)
	bport, _ := strconv.Atoi(port)

	e, err := svc.AddEntry(ctx, registry.NewEntry{ExternalIP: "203.0.113.11", Username: "u", BackendHost: host, BackendPort: bport, Password: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ImportPersonaKeys(ctx, e, *hk); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Probe(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) == 0 {
		t.Fatal("probe should report a login problem for a wrong password")
	}
	if e.State == registry.StateReady {
		t.Fatal("entry must not be ready after a failed probe")
	}
}

func TestRetireHook(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t)
	svc := New(db)
	e, err := svc.AddEntry(ctx, registry.NewEntry{ExternalIP: "203.0.113.12", Username: "u", BackendHost: "h", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	_ = svc.Retire(ctx, e)
	if err := svc.RunRetireHook(ctx, e, "test \"$EXTERNAL_IP\" = 203.0.113.12 && test -n \"$ENTRY_ID\""); err != nil {
		t.Fatalf("hook with the right env failed: %v", err)
	}
	if err := svc.RunRetireHook(ctx, e, "exit 3"); err == nil {
		t.Fatal("a failing hook should return an error")
	}
	if err := svc.RunRetireHook(ctx, e, ""); err != nil {
		t.Fatalf("empty hook must be a no-op: %v", err)
	}
}
