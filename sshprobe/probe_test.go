package sshprobe

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
)

const testVersion = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20"

// startServer runs an in-process SSH server with the three host key types
// and one password account ("u" / "pw").
func startServer(t *testing.T, hk *registry.HostKeys) (host string, port int) {
	t.Helper()

	cfg := &ssh.ServerConfig{
		ServerVersion: testVersion,
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
	port, _ = strconv.Atoi(p)
	return h, port
}

func newKeys(t *testing.T) *registry.HostKeys {
	t.Helper()
	hk, err := registry.GenerateHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	return hk
}

func TestReadBannerAndHostKeys(t *testing.T) {
	hk := newKeys(t)
	host, port := startServer(t, hk)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ctx := context.Background()

	b, err := ReadBanner(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != testVersion {
		t.Errorf("version = %q", b.Version)
	}
	if !strings.Contains(b.Kex.KexAlgos, "curve25519-sha256") || b.Kex.HASSHServer() == "" {
		t.Errorf("unexpected KEXINIT: %+v", b.Kex)
	}

	keys, err := HostKeys(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("host keys = %d, want 3", len(keys))
	}

	p := registry.Persona{}
	p.SetHostKeys(*hk)
	want, err := FromPersona(&p)
	if err != nil {
		t.Fatal(err)
	}
	for typ, k := range want.HostKeys {
		if got := keys[typ]; got == nil || string(got.Marshal()) != string(k.Marshal()) {
			t.Errorf("%s host key differs from the one served", typ)
		}
	}
}

func TestLogin(t *testing.T) {
	hk := newKeys(t)
	host, port := startServer(t, hk)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ctx := context.Background()

	p := registry.Persona{}
	p.SetHostKeys(*hk)
	snap, _ := FromPersona(&p)
	var pinned []ssh.PublicKey
	for _, k := range snap.HostKeys {
		pinned = append(pinned, k)
	}

	if err := Login(ctx, addr, "u", ssh.Password("pw"), pinned); err != nil {
		t.Fatalf("good credentials: %v", err)
	}
	if err := Login(ctx, addr, "u", ssh.Password("bad"), pinned); err == nil {
		t.Error("wrong password accepted")
	}

	other := newKeys(t)
	op := registry.Persona{}
	op.SetHostKeys(*other)
	osnap, _ := FromPersona(&op)
	var wrong []ssh.PublicKey
	for _, k := range osnap.HostKeys {
		wrong = append(wrong, k)
	}
	if err := Login(ctx, addr, "u", ssh.Password("pw"), wrong); err == nil {
		t.Error("login succeeded against unexpected host keys")
	}
}

func TestParseAuthMethods(t *testing.T) {
	out := "debug1: Next authentication method: none\n" +
		"debug1: Authentications that can continue: publickey,password\n" +
		"user@host: Permission denied (publickey,password).\n"
	got, err := ParseAuthMethods(out)
	if err != nil || strings.Join(got, ",") != "publickey,password" {
		t.Fatalf("got %v, %v", got, err)
	}

	// the last line wins
	got, _ = ParseAuthMethods("Authentications that can continue: password\nAuthentications that can continue: publickey,keyboard-interactive\n")
	if strings.Join(got, ",") != "publickey,keyboard-interactive" {
		t.Errorf("got %v", got)
	}

	if _, err := ParseAuthMethods("nothing useful here"); err == nil {
		t.Error("missing line not reported")
	}
}

func TestAuthMethodsWithSSHClient(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	hk := newKeys(t)
	host, port := startServer(t, hk)

	got, err := AuthMethods(context.Background(), host, port, "u")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0] != "password" {
		t.Errorf("methods = %v, want password first", got)
	}
}

func TestDiffAndHash(t *testing.T) {
	hk := newKeys(t)
	p := registry.Persona{
		SSHVersion: testVersion, Kex: "a,b", HostKeyAlgs: "x", Ciphers: "c1,c2", MACs: "m", Compression: "none",
		AuthMethods: "publickey,password", HASSHServer: "abc",
	}
	p.SetHostKeys(*hk)

	a, err := FromPersona(&p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := FromPersona(&p)
	if d := Diff(a, b); len(d) != 0 {
		t.Fatalf("identical snapshots differ: %+v", d)
	}
	if a.Hash() != b.Hash() {
		t.Error("identical snapshots hash differently")
	}

	b.Kex = "a,b,c"
	b.AuthMethods = []string{"password", "publickey"} // same set, other order
	b.HostKeys = map[string]ssh.PublicKey{}
	d := Diff(a, b)
	fields := map[string]bool{}
	for _, x := range d {
		fields[x.Field] = true
	}
	for _, f := range []string{"kex_algorithms", "auth methods", "host key ssh-ed25519"} {
		if !fields[f] {
			t.Errorf("difference on %q not reported: %+v", f, d)
		}
	}
	if a.Hash() == b.Hash() {
		t.Error("different snapshots share a hash")
	}
}
