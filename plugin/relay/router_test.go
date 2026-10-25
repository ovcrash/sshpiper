//go:build full || e2e

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
)

type fakeConn struct {
	user string
	meta map[string]string
}

func (f fakeConn) User() string              { return f.user }
func (f fakeConn) RemoteAddr() string        { return "198.51.100.7:40000" }
func (f fakeConn) UniqueID() string          { return "test" }
func (f fakeConn) GetMeta(key string) string { return f.meta[key] }
func connTo(user, dst string) libplugin.ConnMetadata {
	return fakeConn{user: user, meta: map[string]string{metaDstAddr: dst}}
}

func keyPair(t *testing.T) (pub ssh.PublicKey, pubLine, priv string) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(sk, "")
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	return sp, string(ssh.MarshalAuthorizedKey(sp)), string(pem.EncodeToMemory(block))
}

type fixture struct {
	r        *router
	rw       *registry.DB
	pwEntry  *registry.Entry
	keyEntry *registry.Entry
	keyPub   ssh.PublicKey
	hostKeys *registry.HostKeys
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r.db")
	rw, err := registry.Open(path, registry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ro, err := registry.Open(path, registry.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close(); _ = rw.Close() })

	pub, pubLine, priv := keyPair(t)
	pw, err := rw.Create(ctx, registry.NewEntry{ExternalIP: "192.0.2.10", Username: "alice", BackendHost: "10.0.0.21", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	ke, err := rw.Create(ctx, registry.NewEntry{ExternalIP: "192.0.2.11", Username: "bob", BackendHost: "10.0.0.22", BackendPort: 2222, PublicKey: pubLine, PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	hk, err := registry.GenerateHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*registry.Entry{pw, ke} {
		p := registry.Persona{EntryID: e.ID, AuthMethods: "publickey,password"}
		p.SetHostKeys(*hk)
		if err := rw.SetPersona(ctx, p, "persona_generated", ""); err != nil {
			t.Fatal(err)
		}
		for _, s := range []registry.State{registry.StateProbing, registry.StateReady, registry.StateExposed} {
			if err := rw.SetState(ctx, e.ID, s, ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &fixture{r: newRouter(ro), rw: rw, pwEntry: pw, keyEntry: ke, keyPub: pub, hostKeys: hk}
}

func TestPasswordForwardedAsTyped(t *testing.T) {
	f := newFixture(t)

	// the typed user name is forwarded, even if it differs from the entry's
	for _, user := range []string{"alice", "root", "nosuchuser"} {
		u, err := f.r.password(connTo(user, "192.0.2.10:22"), []byte("whatever-was-typed"))
		if err != nil {
			t.Fatalf("user %q: %v", user, err)
		}
		if u.UserName != user {
			t.Errorf("UserName = %q, want %q", u.UserName, user)
		}
		if u.Uri != "tcp://10.0.0.21:22" {
			t.Errorf("Uri = %q", u.Uri)
		}
		if got := u.GetPassword().GetPassword(); got != "whatever-was-typed" {
			t.Errorf("password = %q", got)
		}
	}

	// the stored password is never used for password logins
	u, _ := f.r.password(connTo("alice", "192.0.2.10:22"), []byte("x"))
	if strings.Contains(u.GetPassword().GetPassword(), "s3cret") {
		t.Error("stored password leaked into a login attempt")
	}
}

func TestKnownHostsPinned(t *testing.T) {
	f := newFixture(t)
	u, err := f.r.password(connTo("alice", "192.0.2.10:22"), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(u.KnownHostsData)), "\n")
	if len(lines) != 3 {
		t.Fatalf("known hosts lines = %d, want 3:\n%s", len(lines), u.KnownHostsData)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "10.0.0.21 ") {
			t.Errorf("unexpected host field in %q", l)
		}
	}

	// non-default port uses the bracketed form
	_, err = f.r.publicKey(connTo("bob", "192.0.2.11:22"), f.keyPub.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	u, _ = f.r.publicKey(connTo("bob", "192.0.2.11:22"), f.keyPub.Marshal())
	if !strings.HasPrefix(string(u.KnownHostsData), "[10.0.0.22]:2222 ") {
		t.Errorf("known hosts = %q", u.KnownHostsData)
	}
}

func TestPublicKey(t *testing.T) {
	f := newFixture(t)

	u, err := f.r.publicKey(connTo("bob", "192.0.2.11:22"), f.keyPub.Marshal())
	if err != nil {
		t.Fatalf("entry key refused: %v", err)
	}
	if !bytes.Contains(u.GetPrivateKey().GetPrivateKey(), []byte("PRIVATE KEY")) {
		t.Error("no private key in the upstream auth")
	}
	if u.UserName != "bob" || u.Uri != "tcp://10.0.0.22:2222" {
		t.Errorf("upstream = %s %s", u.UserName, u.Uri)
	}

	other, _, _ := keyPair(t)
	if _, err := f.r.publicKey(connTo("bob", "192.0.2.11:22"), other.Marshal()); err == nil {
		t.Error("another key was accepted")
	}
	// the password-only entry has no key method
	if _, err := f.r.publicKey(connTo("alice", "192.0.2.10:22"), f.keyPub.Marshal()); err == nil {
		t.Error("key accepted on a password-only entry")
	}
	// the key-only entry has no password method
	if _, err := f.r.password(connTo("bob", "192.0.2.11:22"), []byte("x")); err == nil {
		t.Error("password accepted on a key-only entry")
	}
}

func TestNextAuthMethods(t *testing.T) {
	f := newFixture(t)

	// probed entries offer what the backend offered, in its order,
	// whatever their own credential is
	for _, dst := range []string{"192.0.2.10:22", "192.0.2.11:22"} {
		got, err := f.r.nextAuthMethods(connTo("", dst))
		if err != nil || strings.Join(got, ",") != "publickey,password" {
			t.Errorf("%s: %v, %v", dst, got, err)
		}
	}

	// an entry without persona offers the methods of its credential
	ctx := context.Background()
	for ip, want := range map[string]string{"192.0.2.20": "password", "192.0.2.21": "publickey"} {
		n := registry.NewEntry{ExternalIP: ip, Username: "u", BackendHost: "h", Password: "p"}
		if want == "publickey" {
			_, pubLine, priv := keyPair(t)
			n.Password, n.PublicKey, n.PrivateKey = "", pubLine, priv
		}
		e, err := f.rw.Create(ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []registry.State{registry.StateProbing, registry.StateReady} {
			if err := f.rw.SetState(ctx, e.ID, s, ""); err != nil {
				t.Fatal(err)
			}
		}
		got, err := f.r.nextAuthMethods(connTo("", ip+":22"))
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%s without persona: %v, %v; want %s", ip, got, err, want)
		}
	}
}

func TestNotServed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	for _, dst := range []string{"", "192.0.2.99:22", "garbage"} {
		if err := f.r.newConnection(connTo("u", dst)); err == nil {
			t.Errorf("dst %q: connection accepted", dst)
		}
	}
	if err := f.r.newConnection(connTo("u", "192.0.2.10:22")); err != nil {
		t.Errorf("exposed entry refused: %v", err)
	}

	// retiring takes effect on the next call, without restarting the plugin
	if err := f.rw.SetState(ctx, f.pwEntry.ID, registry.StateRetired, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.r.newConnection(connTo("u", "192.0.2.10:22")); err == nil {
		t.Error("retired entry still accepted")
	}
	if _, err := f.r.password(connTo("alice", "192.0.2.10:22"), []byte("x")); err == nil {
		t.Error("retired entry still routes passwords")
	}
}
