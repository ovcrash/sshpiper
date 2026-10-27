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
	ed, ec, rsa := authKeys(t, hk)
	for _, e := range []*registry.Entry{pw, ke} {
		// the backend's captured public host keys (the pin, per account)
		if err := rw.SetBackendHostKeys(ctx, e.ID, ed, ec, rsa); err != nil {
			t.Fatal(err)
		}
		// the site persona presented on the IP (shared, with the offered methods)
		p := registry.Persona{AuthMethods: "publickey,password"}
		p.SetHostKeys(*hk)
		if err := rw.SetSitePersona(ctx, e.ExternalIP, p); err != nil {
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

// authKeys returns the authorized-key public lines of host key set hk, as the
// backend would present them (captured at probe).
func authKeys(t *testing.T, hk *registry.HostKeys) (ed, ec, rsa string) {
	t.Helper()
	conv := func(priv string) string {
		s, err := ssh.ParsePrivateKey([]byte(priv))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	}
	return conv(hk.ED25519), conv(hk.ECDSA), conv(hk.RSA)
}

func TestPasswordForwardedAsTyped(t *testing.T) {
	f := newFixture(t)

	// the account's user authenticates; the typed password is forwarded as-is
	u, err := f.r.password(connTo("alice", "192.0.2.10:22"), []byte("whatever-was-typed"))
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if u.UserName != "alice" || u.Uri != "tcp://10.0.0.21:22" {
		t.Errorf("UserName=%q Uri=%q", u.UserName, u.Uri)
	}
	if got := u.GetPassword().GetPassword(); got != "whatever-was-typed" {
		t.Errorf("password = %q", got)
	}

	// the stored password is never used for password logins
	if strings.Contains(u.GetPassword().GetPassword(), "s3cret") {
		t.Error("stored password leaked into a login attempt")
	}

	// an unknown user on the same IP fails exactly like a wrong credential
	for _, user := range []string{"root", "nosuchuser"} {
		if _, err := f.r.password(connTo(user, "192.0.2.10:22"), []byte("x")); err == nil {
			t.Errorf("unknown user %q was served", user)
		}
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

	// the site persona's methods are offered, the same for every username
	for _, dst := range []string{"192.0.2.10:22", "192.0.2.11:22"} {
		for _, user := range []string{"alice", "bob", "nosuchuser"} {
			got, err := f.r.nextAuthMethods(connTo(user, dst))
			if err != nil || strings.Join(got, ",") != "publickey,password" {
				t.Errorf("%s as %q: %v, %v", dst, user, got, err)
			}
		}
	}

	ctx := context.Background()
	// a site persona with a single method restricts the offer
	e, err := f.rw.Create(ctx, registry.NewEntry{ExternalIP: "192.0.2.20", Username: "u", BackendHost: "h", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []registry.State{registry.StateProbing, registry.StateReady} {
		_ = f.rw.SetState(ctx, e.ID, s, "")
	}
	if err := f.rw.SetSitePersona(ctx, "192.0.2.20", registry.Persona{AuthMethods: "password"}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.r.nextAuthMethods(connTo("", "192.0.2.20:22")); err != nil || strings.Join(got, ",") != "password" {
		t.Errorf("single-method site: %v, %v", got, err)
	}

	// an IP with a servable account but no site persona offers the generic set
	e2, err := f.rw.Create(ctx, registry.NewEntry{ExternalIP: "192.0.2.21", Username: "u", BackendHost: "h", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []registry.State{registry.StateProbing, registry.StateReady} {
		_ = f.rw.SetState(ctx, e2.ID, s, "")
	}
	if got, err := f.r.nextAuthMethods(connTo("", "192.0.2.21:22")); err != nil || strings.Join(got, ",") != "password,publickey" {
		t.Errorf("no-persona site fallback: %v, %v", got, err)
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
