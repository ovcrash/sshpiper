package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func openTemp(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.db")
	db, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func testKeyPair(t *testing.T) (pub, priv string) {
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
	return string(ssh.MarshalAuthorizedKey(sp)), string(pem.EncodeToMemory(block))
}

func newPasswordEntry(ip string) NewEntry {
	return NewEntry{ExternalIP: ip, Username: "user1", BackendHost: "10.0.0.21", Password: "s3cret-pw"}
}

func TestCreateAndLookup(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)

	e, err := db.Create(ctx, newPasswordEntry("192.0.2.10"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if e.State != StateDraft || e.BackendPort != 22 || !e.AuthPassword || e.AuthKey {
		t.Fatalf("unexpected entry: %+v", e.Redacted())
	}

	got, err := db.ByExternalIP(ctx, "192.0.2.10")
	if err != nil || got.ID != e.ID {
		t.Fatalf("ByExternalIP: %v, %v", got, err)
	}
	// IPv4-mapped form must find the same entry
	if got, err := db.ByExternalIP(ctx, "::ffff:192.0.2.10"); err != nil || got.ID != e.ID {
		t.Fatalf("ByExternalIP mapped: %v, %v", got, err)
	}
	if _, err := db.ByExternalIP(ctx, "192.0.2.11"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown IP: err = %v, want ErrNotFound", err)
	}
	if _, err := db.ByExternalIP(ctx, "not-an-ip"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid IP: err = %v, want ErrNotFound", err)
	}

	evs, err := db.Events(ctx, e.ID)
	if err != nil || len(evs) != 1 || evs[0].Event != "created" {
		t.Fatalf("events = %+v, err = %v", evs, err)
	}
}

func TestUniqueExternalIP(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)

	if _, err := db.Create(ctx, newPasswordEntry("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Create(ctx, newPasswordEntry("192.0.2.10")); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate IP: err = %v, want ErrExists", err)
	}
	// same address written differently
	if _, err := db.Create(ctx, newPasswordEntry("::ffff:192.0.2.10")); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate mapped IP: err = %v, want ErrExists", err)
	}
}

func TestCreateValidation(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)
	pub, priv := testKeyPair(t)
	otherPub, _ := testKeyPair(t)

	cases := []struct {
		name   string
		mutate func(*NewEntry)
	}{
		{"bad ip", func(n *NewEntry) { n.ExternalIP = "999.1.1.1" }},
		{"unspecified ip", func(n *NewEntry) { n.ExternalIP = "0.0.0.0" }},
		{"empty user", func(n *NewEntry) { n.Username = "" }},
		{"space in user", func(n *NewEntry) { n.Username = "a b" }},
		{"empty backend", func(n *NewEntry) { n.BackendHost = " " }},
		{"bad port", func(n *NewEntry) { n.BackendPort = 70000 }},
		{"no method", func(n *NewEntry) { n.Password = "" }},
		{"public key only", func(n *NewEntry) { n.Password, n.PublicKey = "", pub }},
		{"private key only", func(n *NewEntry) { n.Password, n.PrivateKey = "", priv }},
		{"garbage public key", func(n *NewEntry) { n.Password, n.PublicKey, n.PrivateKey = "", "nope", priv }},
		{"garbage private key", func(n *NewEntry) { n.Password, n.PublicKey, n.PrivateKey = "", pub, "nope" }},
		{"mismatched pair", func(n *NewEntry) { n.Password, n.PublicKey, n.PrivateKey = "", otherPub, priv }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := newPasswordEntry("192.0.2.20")
			c.mutate(&n)
			if _, err := db.Create(ctx, n); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	n := newPasswordEntry("192.0.2.21")
	n.Password, n.PublicKey, n.PrivateKey = "", pub, priv
	e, err := db.Create(ctx, n)
	if err != nil {
		t.Fatalf("valid key entry: %v", err)
	}
	if e.AuthPassword || !e.AuthKey {
		t.Fatalf("flags = password %v key %v", e.AuthPassword, e.AuthKey)
	}
}

func TestStateTransitions(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)
	e, err := db.Create(ctx, newPasswordEntry("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}

	var te *TransitionError
	if err := db.SetState(ctx, e.ID, StateExposed, ""); !errors.As(err, &te) {
		t.Fatalf("draft -> exposed: err = %v, want TransitionError", err)
	}
	if err := db.SetState(ctx, e.ID, State("bogus"), ""); err == nil {
		t.Fatal("unknown state accepted")
	}

	for _, to := range []State{StateProbing, StateReady, StateExposed, StateNeedsCheck, StateProbing, StateReady, StateExposed, StateRetired} {
		if err := db.SetState(ctx, e.ID, to, "test"); err != nil {
			t.Fatalf("-> %s: %v", to, err)
		}
	}

	got, _ := db.ByID(ctx, e.ID)
	if got.State != StateRetired || got.RetiredAt == "" {
		t.Fatalf("after retire: state %s retired_at %q", got.State, got.RetiredAt)
	}
	if err := db.SetState(ctx, e.ID, StateProbing, ""); !errors.As(err, &te) {
		t.Fatalf("retired -> probing: err = %v, want TransitionError", err)
	}
	if err := db.SetState(ctx, 9999, StateProbing, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: err = %v, want ErrNotFound", err)
	}

	evs, _ := db.Events(ctx, e.ID)
	var names []string
	for _, ev := range evs {
		names = append(names, ev.Event)
	}
	if !strings.Contains(strings.Join(names, ","), "exposed") || names[len(names)-1] != "retired" {
		t.Fatalf("events = %v", names)
	}
}

func TestListFilter(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)
	a, _ := db.Create(ctx, newPasswordEntry("192.0.2.10"))
	_, _ = db.Create(ctx, newPasswordEntry("192.0.2.11"))
	_ = db.SetState(ctx, a.ID, StateProbing, "")

	all, _ := db.List(ctx)
	probing, _ := db.List(ctx, StateProbing)
	both, _ := db.List(ctx, StateProbing, StateDraft)
	if len(all) != 2 || len(probing) != 1 || probing[0].ID != a.ID || len(both) != 2 {
		t.Fatalf("all=%d probing=%d both=%d", len(all), len(probing), len(both))
	}
}

func TestFilePermissionsAndReopen(t *testing.T) {
	ctx := context.Background()
	db, path := openTemp(t)
	if _, err := db.Create(ctx, newPasswordEntry("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	_ = db.Close()

	db2, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	if list, _ := db2.List(ctx); len(list) != 1 {
		t.Fatalf("entries after reopen = %d", len(list))
	}
}

func TestReadOnly(t *testing.T) {
	ctx := context.Background()
	db, path := openTemp(t)
	if _, err := db.Create(ctx, newPasswordEntry("192.0.2.10")); err != nil {
		t.Fatal(err)
	}

	ro, err := Open(path, Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer ro.Close()
	if _, err := ro.ByExternalIP(ctx, "192.0.2.10"); err != nil {
		t.Fatalf("read-only lookup: %v", err)
	}
	if _, err := ro.Create(ctx, newPasswordEntry("192.0.2.11")); err == nil {
		t.Fatal("write through a read-only handle succeeded")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing.db"), Options{ReadOnly: true}); err == nil {
		t.Fatal("read-only open of a missing file succeeded")
	}
}

func TestConcurrentReadDuringWrite(t *testing.T) {
	ctx := context.Background()
	db, path := openTemp(t)
	if _, err := db.Create(ctx, newPasswordEntry("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	ro, err := Open(path, Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 40 {
			ip := "198.51.100." + itoa(i+1)
			if _, err := db.Create(ctx, newPasswordEntry(ip)); err != nil {
				errs <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			if _, err := ro.ByExternalIP(ctx, "192.0.2.10"); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent access: %v", err)
	}

	if v, err := ro.DataVersion(ctx); err != nil || v == 0 {
		t.Fatalf("DataVersion = %d, %v", v, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestSecretsNotPrinted(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)
	pub, priv := testKeyPair(t)
	n := newPasswordEntry("192.0.2.10")
	n.PublicKey, n.PrivateKey = pub, priv
	e, err := db.Create(ctx, n)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range []string{e.String(), e.Redacted().Password, e.Redacted().PrivateKey} {
		if strings.Contains(s, "s3cret-pw") || strings.Contains(s, "PRIVATE KEY") {
			t.Fatalf("secret leaked in %q", s)
		}
	}
}

func TestPersonaRoundTripAndHostKeys(t *testing.T) {
	ctx := context.Background()
	db, _ := openTemp(t)
	e, _ := db.Create(ctx, newPasswordEntry("192.0.2.10"))

	if _, err := db.Persona(ctx, e.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("persona before set: err = %v", err)
	}

	hk, err := GenerateHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := hk.Validate(); err != nil {
		t.Fatalf("generated keys invalid: %v", err)
	}

	p := Persona{EntryID: e.ID, SSHVersion: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20"}
	p.SetHostKeys(*hk)
	if err := db.SetPersona(ctx, p, "persona_generated", "test"); err != nil {
		t.Fatal(err)
	}
	// update in place
	p.SSHVersion = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.21"
	if err := db.SetPersona(ctx, p, "probed", ""); err != nil {
		t.Fatal(err)
	}

	got, err := db.Persona(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SSHVersion != p.SSHVersion || !got.HasHostKeys() {
		t.Fatalf("persona = %s", got)
	}
	if strings.Contains(got.String(), "PRIVATE KEY") {
		t.Fatal("persona String leaks a private key")
	}

	dir := filepath.Join(t.TempDir(), "keys")
	if err := ExportHostKeys(dir, got.HostKeys()); err != nil {
		t.Fatal(err)
	}
	if err := ExportHostKeys(dir, got.HostKeys()); err == nil {
		t.Fatal("export overwrote existing files")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(dir, "ssh_host_rsa_key")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode = %v", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Join(dir, "ssh_host_rsa_key.pub")); fi.Mode().Perm() != 0o644 {
			t.Fatalf("public key mode = %v", fi.Mode().Perm())
		}
	}
	imported, err := ImportHostKeys(dir)
	if err != nil || *imported != got.HostKeys() {
		t.Fatalf("import mismatch: %v", err)
	}
}
