package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/registry"
)

// run executes registryctl with args and returns what it wrote to stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	runErr := newApp().RunContext(context.Background(), append([]string{"registryctl"}, args...))
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

func TestAddListRetireWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "r.db")
	pw := filepath.Join(dir, "pw")
	if err := os.WriteFile(pw, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := run(t, "--registry", db, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	// a reader that stays open, as the daemon does
	ro, err := registry.Open(db, registry.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()

	if _, err := run(t, "--registry", db, "add", "--ip", "203.0.113.10", "--user", "alice", "--backend", "10.0.0.21", "--password-file", pw); err != nil {
		t.Fatalf("add: %v", err)
	}
	e, err := ro.ByExternalIP(context.Background(), "203.0.113.10")
	if err != nil || e.Password != "hunter2" || e.BackendPort != 22 {
		t.Fatalf("reader does not see the new entry: %v, %v", e, err)
	}

	if _, err := run(t, "--registry", db, "add", "--ip", "203.0.113.10", "--user", "x", "--backend", "h", "--password", "p"); err == nil {
		t.Fatal("duplicate IP accepted")
	}

	list, err := run(t, "--registry", db, "list")
	if err != nil || !strings.Contains(list, "203.0.113.10") || !strings.Contains(list, "draft") {
		t.Fatalf("list = %q, %v", list, err)
	}
	if strings.Contains(list, "hunter2") {
		t.Fatal("list leaks the password")
	}

	if _, err := run(t, "--registry", db, "retire", "--ip", "203.0.113.10"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	e, _ = ro.ByExternalIP(context.Background(), "203.0.113.10")
	if e.State != registry.StateRetired {
		t.Fatalf("reader sees state %s after retire", e.State)
	}
}

func TestExportSecrets(t *testing.T) {
	db := filepath.Join(t.TempDir(), "r.db")
	if _, err := run(t, "--registry", db, "add", "--ip", "203.0.113.10", "--user", "alice", "--backend", "h", "--password", "hunter2"); err != nil {
		t.Fatal(err)
	}

	plain, err := run(t, "--registry", db, "export")
	if err != nil || strings.Contains(plain, "hunter2") {
		t.Fatalf("default export leaks or fails: %v\n%s", err, plain)
	}
	full, err := run(t, "--registry", db, "export", "--with-secrets")
	if err != nil || !strings.Contains(full, "hunter2") {
		t.Fatalf("--with-secrets export lacks the password: %v", err)
	}
}

func TestExposeNeedsReady(t *testing.T) {
	db := filepath.Join(t.TempDir(), "r.db")
	if _, err := run(t, "--registry", db, "add", "--ip", "203.0.113.10", "--user", "alice", "--backend", "h", "--password", "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "--registry", db, "expose", "--ip", "203.0.113.10"); err == nil {
		t.Fatal("a draft entry was exposed")
	}
}

func TestPersonaExportKeys(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "r.db")
	keys := filepath.Join(dir, "keys")
	if _, err := run(t, "--registry", db, "add", "--ip", "203.0.113.10", "--user", "alice", "--backend", "h", "--password", "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "--registry", db, "persona", "export-keys", "--id", "1", "--dir", keys); err == nil {
		t.Fatal("export before gen succeeded")
	}
	if _, err := run(t, "--registry", db, "persona", "gen", "--id", "1"); err != nil {
		t.Fatalf("gen: %v", err)
	}
	if _, err := run(t, "--registry", db, "persona", "gen", "--id", "1"); err == nil {
		t.Fatal("gen replaced existing keys without --force")
	}
	if _, err := run(t, "--registry", db, "persona", "export-keys", "--id", "1", "--dir", keys); err != nil {
		t.Fatalf("export-keys: %v", err)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(keys, "ssh_host_ed25519_key"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("private key file: %v, %v", fi, err)
		}
	}
	if _, err := run(t, "--registry", db, "persona", "import", "--id", "1", "--from", keys); err != nil {
		t.Fatalf("import: %v", err)
	}
}
