package registry

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// retire takes a fresh draft entry straight to retired (draft -> retired is allowed).
func retire(t *testing.T, db *DB, id int64) {
	t.Helper()
	if err := db.SetState(context.Background(), id, StateRetired, "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}
}

func TestReuseIPAfterRetire(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()

	a, err := db.Create(ctx, newPasswordEntry("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	// a second live entry on the same IP is still refused
	if _, err := db.Create(ctx, newPasswordEntry("192.0.2.10")); !errors.Is(err, ErrExists) {
		t.Fatalf("second live entry on same IP: want ErrExists, got %v", err)
	}

	retire(t, db, a.ID)

	// now the address is free for a new entry
	b, err := db.Create(ctx, newPasswordEntry("192.0.2.10"))
	if err != nil {
		t.Fatalf("reuse IP after retire: %v", err)
	}
	if b.ID == a.ID {
		t.Fatal("expected a new row, got the retired one")
	}

	// ByExternalIP returns the live one (b), not the retired a
	got, err := db.ByExternalIP(ctx, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != b.ID || got.State != StateDraft {
		t.Errorf("ByExternalIP returned id=%d state=%s, want live b=%d", got.ID, got.State, b.ID)
	}
}

func TestReactivate(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()

	e, err := db.Create(ctx, newPasswordEntry("192.0.2.20"))
	if err != nil {
		t.Fatal(err)
	}
	retire(t, db, e.ID)

	// reactivate: retired -> draft, retired_at cleared
	if err := db.SetState(ctx, e.ID, StateDraft, "reactivated"); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	got, err := db.ByID(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateDraft {
		t.Errorf("state = %s, want draft", got.State)
	}
	if got.RetiredAt != "" {
		t.Errorf("retired_at = %q, want cleared", got.RetiredAt)
	}

	// and the normal flow works again from draft
	for _, to := range []State{StateProbing, StateReady, StateExposed} {
		if err := db.SetState(ctx, e.ID, to, "test"); err != nil {
			t.Fatalf("reactivated -> %s: %v", to, err)
		}
	}
}

func TestReactivateConflictsWithLiveIP(t *testing.T) {
	db, _ := openTemp(t)
	ctx := context.Background()

	a, _ := db.Create(ctx, newPasswordEntry("192.0.2.30"))
	retire(t, db, a.ID)
	b, err := db.Create(ctx, newPasswordEntry("192.0.2.30")) // reuse the freed IP
	if err != nil {
		t.Fatal(err)
	}
	_ = b

	// reactivating a now collides with the live entry b on the same IP
	if err := db.SetState(ctx, a.ID, StateDraft, "reactivated"); !errors.Is(err, ErrExists) {
		t.Fatalf("reactivate over a live IP: want ErrExists, got %v", err)
	}
}

func TestMigrationV2toV3PreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	ctx := context.Background()

	hk, err := GenerateHostKeys()
	if err != nil {
		t.Fatal(err)
	}

	// Open at v2 (no backend_hostkey columns, IP-unique), insert an entry and
	// its persona with raw SQL (the v2 schema), then migrate to v3 on reopen.
	saved := migrations
	migrations = migrations[:2]
	db, err := Open(path, Options{})
	if err != nil {
		migrations = saved
		t.Fatal(err)
	}
	ts := now()
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO entries
		(id, external_ip, username, auth_password, password, auth_key, backend_host, backend_port, state, created_at, updated_at)
		VALUES (1,'192.0.2.40','alice',1,'pw',0,'10.0.0.21',22,'exposed',?,?)`, ts, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO personas
		(entry_id, ssh_version, host_key_ed25519, host_key_ecdsa, host_key_rsa, auth_methods, probed_at)
		VALUES (1,'SSH-2.0-OpenSSH_9.6',?,?,?,'password',?)`, hk.ED25519, hk.ECDSA, hk.RSA, ts); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	migrations = saved

	db2, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("migrate v2->v3: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	// the account is preserved, and its backend host keys were backfilled from
	// the persona's private keys (the public parts)
	e, err := db2.ByID(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if e.BackendHostED25519 == "" || e.BackendHostECDSA == "" || e.BackendHostRSA == "" {
		t.Errorf("backend host keys not backfilled: %+v", e)
	}
	// the site persona was created for the IP, with the presented host keys
	sp, err := db2.SitePersona(ctx, "192.0.2.40")
	if err != nil {
		t.Fatalf("site persona missing: %v", err)
	}
	if !sp.HasHostKeys() || sp.SSHVersion != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("site persona wrong: %+v", sp)
	}
	// (IP, user) uniqueness: a second user on the same IP is allowed
	if _, err := db2.Create(ctx, NewEntry{ExternalIP: "192.0.2.40", Username: "bob", BackendHost: "10.0.0.21", Password: "pw"}); err != nil {
		t.Errorf("second user on same IP should be allowed: %v", err)
	}
	// but the same (IP, user) twice is refused
	if _, err := db2.Create(ctx, NewEntry{ExternalIP: "192.0.2.40", Username: "bob", BackendHost: "10.0.0.21", Password: "pw"}); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate (IP,user): want ErrExists, got %v", err)
	}
}
