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

func TestMigrationV1toV2PreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	ctx := context.Background()

	// open at v1 only, populate, then migrate to v2 on reopen
	saved := migrations
	migrations = migrations[:1]
	defer func() { migrations = saved }()

	db, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := db.Create(ctx, newPasswordEntry("192.0.2.40"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Create(ctx, newPasswordEntry("192.0.2.41")); err != nil {
		t.Fatal(err)
	}
	// give a a persona and retire it, to exercise FK rows across the rebuild
	hk, _ := GenerateHostKeys()
	p := &Persona{EntryID: a.ID}
	p.SetHostKeys(*hk)
	if err := db.SetPersona(ctx, *p, "persona_generated", "x"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetState(ctx, a.ID, StateRetired, "test"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// reopen with the full migration set -> runs v2 (table rebuild)
	migrations = saved
	db2, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("migrate v1->v2: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	// rows preserved, ids intact, persona FK still resolves
	all, err := db2.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("after migration: %d entries, want 2", len(all))
	}
	if _, err := db2.Persona(ctx, a.ID); err != nil {
		t.Errorf("persona lost across migration: %v", err)
	}
	// the v2 partial index now allows reusing the retired IP
	if _, err := db2.Create(ctx, newPasswordEntry("192.0.2.40")); err != nil {
		t.Errorf("reuse retired IP after migration: %v", err)
	}
}
