package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Entry maps one external IP to one backend machine and one credential set.
// Password and PrivateKey are secrets: use Redacted for display.
type Entry struct {
	ID           int64
	ExternalIP   string
	Username     string
	AuthPassword bool
	Password     string
	AuthKey      bool
	PublicKey    string
	PrivateKey   string
	BackendHost  string
	BackendPort  int
	State        State
	CreatedAt    string
	UpdatedAt    string
	RetiredAt    string
}

// Redacted returns a copy without secrets.
func (e Entry) Redacted() Entry {
	if e.Password != "" {
		e.Password = "***"
	}
	if e.PrivateKey != "" {
		e.PrivateKey = "***"
	}
	return e
}

// String never prints secrets.
func (e Entry) String() string {
	return fmt.Sprintf("entry %d %s -> %s:%d user=%s state=%s", e.ID, e.ExternalIP, e.BackendHost, e.BackendPort, e.Username, e.State)
}

// NewEntry is the input of Create.
type NewEntry struct {
	ExternalIP  string
	Username    string
	BackendHost string
	BackendPort int // 0 means 22
	Password    string
	PublicKey   string
	PrivateKey  string
}

// Event is a line of the audit trail of registry changes.
type Event struct {
	ID      int64
	EntryID int64
	Event   string
	At      string
	Detail  string
}

var (
	// ErrNotFound is returned when an entry does not exist.
	ErrNotFound = errors.New("registry: not found")
	// ErrExists is returned when the external IP is already registered
	// (retired entries keep their IP).
	ErrExists = errors.New("registry: external IP already registered")
)

// stateEvents names the event recorded for the states that have one in the
// data model; other moves are recorded as state_<name>.
var stateEvents = map[State]string{
	StateExposed:    "exposed",
	StateRetired:    "retired",
	StateNeedsCheck: "needs_check",
}

const entryColumns = `id, external_ip, username, auth_password, COALESCE(password,''), auth_key,
	COALESCE(public_key,''), COALESCE(private_key,''), backend_host, backend_port, state,
	created_at, updated_at, COALESCE(retired_at,'')`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEntry(r rowScanner) (*Entry, error) {
	var e Entry
	var ap, ak int
	var state string
	if err := r.Scan(&e.ID, &e.ExternalIP, &e.Username, &ap, &e.Password, &ak, &e.PublicKey, &e.PrivateKey,
		&e.BackendHost, &e.BackendPort, &state, &e.CreatedAt, &e.UpdatedAt, &e.RetiredAt); err != nil {
		return nil, err
	}
	e.AuthPassword = ap != 0
	e.AuthKey = ak != 0
	e.State = State(state)
	return &e, nil
}

// Create validates and inserts a new entry in state draft.
func (db *DB) Create(ctx context.Context, n NewEntry) (*Entry, error) {
	if err := db.writable(); err != nil {
		return nil, err
	}
	if n.BackendPort == 0 {
		n.BackendPort = 22
	}
	ip, err := n.Validate()
	if err != nil {
		return nil, err
	}

	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	ts := now()
	res, err := tx.ExecContext(ctx, `INSERT INTO entries
		(external_ip, username, auth_password, password, auth_key, public_key, private_key,
		 backend_host, backend_port, state, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ip, n.Username, b2i(n.Password != ""), nullable(n.Password), b2i(n.PublicKey != ""),
		nullable(n.PublicKey), nullable(n.PrivateKey), strings.TrimSpace(n.BackendHost), n.BackendPort,
		string(StateDraft), ts, ts)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("%w: %s", ErrExists, ip)
		}
		return nil, fmt.Errorf("registry: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	if err := addEvent(ctx, tx, id, "created", ip); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}

	return db.ByID(ctx, id)
}

// ByID returns an entry or ErrNotFound.
func (db *DB) ByID(ctx context.Context, id int64) (*Entry, error) {
	return db.one(ctx, "SELECT "+entryColumns+" FROM entries WHERE id = ?", id)
}

// ByExternalIP returns the entry for an IP (any form accepted by
// NormalizeIP) or ErrNotFound.
func (db *DB) ByExternalIP(ctx context.Context, ip string) (*Entry, error) {
	norm, err := NormalizeIP(ip)
	if err != nil {
		return nil, ErrNotFound
	}
	// An IP can carry one live entry plus retired ones (after reuse). Prefer
	// the live entry, else the most recently updated retired one.
	return db.one(ctx, "SELECT "+entryColumns+" FROM entries WHERE external_ip = ? "+
		"ORDER BY (state = 'retired'), updated_at DESC LIMIT 1", norm)
}

func (db *DB) one(ctx context.Context, query string, args ...any) (*Entry, error) {
	e, err := scanEntry(db.sql.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return e, nil
}

// Route is the part of an entry needed to decide, per connection, whether to
// serve an address. It carries no secrets.
type Route struct {
	ID        int64
	State     State
	UpdatedAt string
}

// RouteByExternalIP is a light lookup for the connection path. It returns
// ErrNotFound for unknown or invalid addresses.
func (db *DB) RouteByExternalIP(ctx context.Context, ip string) (*Route, error) {
	norm, err := NormalizeIP(ip)
	if err != nil {
		return nil, ErrNotFound
	}
	var r Route
	var state string
	err = db.sql.QueryRowContext(ctx, "SELECT id, state, updated_at FROM entries WHERE external_ip = ? "+
		"ORDER BY (state = 'retired'), updated_at DESC LIMIT 1", norm).Scan(&r.ID, &state, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	r.State = State(state)
	return &r, nil
}

// List returns entries ordered by id, optionally limited to some states.
func (db *DB) List(ctx context.Context, states ...State) ([]*Entry, error) {
	query := "SELECT " + entryColumns + " FROM entries"
	var args []any
	if len(states) > 0 {
		marks := make([]string, len(states))
		for i, s := range states {
			marks[i] = "?"
			args = append(args, string(s))
		}
		query += " WHERE state IN (" + strings.Join(marks, ",") + ")"
	}
	query += " ORDER BY id"

	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	defer rows.Close()

	var out []*Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("registry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetState moves an entry to a new state if the transition is allowed and
// records an event.
func (db *DB) SetState(ctx context.Context, id int64, to State, detail string) error {
	if err := db.writable(); err != nil {
		return err
	}
	if !to.Valid() {
		return fmt.Errorf("registry: unknown state %q", to)
	}

	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var from string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM entries WHERE id = ?", id).Scan(&from); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if !State(from).CanMoveTo(to) {
		return &TransitionError{From: State(from), To: to}
	}

	ts := now()
	// retired_at: set it when retiring, clear it when reactivating (leaving
	// retired), keep it unchanged otherwise.
	var query string
	var args []any
	switch {
	case to == StateRetired:
		query = "UPDATE entries SET state = ?, updated_at = ?, retired_at = ? WHERE id = ?"
		args = []any{string(to), ts, ts, id}
	case State(from) == StateRetired:
		query = "UPDATE entries SET state = ?, updated_at = ?, retired_at = NULL WHERE id = ?"
		args = []any{string(to), ts, id}
	default:
		query = "UPDATE entries SET state = ?, updated_at = ? WHERE id = ?"
		args = []any{string(to), ts, id}
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("%w: external IP already in use by a live entry", ErrExists)
		}
		return fmt.Errorf("registry: %w", err)
	}

	event, ok := stateEvents[to]
	if !ok {
		event = "state_" + string(to)
	}
	if err := addEvent(ctx, tx, id, event, detail); err != nil {
		return err
	}

	return tx.Commit()
}

// AddEvent appends a free-form event to an entry.
func (db *DB) AddEvent(ctx context.Context, id int64, event, detail string) error {
	if err := db.writable(); err != nil {
		return err
	}
	return addEvent(ctx, db.sql, id, event, detail)
}

// Events returns the events of an entry, oldest first.
func (db *DB) Events(ctx context.Context, id int64) ([]Event, error) {
	rows, err := db.sql.QueryContext(ctx,
		"SELECT id, entry_id, event, at, COALESCE(detail,'') FROM registry_events WHERE entry_id = ? ORDER BY id", id)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.EntryID, &e.Event, &e.At, &e.Detail); err != nil {
			return nil, fmt.Errorf("registry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func addEvent(ctx context.Context, x execer, id int64, event, detail string) error {
	if _, err := x.ExecContext(ctx, "INSERT INTO registry_events (entry_id, event, at, detail) VALUES (?,?,?,?)",
		id, event, now(), nullable(detail)); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
