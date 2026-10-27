// Package registry stores the routing table of the relay in a SQLite file:
// one entry per external IP, its identity ("persona") and an event log.
//
// The file holds secrets in clear text and is created with mode 0600. Only
// registryctl writes to it; the daemon and the plugin open it read-only.
package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, no CGO
)

// DB is an open registry.
type DB struct {
	sql      *sql.DB
	path     string
	readOnly bool
}

// Options configure Open.
type Options struct {
	// ReadOnly opens an existing file without write access or migrations.
	ReadOnly bool
}

// Open opens the registry at path. A missing file is created (mode 0600) and
// migrated unless opts.ReadOnly is set.
func Open(path string, opts Options) (*DB, error) {
	if path == "" {
		return nil, errors.New("registry: empty path")
	}

	if opts.ReadOnly {
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("registry: %w", err)
		}
	} else {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("registry: %w", err)
		}
		_ = f.Close()
		_ = os.Chmod(path, 0o600)
	}

	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	if opts.ReadOnly {
		q.Set("mode", "ro")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
	}
	dsn := (&url.URL{Scheme: "file", Opaque: url.PathEscape(path), RawQuery: q.Encode()}).String()

	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	if opts.ReadOnly {
		sdb.SetMaxOpenConns(4)
	} else {
		// one writer at a time; readers use their own handles
		sdb.SetMaxOpenConns(1)
	}

	db := &DB{sql: sdb, path: path, readOnly: opts.ReadOnly}
	if err := sdb.PingContext(context.Background()); err != nil {
		_ = sdb.Close()
		return nil, fmt.Errorf("registry: %w", err)
	}
	if !opts.ReadOnly {
		if err := db.migrate(context.Background()); err != nil {
			_ = sdb.Close()
			return nil, err
		}
	}

	return db, nil
}

// Close releases the database.
func (db *DB) Close() error { return db.sql.Close() }

// Path returns the file path given to Open.
func (db *DB) Path() string { return db.path }

// DataVersion returns SQLite's PRAGMA data_version, which changes when
// another connection modifies the file. Callers can poll it to invalidate
// caches cheaply.
func (db *DB) DataVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := db.sql.QueryRowContext(ctx, "PRAGMA data_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("registry: %w", err)
	}
	return v, nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

var migrations = []string{
	// v1
	`CREATE TABLE entries (
		id            INTEGER PRIMARY KEY,
		external_ip   TEXT    NOT NULL UNIQUE,
		username      TEXT    NOT NULL,
		auth_password INTEGER NOT NULL DEFAULT 0,
		password      TEXT,
		auth_key      INTEGER NOT NULL DEFAULT 0,
		public_key    TEXT,
		private_key   TEXT,
		backend_host  TEXT    NOT NULL,
		backend_port  INTEGER NOT NULL DEFAULT 22,
		state         TEXT    NOT NULL CHECK (state IN ('draft','probing','ready','exposed','retired','needs_check')),
		created_at    TEXT    NOT NULL,
		updated_at    TEXT    NOT NULL,
		retired_at    TEXT
	);
	CREATE TABLE personas (
		entry_id         INTEGER PRIMARY KEY REFERENCES entries(id),
		ssh_version      TEXT,
		host_key_ed25519 TEXT,
		host_key_ecdsa   TEXT,
		host_key_rsa     TEXT,
		kex              TEXT,
		host_key_algs    TEXT,
		ciphers          TEXT,
		macs             TEXT,
		compression      TEXT,
		auth_methods     TEXT,
		hassh_server     TEXT,
		probe_hash       TEXT,
		probed_at        TEXT
	);
	CREATE TABLE registry_events (
		id       INTEGER PRIMARY KEY,
		entry_id INTEGER REFERENCES entries(id),
		event    TEXT NOT NULL,
		at       TEXT NOT NULL,
		detail   TEXT
	);
	CREATE INDEX registry_events_entry ON registry_events(entry_id);`,

	// v2: drop the column-level UNIQUE on external_ip and replace it with a
	// partial unique index that only covers live (non-retired) entries, so the
	// address of a retired entry can be reused by a new one while the retired
	// row is kept for history. SQLite cannot drop an inline UNIQUE, so the
	// table is rebuilt; ids are preserved, keeping the personas/events FKs
	// valid. migrate() runs this with foreign_keys OFF (see below).
	`CREATE TABLE entries_new (
		id            INTEGER PRIMARY KEY,
		external_ip   TEXT    NOT NULL,
		username      TEXT    NOT NULL,
		auth_password INTEGER NOT NULL DEFAULT 0,
		password      TEXT,
		auth_key      INTEGER NOT NULL DEFAULT 0,
		public_key    TEXT,
		private_key   TEXT,
		backend_host  TEXT    NOT NULL,
		backend_port  INTEGER NOT NULL DEFAULT 22,
		state         TEXT    NOT NULL CHECK (state IN ('draft','probing','ready','exposed','retired','needs_check')),
		created_at    TEXT    NOT NULL,
		updated_at    TEXT    NOT NULL,
		retired_at    TEXT
	);
	INSERT INTO entries_new SELECT * FROM entries;
	DROP TABLE entries;
	ALTER TABLE entries_new RENAME TO entries;
	CREATE UNIQUE INDEX entries_live_ip ON entries(external_ip) WHERE state != 'retired';`,
}

func (db *DB) migrate(ctx context.Context) error {
	var version int
	if err := db.sql.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("registry: database version %d is newer than this program (%d)", version, len(migrations))
	}
	if version == len(migrations) {
		return nil
	}

	// Run migrations on a dedicated connection with foreign_keys OFF: a
	// migration may rebuild a referenced table (DROP + RENAME), which the FK
	// enforcement enabled in the DSN would otherwise block. foreign_keys
	// cannot be toggled inside a transaction, so it is set on the connection
	// around the transactions. With MaxOpenConns(1) this same connection is
	// reused afterwards, so it is restored to ON before being released.
	conn, err := db.sql.Conn(ctx)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(ctx, "PRAGMA foreign_keys = ON")
		_ = conn.Close()
	}()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("registry: %w", err)
	}

	for v := version; v < len(migrations); v++ {
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("registry: %w", err)
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("registry: migration %d: %w", v+1, err)
		}
		// PRAGMA does not accept bound parameters
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("registry: migration %d: %w", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("registry: migration %d: %w", v+1, err)
		}
	}

	// Verify the rebuild left no dangling references.
	rows, err := conn.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("registry: foreign key check failed after migration")
	}
	return nil
}

func (db *DB) writable() error {
	if db.readOnly {
		return errors.New("registry: opened read-only")
	}
	return nil
}
