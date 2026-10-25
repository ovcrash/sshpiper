package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Persona is the identity presented on an external IP: the host keys
// (private, PEM OpenSSH) and what was read from the backend.
type Persona struct {
	EntryID        int64
	SSHVersion     string
	HostKeyED25519 string
	HostKeyECDSA   string
	HostKeyRSA     string
	Kex            string
	HostKeyAlgs    string
	Ciphers        string
	MACs           string
	Compression    string
	AuthMethods    string
	HASSHServer    string
	ProbeHash      string
	ProbedAt       string
}

// HasHostKeys reports whether the three host keys are present.
func (p *Persona) HasHostKeys() bool {
	return p.HostKeyED25519 != "" && p.HostKeyECDSA != "" && p.HostKeyRSA != ""
}

// String never prints the private host keys.
func (p Persona) String() string {
	return fmt.Sprintf("persona entry=%d version=%q hassh_server=%s", p.EntryID, p.SSHVersion, p.HASSHServer)
}

const personaColumns = `entry_id, COALESCE(ssh_version,''), COALESCE(host_key_ed25519,''), COALESCE(host_key_ecdsa,''),
	COALESCE(host_key_rsa,''), COALESCE(kex,''), COALESCE(host_key_algs,''), COALESCE(ciphers,''),
	COALESCE(macs,''), COALESCE(compression,''), COALESCE(auth_methods,''), COALESCE(hassh_server,''),
	COALESCE(probe_hash,''), COALESCE(probed_at,'')`

// Persona returns the persona of an entry, or ErrNotFound.
func (db *DB) Persona(ctx context.Context, entryID int64) (*Persona, error) {
	var p Persona
	err := db.sql.QueryRowContext(ctx, "SELECT "+personaColumns+" FROM personas WHERE entry_id = ?", entryID).Scan(
		&p.EntryID, &p.SSHVersion, &p.HostKeyED25519, &p.HostKeyECDSA, &p.HostKeyRSA, &p.Kex, &p.HostKeyAlgs,
		&p.Ciphers, &p.MACs, &p.Compression, &p.AuthMethods, &p.HASSHServer, &p.ProbeHash, &p.ProbedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return &p, nil
}

// SetPersona inserts or replaces the persona of an entry. detail is stored
// in the event log (event persona_generated, or probed when probed_at is set).
func (db *DB) SetPersona(ctx context.Context, p Persona, event, detail string) error {
	if err := db.writable(); err != nil {
		return err
	}

	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `INSERT INTO personas
		(entry_id, ssh_version, host_key_ed25519, host_key_ecdsa, host_key_rsa, kex, host_key_algs, ciphers,
		 macs, compression, auth_methods, hassh_server, probe_hash, probed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(entry_id) DO UPDATE SET
		 ssh_version=excluded.ssh_version, host_key_ed25519=excluded.host_key_ed25519,
		 host_key_ecdsa=excluded.host_key_ecdsa, host_key_rsa=excluded.host_key_rsa, kex=excluded.kex,
		 host_key_algs=excluded.host_key_algs, ciphers=excluded.ciphers, macs=excluded.macs,
		 compression=excluded.compression, auth_methods=excluded.auth_methods,
		 hassh_server=excluded.hassh_server, probe_hash=excluded.probe_hash, probed_at=excluded.probed_at`,
		p.EntryID, nullable(p.SSHVersion), nullable(p.HostKeyED25519), nullable(p.HostKeyECDSA),
		nullable(p.HostKeyRSA), nullable(p.Kex), nullable(p.HostKeyAlgs), nullable(p.Ciphers), nullable(p.MACs),
		nullable(p.Compression), nullable(p.AuthMethods), nullable(p.HASSHServer), nullable(p.ProbeHash),
		nullable(p.ProbedAt)); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE entries SET updated_at = ? WHERE id = ?", now(), p.EntryID); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if err := addEvent(ctx, tx, p.EntryID, event, detail); err != nil {
		return err
	}

	return tx.Commit()
}
