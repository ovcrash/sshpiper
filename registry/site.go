package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// A "site" is the identity presented on an external IP: one persona (host keys,
// version, algorithms) shared by every account on that IP, because SSH presents
// host keys at KEX before the username is known. Accounts (entries keyed by
// (external_ip, username)) route after authentication. The site persona reuses
// the Persona type; its EntryID field is unused (0).

const sitePersonaColumns = `COALESCE(ssh_version,''), COALESCE(host_key_ed25519,''), COALESCE(host_key_ecdsa,''),
	COALESCE(host_key_rsa,''), COALESCE(kex,''), COALESCE(host_key_algs,''), COALESCE(ciphers,''),
	COALESCE(macs,''), COALESCE(compression,''), COALESCE(auth_methods,''), COALESCE(hassh_server,''),
	COALESCE(probe_hash,''), COALESCE(probed_at,'')`

// SitePersona returns the persona presented on an external IP, or ErrNotFound.
func (db *DB) SitePersona(ctx context.Context, ip string) (*Persona, error) {
	norm, err := NormalizeIP(ip)
	if err != nil {
		return nil, ErrNotFound
	}
	var p Persona
	err = db.sql.QueryRowContext(ctx, "SELECT "+sitePersonaColumns+" FROM site_personas WHERE external_ip = ?", norm).Scan(
		&p.SSHVersion, &p.HostKeyED25519, &p.HostKeyECDSA, &p.HostKeyRSA, &p.Kex, &p.HostKeyAlgs,
		&p.Ciphers, &p.MACs, &p.Compression, &p.AuthMethods, &p.HASSHServer, &p.ProbeHash, &p.ProbedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return &p, nil
}

// SetSitePersona inserts or replaces the persona presented on an external IP.
func (db *DB) SetSitePersona(ctx context.Context, ip string, p Persona) error {
	if err := db.writable(); err != nil {
		return err
	}
	norm, err := NormalizeIP(ip)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO site_personas
		(external_ip, ssh_version, host_key_ed25519, host_key_ecdsa, host_key_rsa, kex, host_key_algs, ciphers,
		 macs, compression, auth_methods, hassh_server, probe_hash, probed_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(external_ip) DO UPDATE SET
		 ssh_version=excluded.ssh_version, host_key_ed25519=excluded.host_key_ed25519,
		 host_key_ecdsa=excluded.host_key_ecdsa, host_key_rsa=excluded.host_key_rsa, kex=excluded.kex,
		 host_key_algs=excluded.host_key_algs, ciphers=excluded.ciphers, macs=excluded.macs,
		 compression=excluded.compression, auth_methods=excluded.auth_methods,
		 hassh_server=excluded.hassh_server, probe_hash=excluded.probe_hash, probed_at=excluded.probed_at,
		 updated_at=excluded.updated_at`,
		norm, nullable(p.SSHVersion), nullable(p.HostKeyED25519), nullable(p.HostKeyECDSA), nullable(p.HostKeyRSA),
		nullable(p.Kex), nullable(p.HostKeyAlgs), nullable(p.Ciphers), nullable(p.MACs), nullable(p.Compression),
		nullable(p.AuthMethods), nullable(p.HASSHServer), nullable(p.ProbeHash), nullable(p.ProbedAt), now())
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	return nil
}

// SiteRoute is the connection-path view of an external IP: whether it can be
// served and a cache key that changes when the persona or any account changes.
type SiteRoute struct {
	Servable bool // at least one exposed account
	Ready    bool // at least one ready account (served only to verify sources)
	CacheKey string
}

// SiteByExternalIP reports how an external IP can be served. ErrNotFound when
// the IP has no account and no persona.
func (db *DB) SiteByExternalIP(ctx context.Context, ip string) (*SiteRoute, error) {
	norm, err := NormalizeIP(ip)
	if err != nil {
		return nil, ErrNotFound
	}
	var exposed, ready int
	var entriesKey, personaKey string
	var accounts int
	err = db.sql.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN state='exposed' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN state='ready' THEN 1 ELSE 0 END),0),
		COUNT(*),
		COALESCE(MAX(updated_at),'')
		FROM entries WHERE external_ip = ? AND state != 'retired'`, norm).Scan(&exposed, &ready, &accounts, &entriesKey)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	_ = db.sql.QueryRowContext(ctx, "SELECT COALESCE(MAX(updated_at),'') FROM site_personas WHERE external_ip = ?", norm).Scan(&personaKey)
	if accounts == 0 && personaKey == "" {
		return nil, ErrNotFound
	}
	return &SiteRoute{
		Servable: exposed > 0,
		Ready:    ready > 0,
		CacheKey: personaKey + "|" + entriesKey,
	}, nil
}
