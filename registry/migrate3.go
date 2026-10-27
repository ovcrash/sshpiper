package registry

import (
	"context"
	"database/sql"
	"strings"

	"golang.org/x/crypto/ssh"
)

// migrateV3 backfills each account's backend public host keys from the existing
// per-entry persona. Before v3 the persona private host keys were installed on
// the backend, so the backend's public keys equal the public parts of those
// private keys — which is exactly what the known_hosts pin needs. This keeps
// the proxy->backend pin working unchanged after the schema split.
func migrateV3(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT p.entry_id,
		COALESCE(p.host_key_ed25519,''), COALESCE(p.host_key_ecdsa,''), COALESCE(p.host_key_rsa,'')
		FROM personas p`)
	if err != nil {
		return err
	}
	type keys struct {
		id          int64
		ed, ec, rsa string
	}
	var items []keys
	for rows.Next() {
		var k keys
		if err := rows.Scan(&k.id, &k.ed, &k.ec, &k.rsa); err != nil {
			_ = rows.Close()
			return err
		}
		items = append(items, k)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, k := range items {
		if _, err := tx.ExecContext(ctx,
			"UPDATE entries SET backend_hostkey_ed25519=?, backend_hostkey_ecdsa=?, backend_hostkey_rsa=? WHERE id=?",
			nullable(pubFromPriv(k.ed)), nullable(pubFromPriv(k.ec)), nullable(pubFromPriv(k.rsa)), k.id); err != nil {
			return err
		}
	}
	return nil
}

// pubFromPriv returns the authorized-key public line for a private host key
// PEM, or "" when it cannot be parsed.
func pubFromPriv(privPEM string) string {
	if strings.TrimSpace(privPEM) == "" {
		return ""
	}
	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}
