//go:build full || e2e

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/registry"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// metaDstAddr is set by sshpiperd to the local address of the accepted socket.
const metaDstAddr = "sshpiperd.dst_addr"

const lookupTimeout = 2 * time.Second

type router struct {
	db *registry.DB
}

func newRouter(db *registry.DB) *router { return &router{db: db} }

var errNotServed = errors.New("address not in service")

// dstIP returns the external IP the client connected to.
func dstIP(conn libplugin.ConnMetadata) (string, error) {
	host, _, err := net.SplitHostPort(conn.GetMeta(metaDstAddr))
	if err != nil {
		return "", fmt.Errorf("%w: no destination address", errNotServed)
	}
	return host, nil
}

// accountFor returns the account for (external IP, username) the client is
// authenticating as. Accounts that are not exposed (or ready, for verification)
// are not served. A missing account returns errNotServed, so an unknown user
// fails exactly like a wrong credential (no account enumeration).
func (r *router) accountFor(conn libplugin.ConnMetadata) (*registry.Entry, error) {
	host, err := dstIP(conn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	e, err := r.db.ByExternalIPAndUser(ctx, host, conn.User())
	if err != nil {
		return nil, errNotServed
	}
	if e.State != registry.StateExposed && e.State != registry.StateReady {
		return nil, errNotServed
	}
	return e, nil
}

// newConnection runs before the username is known, so it only checks that the
// site (external IP) has at least one servable account.
func (r *router) newConnection(conn libplugin.ConnMetadata) error {
	host, err := dstIP(conn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	site, err := r.db.SiteByExternalIP(ctx, host)
	if err != nil || !(site.Servable || site.Ready) {
		return errNotServed
	}
	return nil
}

// nextAuthMethods announces the methods of the site persona (what the backend
// announced when probed), the same for every username so an unknown user is
// offered exactly what a valid one is — no account enumeration. The credential
// callbacks then accept or refuse per account.
func (r *router) nextAuthMethods(conn libplugin.ConnMetadata) ([]string, error) {
	host, err := dstIP(conn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	site, err := r.db.SiteByExternalIP(ctx, host)
	if err != nil || !(site.Servable || site.Ready) {
		return nil, errNotServed
	}

	var methods []string
	if p, err := r.db.SitePersona(ctx, host); err == nil {
		seen := map[string]bool{}
		for _, m := range strings.Split(p.AuthMethods, ",") {
			m = strings.TrimSpace(m)
			if (m == "password" || m == "publickey") && !seen[m] {
				seen[m] = true
				methods = append(methods, m)
			}
		}
	}
	if len(methods) == 0 {
		methods = []string{"password", "publickey"} // generic, uniform fallback
	}
	return methods, nil
}

// password forwards the user name and password as typed: the backend judges,
// including for names that do not exist there.
func (r *router) password(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	e, err := r.accountFor(conn)
	if err != nil {
		return nil, err
	}
	if !e.AuthPassword {
		return nil, errors.New("password not accepted")
	}
	u, err := r.upstream(e, conn.User())
	if err != nil {
		return nil, err
	}
	u.Auth = libplugin.CreatePasswordAuth(password)
	return u, nil
}

// publicKey accepts exactly the public key of the entry and then
// authenticates to the backend with the stored private key.
func (r *router) publicKey(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	e, err := r.accountFor(conn)
	if err != nil {
		return nil, err
	}
	if !e.AuthKey {
		return nil, errors.New("public key not accepted")
	}

	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
	if err != nil {
		return nil, errors.New("entry has an invalid public key")
	}
	if !bytes.Equal(want.Marshal(), key) {
		return nil, errors.New("public key not accepted")
	}
	u, err := r.upstream(e, conn.User())
	if err != nil {
		return nil, err
	}
	u.Auth = libplugin.CreatePrivateKeyAuth([]byte(e.PrivateKey))
	return u, nil
}

// upstream builds the route to the backend of e, pinned to its host keys; the caller sets Auth.
func (r *router) upstream(e *registry.Entry, user string) (*libplugin.Upstream, error) {
	addr := net.JoinHostPort(e.BackendHost, strconv.Itoa(e.BackendPort))

	known, err := knownHostsData(addr, e)
	if err != nil {
		return nil, fmt.Errorf("entry %d: %w", e.ID, err)
	}

	return &libplugin.Upstream{
		Uri:            "tcp://" + addr,
		UserName:       user,
		KnownHostsData: known,
	}, nil
}

// knownHostsData pins the backend to its own captured public host keys (the
// pin), which is separate from the site persona the proxy presents. Returns
// nil when the account has no captured keys yet (not probed).
func knownHostsData(addr string, e *registry.Entry) ([]byte, error) {
	var buf bytes.Buffer
	for _, authk := range []string{e.BackendHostED25519, e.BackendHostECDSA, e.BackendHostRSA} {
		if authk == "" {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authk))
		if err != nil {
			return nil, fmt.Errorf("backend host key: %w", err)
		}
		buf.WriteString(knownhosts.Line([]string{addr}, pk))
		buf.WriteByte('\n')
	}
	if buf.Len() == 0 {
		return nil, nil
	}
	return buf.Bytes(), nil
}
