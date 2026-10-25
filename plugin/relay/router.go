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

// entryFor returns the entry of the address the client connected to. Entries
// that are not exposed (or ready, for verification) are not served.
func (r *router) entryFor(conn libplugin.ConnMetadata) (*registry.Entry, error) {
	dst := conn.GetMeta(metaDstAddr)
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, fmt.Errorf("%w: no destination address", errNotServed)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	e, err := r.db.ByExternalIP(ctx, host)
	if err != nil {
		return nil, errNotServed
	}
	if e.State != registry.StateExposed && e.State != registry.StateReady {
		return nil, errNotServed
	}
	return e, nil
}

func (r *router) newConnection(conn libplugin.ConnMetadata) error {
	_, err := r.entryFor(conn)
	return err
}

// nextAuthMethods lists the methods of the entry, in the order announced by
// the backend when it was probed.
func (r *router) nextAuthMethods(conn libplugin.ConnMetadata) ([]string, error) {
	e, err := r.entryFor(conn)
	if err != nil {
		return nil, err
	}

	enabled := map[string]bool{"password": e.AuthPassword, "publickey": e.AuthKey}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	var order []string
	if p, err := r.db.Persona(ctx, e.ID); err == nil {
		order = strings.Split(p.AuthMethods, ",")
	}
	order = append(order, "password", "publickey")

	var methods []string
	seen := map[string]bool{}
	for _, m := range order {
		m = strings.TrimSpace(m)
		if enabled[m] && !seen[m] {
			seen[m] = true
			methods = append(methods, m)
		}
	}
	return methods, nil
}

// password forwards the user name and password as typed: the backend judges,
// including for names that do not exist there.
func (r *router) password(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	e, err := r.entryFor(conn)
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
	e, err := r.entryFor(conn)
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

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	var known []byte
	if p, err := r.db.Persona(ctx, e.ID); err == nil {
		known, err = knownHostsData(addr, p)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", e.ID, err)
		}
	}

	return &libplugin.Upstream{
		Uri:            "tcp://" + addr,
		UserName:       user,
		KnownHostsData: known,
	}, nil
}

// knownHostsData pins the backend to the host keys of its persona.
func knownHostsData(addr string, p *registry.Persona) ([]byte, error) {
	if !p.HasHostKeys() {
		return nil, nil
	}

	var buf bytes.Buffer
	for _, k := range []string{p.HostKeyED25519, p.HostKeyECDSA, p.HostKeyRSA} {
		s, err := ssh.ParsePrivateKey([]byte(k))
		if err != nil {
			return nil, fmt.Errorf("host key: %w", err)
		}
		buf.WriteString(knownhosts.Line([]string{addr}, s.PublicKey()))
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}
