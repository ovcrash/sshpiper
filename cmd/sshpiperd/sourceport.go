package main

// relay: open the upstream connection from the same source port as the client.

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/urfave/cli/v2"
)

func sourcePortFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    "preserve-source-port",
			Usage:   "open each upstream connection from the client's source port when it is free on this host (otherwise an ephemeral port is used)",
			EnvVars: []string{"SSHPIPERD_PRESERVE_SOURCE_PORT"},
		},
	}
}

// Every authentication attempt opens a new upstream connection, and the SSH
// library abandons the connection of a failed attempt without closing it. It
// stays open on the backend until its login grace time, and it holds the
// 4-tuple that the next attempt wants to reuse. The upstream connections of a
// client are therefore tracked: a new attempt first aborts the abandoned ones
// (reset, so no TIME_WAIT keeps the port), and releaseUpstreams aborts what is
// left when the client connection ends.
var upstreams = struct {
	mu sync.Mutex
	m  map[string][]*trackedConn
}{m: make(map[string][]*trackedConn)}

type trackedConn struct {
	net.Conn
	key     string
	onClose func(net.Conn) // optional, called once on the first Close
	once    sync.Once
}

func (t *trackedConn) Close() error {
	if t.onClose != nil {
		t.once.Do(func() { t.onClose(t.Conn) })
	}
	upstreams.mu.Lock()
	list := upstreams.m[t.key]
	for i, c := range list {
		if c == t {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(upstreams.m, t.key)
	} else {
		upstreams.m[t.key] = list
	}
	upstreams.mu.Unlock()
	return t.Conn.Close()
}

// abort closes c without TIME_WAIT (RST).
func abort(c *trackedConn) {
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}

func takeUpstreams(key string) []*trackedConn {
	upstreams.mu.Lock()
	defer upstreams.mu.Unlock()
	list := upstreams.m[key]
	delete(upstreams.m, key)
	return list
}

// releaseUpstreams aborts the upstream connections still open for a client
// connection (abandoned attempts). The one in use by a finished pipe is
// already closed. It is a no-op when the option is off.
func releaseUpstreams(downstream net.Addr) {
	if downstream == nil {
		return
	}
	for _, c := range takeUpstreams(downstream.String()) {
		abort(c)
	}
}

func clientPort(downstream net.Addr) int {
	if tcp, ok := downstream.(*net.TCPAddr); ok {
		return tcp.Port
	}
	if downstream == nil {
		return 0
	}
	_, p, err := net.SplitHostPort(downstream.String())
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

// dialKeepSourcePort dials addr from the source port of downstream. If that
// port cannot be used (in use on this host, or the same 4-tuple still
// exists), it falls back to an ephemeral port, so a login is never refused
// because of this option.
func dialKeepSourcePort(network, addr string, downstream net.Addr) (net.Conn, error) {
	return dialKeepSourcePortHook(network, addr, downstream, nil)
}

// dialKeepSourcePortHook is dialKeepSourcePort with a hook run when the
// returned connection is closed, including when an abandoned attempt is reset.
func dialKeepSourcePortHook(network, addr string, downstream net.Addr, onClose func(net.Conn)) (net.Conn, error) {
	port := clientPort(downstream)
	if port == 0 || !strings.HasPrefix(network, "tcp") {
		c, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		return withCloseHook(c, onClose), nil
	}
	key := downstream.String()

	// a new attempt: the previous ones of this client failed and were abandoned
	for _, c := range takeUpstreams(key) {
		abort(c)
	}

	d := net.Dialer{LocalAddr: &net.TCPAddr{Port: port}, Control: reuseAddrControl}
	c, err := d.Dial(network, addr)
	if err != nil {
		slog.Debug("client source port unavailable for upstream, using an ephemeral port", "port", port, "upstream", addr, "error", err)
		if c, err = net.Dial(network, addr); err != nil {
			return nil, err
		}
	}

	t := &trackedConn{Conn: c, key: key, onClose: onClose}
	upstreams.mu.Lock()
	upstreams.m[key] = append(upstreams.m[key], t)
	upstreams.mu.Unlock()
	return t, nil
}

// hookConn runs a hook once when closed (connections that are not tracked).
type hookConn struct {
	net.Conn
	onClose func(net.Conn)
	once    sync.Once
}

func (h *hookConn) Close() error {
	h.once.Do(func() { h.onClose(h.Conn) })
	return h.Conn.Close()
}

func withCloseHook(c net.Conn, onClose func(net.Conn)) net.Conn {
	if onClose == nil {
		return c
	}
	return &hookConn{Conn: c, onClose: onClose}
}
