package main

import (
	"net"
	"sync"

	"github.com/google/uuid"
	"github.com/tg123/sshpiper/sshkex"
)

// captureConn wraps a downstream net.Conn and copies, without modifying them,
// the first bytes read from the client until the version line and the first
// KEXINIT are complete. It keeps LocalAddr/RemoteAddr so the daemon and the
// plugins see the real socket. It carries the session UUID generated at
// accept time.
type captureConn struct {
	net.Conn
	sessionID string

	mu      sync.Mutex
	capture sshkex.Capture
}

func newCaptureConn(c net.Conn) *captureConn {
	return &captureConn{Conn: c, sessionID: uuid.NewString()}
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.capture.Done() {
			c.capture.Write(p[:n])
		}
		c.mu.Unlock()
	}
	return n, err
}

// clientHandshake returns the client version line and parsed KEXINIT once
// captured. ok is false while still incomplete or on a parse error.
func (c *captureConn) clientHandshake() (version string, kex *sshkex.KexInit, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, k, err := c.capture.Result()
	if err != nil {
		return "", nil, false
	}
	return v, k, true
}
