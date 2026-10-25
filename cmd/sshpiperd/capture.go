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

	// onHandshake, if set before the first Read, is called once with the
	// client version and KEXINIT as soon as both are captured.
	onHandshake func(version string, kex *sshkex.KexInit)

	mu       sync.Mutex
	capture  sshkex.Capture
	reported bool
}

func newCaptureConn(c net.Conn) *captureConn {
	return &captureConn{Conn: c, sessionID: uuid.NewString()}
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		var (
			version string
			kex     *sshkex.KexInit
			report  bool
		)
		c.mu.Lock()
		if !c.capture.Done() {
			c.capture.Write(p[:n])
			if c.capture.Done() && !c.reported {
				if v, k, rerr := c.capture.Result(); rerr == nil {
					version, kex, report = v, k, true
					c.reported = true
				}
			}
		}
		c.mu.Unlock()
		if report && c.onHandshake != nil {
			c.onHandshake(version, kex)
		}
	}
	return n, err
}

// clientHandshake returns the client version line and parsed KEXINIT if they
// were captured and not reported yet through onHandshake, and marks them as
// reported. ok is false otherwise.
func (c *captureConn) clientHandshake() (version string, kex *sshkex.KexInit, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reported {
		return "", nil, false
	}
	v, k, err := c.capture.Result()
	if err != nil {
		return "", nil, false
	}
	c.reported = true
	return v, k, true
}
