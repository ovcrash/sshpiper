package sshkex

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// MaxCaptureBytes bounds what a Capture buffers. RFC 4253 limits a packet to
// 35000 bytes; the version line and the first packet fit easily.
const MaxCaptureBytes = 64 * 1024

// Capture accumulates the first bytes a peer sends, without altering them,
// until the version line and the first (unencrypted) packet are complete.
// It is not safe for concurrent use.
type Capture struct {
	buf  []byte
	done bool
}

// Write appends data seen on the wire. It never fails, so it can sit in a
// read path without affecting the connection.
func (c *Capture) Write(p []byte) {
	if c.done {
		return
	}
	room := MaxCaptureBytes - len(c.buf)
	if room <= 0 {
		c.done = true
		return
	}
	if len(p) > room {
		p = p[:room]
	}
	c.buf = append(c.buf, p...)
	if _, _, err := c.Result(); !errors.Is(err, ErrIncomplete) {
		c.done = true
	}
}

// Done reports whether Write no longer records data.
func (c *Capture) Done() bool { return c.done }

// ErrIncomplete means more bytes are needed.
var ErrIncomplete = errors.New("sshkex: incomplete")

// Result returns the version line (without CRLF) and the parsed KEXINIT.
// It returns ErrIncomplete until enough bytes were written.
func (c *Capture) Result() (version string, kex *KexInit, err error) {
	// RFC 4253 4.2: the server may send other lines before its version;
	// a client sends the version line first.
	data := c.buf
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			if len(data) > 255 {
				return "", nil, errors.New("sshkex: version line too long")
			}
			return "", nil, ErrIncomplete
		}
		line := bytes.TrimSuffix(data[:i], []byte("\r"))
		data = data[i+1:]
		if bytes.HasPrefix(line, []byte("SSH-")) {
			version = string(line)
			break
		}
	}

	if len(data) < 5 {
		return "", nil, ErrIncomplete
	}
	packetLen := binary.BigEndian.Uint32(data)
	if packetLen < 2 || packetLen > 35000 {
		return "", nil, errors.New("sshkex: invalid first packet length")
	}
	if uint64(len(data)) < 4+uint64(packetLen) {
		return "", nil, ErrIncomplete
	}
	padLen := uint32(data[4])
	if padLen+1 > packetLen {
		return "", nil, errors.New("sshkex: invalid padding length")
	}
	payload := data[5 : 4+packetLen-padLen]

	kex, err = ParseKexInit(payload)
	if err != nil {
		return "", nil, err
	}
	return version, kex, nil
}
