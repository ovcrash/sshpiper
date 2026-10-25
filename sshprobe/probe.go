// Package sshprobe reads what an SSH server announces before authentication:
// version line, algorithm lists, host keys and authentication methods.
package sshprobe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/tg123/sshpiper/sshkex"
	"golang.org/x/crypto/ssh"
)

const defaultTimeout = 15 * time.Second

func dial(ctx context.Context, addr string) (net.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	return c, nil
}

// Banner is the version line and first KEXINIT sent by a server.
type Banner struct {
	Version string
	Kex     *sshkex.KexInit
}

// ReadBanner connects to addr, sends a client version line and reads the
// server's version line and KEXINIT (sent in clear, before any key exchange).
func ReadBanner(ctx context.Context, addr string) (*Banner, error) {
	c, err := dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if _, err := c.Write([]byte("SSH-2.0-probe\r\n")); err != nil {
		return nil, err
	}

	var capture sshkex.Capture
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		capture.Write(buf[:n])
		version, kex, rerr := capture.Result()
		if rerr == nil {
			return &Banner{Version: version, Kex: kex}, nil
		}
		if !errors.Is(rerr, sshkex.ErrIncomplete) {
			return nil, rerr
		}
		if err != nil {
			return nil, fmt.Errorf("sshprobe: %s: connection ended before KEXINIT: %w", addr, err)
		}
	}
}

// hostKeyAlgs are asked one at a time to get the server's key of each type.
var hostKeyAlgs = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA512}

// HostKeys returns the server's public host keys by key type
// (ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa).
func HostKeys(ctx context.Context, addr string) (map[string]ssh.PublicKey, error) {
	keys := make(map[string]ssh.PublicKey)
	for _, alg := range hostKeyAlgs {
		c, err := dial(ctx, addr)
		if err != nil {
			return nil, err
		}

		var got ssh.PublicKey
		cfg := &ssh.ClientConfig{
			User:              "probe",
			HostKeyAlgorithms: []string{alg},
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
				got = k
				return nil
			},
			Timeout: defaultTimeout,
		}
		// the handshake ends at authentication, which is expected to fail
		conn, _, _, _ := ssh.NewClientConn(c, addr, cfg)
		if conn != nil {
			_ = conn.Close()
		}
		_ = c.Close()

		if got == nil {
			return nil, fmt.Errorf("sshprobe: %s did not present a %s host key", addr, alg)
		}
		keys[got.Type()] = got
	}
	return keys, nil
}

// ParseAuthMethods extracts the list printed by "ssh -v" on its
// "Authentications that can continue:" line (the last one wins).
func ParseAuthMethods(output string) ([]string, error) {
	const marker = "Authentications that can continue:"
	var last string
	for _, line := range strings.Split(output, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			last = strings.TrimSpace(line[i+len(marker):])
		}
	}
	if last == "" {
		return nil, errors.New("sshprobe: no \"Authentications that can continue\" line in ssh output")
	}
	var methods []string
	for _, m := range strings.Split(last, ",") {
		if m = strings.TrimSpace(m); m != "" {
			methods = append(methods, m)
		}
	}
	return methods, nil
}

// AuthMethods asks the server which methods it offers, in order, by running
// the OpenSSH client with the none method only. The Go client does not
// expose this list.
func AuthMethods(ctx context.Context, host string, port int, user string) ([]string, error) {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		return nil, errors.New("sshprobe: the ssh client is required to read the authentication methods (install openssh-client)")
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "-v",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=none",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-p", strconv.Itoa(port),
		user+"@"+host, "true")
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // exits non-zero: the none method is refused

	return ParseAuthMethods(out.String())
}

// Login opens a session-less connection with the given method and closes it,
// to check that a credential works. expected, if not empty, pins the host keys.
func Login(ctx context.Context, addr, user string, auth ssh.AuthMethod, expected []ssh.PublicKey) error {
	c, err := dial(ctx, addr)
	if err != nil {
		return err
	}
	defer c.Close()

	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if len(expected) == 0 {
				return nil
			}
			for _, e := range expected {
				if bytes.Equal(e.Marshal(), k.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("unexpected %s host key", k.Type())
		},
		Timeout: defaultTimeout,
	}
	conn, _, _, err := ssh.NewClientConn(c, addr, cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}
