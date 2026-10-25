// Package sshkex parses the unencrypted start of an SSH connection (version
// line and first KEXINIT packet, RFC 4253 sections 4.2 and 7.1) and computes
// HASSH fingerprints from it.
package sshkex

import (
	"crypto/md5" //nolint:gosec // HASSH is defined as an MD5 digest
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const msgKexInit = 20

// KexInit holds the name-lists of a SSH_MSG_KEXINIT packet, as received.
type KexInit struct {
	Cookie                  [16]byte
	KexAlgos                string
	ServerHostKeyAlgos      string
	CiphersClientServer     string
	CiphersServerClient     string
	MACsClientServer        string
	MACsServerClient        string
	CompressionClientServer string
	CompressionServerClient string
	LanguagesClientServer   string
	LanguagesServerClient   string
	FirstKexFollows         bool
	Reserved                uint32
}

// ErrNotKexInit is returned when a payload does not start with SSH_MSG_KEXINIT.
var ErrNotKexInit = errors.New("sshkex: not a KEXINIT packet")

// ParseKexInit parses a KEXINIT payload (message type byte included).
func ParseKexInit(payload []byte) (*KexInit, error) {
	if len(payload) == 0 || payload[0] != msgKexInit {
		return nil, ErrNotKexInit
	}
	if len(payload) < 17 {
		return nil, fmt.Errorf("sshkex: KEXINIT too short: %d bytes", len(payload))
	}

	k := &KexInit{}
	copy(k.Cookie[:], payload[1:17])
	rest := payload[17:]

	lists := []*string{
		&k.KexAlgos,
		&k.ServerHostKeyAlgos,
		&k.CiphersClientServer,
		&k.CiphersServerClient,
		&k.MACsClientServer,
		&k.MACsServerClient,
		&k.CompressionClientServer,
		&k.CompressionServerClient,
		&k.LanguagesClientServer,
		&k.LanguagesServerClient,
	}
	for i, dst := range lists {
		if len(rest) < 4 {
			return nil, fmt.Errorf("sshkex: truncated name-list %d", i)
		}
		n := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(n) > uint64(len(rest)) {
			return nil, fmt.Errorf("sshkex: name-list %d length %d exceeds packet", i, n)
		}
		*dst = string(rest[:n])
		rest = rest[n:]
	}

	if len(rest) < 5 {
		return nil, errors.New("sshkex: truncated KEXINIT trailer")
	}
	k.FirstKexFollows = rest[0] != 0
	k.Reserved = binary.BigEndian.Uint32(rest[1:5])

	return k, nil
}

// HASSHAlgorithms returns the client HASSH input:
// kex ";" ciphers c2s ";" macs c2s ";" compression c2s.
func (k *KexInit) HASSHAlgorithms() string {
	return strings.Join([]string{k.KexAlgos, k.CiphersClientServer, k.MACsClientServer, k.CompressionClientServer}, ";")
}

// HASSH returns the client HASSH (hex MD5 of HASSHAlgorithms).
func (k *KexInit) HASSH() string {
	return md5hex(k.HASSHAlgorithms())
}

// HASSHServerAlgorithms returns the server HASSH input:
// kex ";" ciphers s2c ";" macs s2c ";" compression s2c.
func (k *KexInit) HASSHServerAlgorithms() string {
	return strings.Join([]string{k.KexAlgos, k.CiphersServerClient, k.MACsServerClient, k.CompressionServerClient}, ";")
}

// HASSHServer returns the server HASSH (hex MD5 of HASSHServerAlgorithms).
func (k *KexInit) HASSHServer() string {
	return md5hex(k.HASSHServerAlgorithms())
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // HASSH is defined as an MD5 digest
	return hex.EncodeToString(sum[:])
}
