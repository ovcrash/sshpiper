package registry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// Host key file names, as written by ssh-keygen -A on Ubuntu.
const (
	fileED25519 = "ssh_host_ed25519_key"
	fileECDSA   = "ssh_host_ecdsa_key"
	fileRSA     = "ssh_host_rsa_key"
)

// HostKeys are PEM OpenSSH private keys.
type HostKeys struct {
	ED25519 string `json:"ed25519"`
	ECDSA   string `json:"ecdsa"`
	RSA     string `json:"rsa"`
}

// GenerateHostKeys creates the three host keys with the defaults of an
// Ubuntu 24.04 server: ed25519, ECDSA P-256 and RSA 3072.
func GenerateHostKeys() (*HostKeys, error) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}

	var hk HostKeys
	for _, k := range []struct {
		key crypto.PrivateKey
		dst *string
	}{{edKey, &hk.ED25519}, {ecKey, &hk.ECDSA}, {rsaKey, &hk.RSA}} {
		block, err := ssh.MarshalPrivateKey(k.key, "")
		if err != nil {
			return nil, err
		}
		*k.dst = string(pem.EncodeToMemory(block))
	}

	return &hk, nil
}

// Validate checks that each key parses and has the expected type.
func (h *HostKeys) Validate() error {
	for _, k := range []struct{ name, pem, typ string }{
		{"ed25519", h.ED25519, ssh.KeyAlgoED25519},
		{"ecdsa", h.ECDSA, ssh.KeyAlgoECDSA256},
		{"rsa", h.RSA, ssh.KeyAlgoRSA},
	} {
		s, err := ssh.ParsePrivateKey([]byte(k.pem))
		if err != nil {
			return fmt.Errorf("registry: %s host key: %w", k.name, err)
		}
		if s.PublicKey().Type() != k.typ {
			return fmt.Errorf("registry: %s host key has type %s", k.name, s.PublicKey().Type())
		}
	}
	return nil
}

// HostKeys returns the persona host keys.
func (p *Persona) HostKeys() HostKeys {
	return HostKeys{ED25519: p.HostKeyED25519, ECDSA: p.HostKeyECDSA, RSA: p.HostKeyRSA}
}

// SetHostKeys stores keys in the persona.
func (p *Persona) SetHostKeys(h HostKeys) {
	p.HostKeyED25519, p.HostKeyECDSA, p.HostKeyRSA = h.ED25519, h.ECDSA, h.RSA
}

// ExportHostKeys writes the keys and their .pub files to dir
// (private 0600, public 0644). Existing files are not overwritten.
func ExportHostKeys(dir string, h HostKeys) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, k := range []struct{ name, pem string }{
		{fileED25519, h.ED25519}, {fileECDSA, h.ECDSA}, {fileRSA, h.RSA},
	} {
		signer, err := ssh.ParsePrivateKey([]byte(k.pem))
		if err != nil {
			return fmt.Errorf("registry: %s: %w", k.name, err)
		}
		if err := writeNew(filepath.Join(dir, k.name), []byte(k.pem), 0o600); err != nil {
			return err
		}
		if err := writeNew(filepath.Join(dir, k.name+".pub"), ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ImportHostKeys reads the three keys from a directory laid out like
// /etc/ssh.
func ImportHostKeys(dir string) (*HostKeys, error) {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		return string(b), err
	}
	var h HostKeys
	var err error
	if h.ED25519, err = read(fileED25519); err != nil {
		return nil, err
	}
	if h.ECDSA, err = read(fileECDSA); err != nil {
		return nil, err
	}
	if h.RSA, err = read(fileRSA); err != nil {
		return nil, err
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return &h, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("registry: %s already exists, not overwriting", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
