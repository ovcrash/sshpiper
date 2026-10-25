package registry

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// NormalizeIP returns the canonical text form of an IP address (IPv4-mapped
// IPv6 addresses are unmapped), so equal addresses compare equal as strings.
func NormalizeIP(s string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("registry: invalid IP %q", s)
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() {
		return "", fmt.Errorf("registry: IP %s cannot be used as an external address", addr)
	}
	return addr.String(), nil
}

func validateUsername(u string) error {
	if u == "" {
		return errors.New("registry: empty username")
	}
	if len(u) > 255 {
		return errors.New("registry: username too long")
	}
	for _, r := range u {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("registry: username contains whitespace or control characters")
		}
	}
	return nil
}

// ValidateKeyPair checks that publicKey is an authorized_keys line, that
// privateKey is an unencrypted private key and that they match.
func ValidateKeyPair(publicKey, privateKey string) error {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return fmt.Errorf("registry: invalid public key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return fmt.Errorf("registry: invalid private key: %w", err)
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		return errors.New("registry: private key does not match the public key")
	}
	return nil
}

// Validate checks a NewEntry and returns its normalized external IP.
func (n *NewEntry) Validate() (string, error) {
	ip, err := NormalizeIP(n.ExternalIP)
	if err != nil {
		return "", err
	}
	if err := validateUsername(n.Username); err != nil {
		return "", err
	}
	if strings.TrimSpace(n.BackendHost) == "" {
		return "", errors.New("registry: empty backend host")
	}
	if n.BackendPort < 1 || n.BackendPort > 65535 {
		return "", fmt.Errorf("registry: invalid backend port %d", n.BackendPort)
	}
	if n.Password == "" && n.PublicKey == "" && n.PrivateKey == "" {
		return "", errors.New("registry: at least one authentication method (password or key pair) is required")
	}
	if (n.PublicKey == "") != (n.PrivateKey == "") {
		return "", errors.New("registry: public and private key must be given together")
	}
	if n.PublicKey != "" {
		if err := ValidateKeyPair(n.PublicKey, n.PrivateKey); err != nil {
			return "", err
		}
	}
	return ip, nil
}
