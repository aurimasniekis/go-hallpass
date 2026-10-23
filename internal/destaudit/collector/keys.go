package collector

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GenerateKeyFile creates a new Ed25519 collector key at path (OpenSSH private key format, mode 0600). It refuses to
// overwrite an existing file. It returns the public key in authorized_keys format for enrollment in Hallpass.
func GenerateKeyFile(path, comment string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen key path
	if err != nil {
		return "", err
	}
	if _, err := f.Write(pem.EncodeToMemory(block)); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return PublicLine(pub, comment)
}

// PublicLine renders an Ed25519 public key in authorized_keys format.
func PublicLine(pub ed25519.PublicKey, comment string) (string, error) {
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	if comment != "" {
		line += " " + comment
	}
	return line, nil
}

// LoadKeyFile reads an Ed25519 private key in OpenSSH format. Group- or world-accessible key files are refused.
func LoadKeyFile(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key file %s must not be accessible by group or others (mode %o)", path, st.Mode().Perm())
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-chosen key path
	if err != nil {
		return nil, err
	}
	k, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, err
	}
	switch v := k.(type) {
	case *ed25519.PrivateKey:
		return *v, nil
	case ed25519.PrivateKey:
		return v, nil
	}
	return nil, errors.New("collector key must be Ed25519")
}
