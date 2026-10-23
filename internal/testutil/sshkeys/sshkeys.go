// Package sshkeys generates throwaway SSH keys for tests (never commit key material, HP-OPS-012).
package sshkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Key is a generated key pair.
type Key struct {
	Private crypto.Signer
	Public  ssh.PublicKey
	Signer  ssh.Signer
}

// AuthorizedLine returns the public key as an authorized_keys line with a comment.
func (k Key) AuthorizedLine(comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.Public)))
	if comment != "" {
		line += " " + comment
	}
	return line
}

// Fingerprint returns the SHA256 fingerprint.
func (k Key) Fingerprint() string { return ssh.FingerprintSHA256(k.Public) }

func from(t testing.TB, priv crypto.Signer) Key {
	t.Helper()
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return Key{Private: priv, Public: signer.PublicKey(), Signer: signer}
}

// Ed25519 generates an Ed25519 key.
func Ed25519(t testing.TB) Key {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return from(t, priv)
}

// ECDSA generates an ECDSA key on curve.
func ECDSA(t testing.TB, curve elliptic.Curve) Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return from(t, priv)
}

// RSA generates an RSA key of bits.
func RSA(t testing.TB, bits int) Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return from(t, priv)
}

// ECDSA256 generates a P-256 ECDSA key.
func ECDSA256(t testing.TB) Key { return ECDSA(t, elliptic.P256()) }
