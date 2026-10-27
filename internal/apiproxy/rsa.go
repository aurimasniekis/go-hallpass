package apiproxy

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// parseRSAKey parses the PEM RSA private key of a Google service account key (PKCS #8, or PKCS #1).
func parseRSAKey(s string) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("not a PEM private key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("not an RSA private key")
	}
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}
