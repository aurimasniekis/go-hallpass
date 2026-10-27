package apiproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"time"
)

// Certificate lifetimes. The CA outlives every leaf it signs; leaves are short and re-minted in memory.
const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 7 * 24 * time.Hour
	leafRenew    = 24 * time.Hour // re-mint a cached leaf with less than this left
	clockSkew    = time.Hour
)

// permittedDomains returns the X.509 name constraints for a target's hosts: an exact host permits itself (and its
// subdomains), "*.example.com" permits example.com and its subdomains. The CA can sign for nothing else.
func permittedDomains(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, strings.TrimPrefix(h, "*."))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// newCA creates a target's interception CA: ECDSA P-256, path length 0, DNS names limited to the target's hosts and
// every IP address excluded, so trusting it lets HallPass intercept only that API.
func newCA(alias, serverID string, hosts []string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{CommonName: "HallPass API proxy CA for " + alias, Organization: []string{"HallPass"},
			OrganizationalUnit: []string{serverID}},
		NotBefore:                   now.Add(-clockSkew),
		NotAfter:                    now.Add(caValidity),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDomains(hosts),
		ExcludedIPRanges:            []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// caCovers reports whether a stored CA was issued for exactly these hosts (otherwise it is replaced).
func caCovers(cert *x509.Certificate, hosts []string, now time.Time) bool {
	return slices.Equal(cert.PermittedDNSDomains, permittedDomains(hosts)) && now.Add(leafValidity).Before(cert.NotAfter)
}

func encodeCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func parseCertPEM(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

// Fingerprint is the SHA-256 fingerprint of a certificate, colon-separated hex.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// signedCA is a target CA ready to sign leaves.
type signedCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// leaf mints a server certificate for host, signed by the CA, for the shared leaf key.
func (ca *signedCA) leaf(host string, leafKey *ecdsa.PrivateKey, now time.Time) (*leafCert, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafValidity)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return &leafCert{chain: [][]byte{der, ca.cert.Raw}, key: leafKey, notAfter: notAfter}, nil
}

type leafCert struct {
	chain    [][]byte
	key      *ecdsa.PrivateKey
	notAfter time.Time
	ca       *x509.Certificate
}

// issuedBy reports whether the leaf was signed by ca (a target's CA changes when its hosts do).
func (l *leafCert) issuedBy(ca *signedCA) bool { return l.ca != nil && l.ca.Equal(ca.cert) }
