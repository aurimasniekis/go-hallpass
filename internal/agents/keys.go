package agents

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
)

// MinRSABits is the minimum accepted RSA modulus size (HP-SSH-004).
const MinRSABits = 3072

// MaxKeyLineBytes bounds pasted key input.
const MaxKeyLineBytes = 16 << 10

// ParsedKey is a validated agent public key.
type ParsedKey struct {
	Key         ssh.PublicKey
	Fingerprint string // "SHA256:…"
	Algorithm   string
	Bits        int
	Comment     string
	Line        string // canonical authorized_keys line without comment
}

// AllowedKeyTypes are the accepted agent key algorithms.
var AllowedKeyTypes = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA,
}

// ParseAgentKey validates a single OpenSSH public key line (HP-AGT-004, HP-AGT-006).
// It rejects private keys, authorized_keys options, certificates, multiple keys and disallowed algorithms.
func ParseAgentKey(input string) (*ParsedKey, error) {
	if len(input) > MaxKeyLineBytes {
		return nil, apperr.New(apperr.CodeInvalid, "public key input too large")
	}
	if strings.Contains(input, "PRIVATE KEY") || strings.Contains(input, "OPENSSH PRIVATE") {
		// Never echo the input: it may be secret material.
		return nil, apperr.New(apperr.CodeInvalid, "a private key was supplied; Hallpass only accepts agent public keys and never stores agent private keys")
	}
	data := bytes.TrimSpace([]byte(input))
	if bytes.Count(data, []byte("\n")) > 0 {
		return nil, apperr.New(apperr.CodeInvalid, "exactly one public key line is required")
	}
	pk, comment, options, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, apperr.New(apperr.CodeInvalid, "not a valid OpenSSH public key line")
	}
	if len(options) > 0 {
		return nil, apperr.New(apperr.CodeInvalid, "authorized_keys options are not accepted; Hallpass enforces restrictions itself")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, apperr.New(apperr.CodeInvalid, "exactly one public key line is required")
	}
	if _, isCert := pk.(*ssh.Certificate); isCert {
		return nil, apperr.New(apperr.CodeInvalid, "SSH certificates are not accepted as agent keys in this version")
	}
	bits, err := checkAlgorithm(pk)
	if err != nil {
		return nil, err
	}
	return &ParsedKey{
		Key:         pk,
		Fingerprint: ssh.FingerprintSHA256(pk),
		Algorithm:   pk.Type(),
		Bits:        bits,
		Comment:     sanitizeComment(comment),
		Line:        strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))),
	}, nil
}

// CheckKeyPolicy validates the algorithm of a key presented during SSH authentication.
func CheckKeyPolicy(pk ssh.PublicKey) error {
	if _, isCert := pk.(*ssh.Certificate); isCert {
		return apperr.New(apperr.CodeInvalid, "certificates not accepted")
	}
	_, err := checkAlgorithm(pk)
	return err
}

func checkAlgorithm(pk ssh.PublicKey) (int, error) {
	switch pk.Type() {
	case ssh.KeyAlgoED25519:
		return 256, nil
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		cpk, ok := pk.(ssh.CryptoPublicKey)
		if !ok {
			return 0, apperr.New(apperr.CodeInvalid, "unsupported ECDSA key")
		}
		ek, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok {
			return 0, apperr.New(apperr.CodeInvalid, "unsupported ECDSA key")
		}
		return ek.Curve.Params().BitSize, nil
	case ssh.KeyAlgoRSA:
		cpk, ok := pk.(ssh.CryptoPublicKey)
		if !ok {
			return 0, apperr.New(apperr.CodeInvalid, "unsupported RSA key")
		}
		rk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return 0, apperr.New(apperr.CodeInvalid, "unsupported RSA key")
		}
		if bits := rk.N.BitLen(); bits < MinRSABits {
			return 0, apperr.New(apperr.CodeInvalid, "RSA keys must be at least %d bits (got %d)", MinRSABits, bits)
		}
		return rk.N.BitLen(), nil
	default:
		return 0, apperr.New(apperr.CodeInvalid, "key type %q is not allowed (use Ed25519, ECDSA or RSA >= %d)", pk.Type(), MinRSABits)
	}
}

func sanitizeComment(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}
