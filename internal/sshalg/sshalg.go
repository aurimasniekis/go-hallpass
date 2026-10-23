// Package sshalg defines the SSH algorithm allowlists used on both the agent-facing and destination legs (HP-SSH-004).
package sshalg

import "golang.org/x/crypto/ssh"

// KeyExchanges are the allowed key-exchange methods (post-quantum hybrid first).
var KeyExchanges = []string{
	ssh.KeyExchangeMLKEM768X25519,
	ssh.KeyExchangeCurve25519,
	ssh.KeyExchangeECDHP256,
	ssh.KeyExchangeECDHP384,
	ssh.KeyExchangeECDHP521,
	ssh.KeyExchangeDH16SHA512,
	ssh.KeyExchangeDH14SHA256,
}

// Ciphers are the allowed transport ciphers (AEAD first; CTR only with ETM MACs preferred).
var Ciphers = []string{
	ssh.CipherChaCha20Poly1305,
	ssh.CipherAES256GCM,
	ssh.CipherAES128GCM,
	ssh.CipherAES256CTR,
	ssh.CipherAES192CTR,
	ssh.CipherAES128CTR,
}

// MACs are the allowed MACs (no SHA-1).
var MACs = []string{
	ssh.HMACSHA256ETM,
	ssh.HMACSHA512ETM,
	ssh.HMACSHA256,
	ssh.HMACSHA512,
}

// PublicKeyAuthAlgorithms are the signature algorithms accepted for public-key authentication (no SHA-1 ssh-rsa).
var PublicKeyAuthAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

// Config returns an ssh.Config with the allowlists applied.
func Config() ssh.Config {
	return ssh.Config{KeyExchanges: KeyExchanges, Ciphers: Ciphers, MACs: MACs}
}

// HostKeyAlgorithmsFor maps an enrolled host key type to the negotiable host-key algorithms.
func HostKeyAlgorithmsFor(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	case ssh.CertAlgoRSAv01:
		return []string{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01}
	default:
		return []string{keyType}
	}
}

// HostCertAlgorithms are host-certificate algorithms accepted when a host CA is bound.
var HostCertAlgorithms = []string{
	ssh.CertAlgoED25519v01,
	ssh.CertAlgoECDSA256v01,
	ssh.CertAlgoECDSA384v01,
	ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01,
	ssh.CertAlgoRSASHA256v01,
}
