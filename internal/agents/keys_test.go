package agents

import (
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

// HP-AGT-004, HP-SSH-004: algorithm policy and strict parsing.
func TestParseAgentKeyPolicy(t *testing.T) {
	ok := map[string]sshkeys.Key{
		"ed25519": sshkeys.Ed25519(t),
		"p256":    sshkeys.ECDSA(t, elliptic.P256()),
		"p384":    sshkeys.ECDSA(t, elliptic.P384()),
		"p521":    sshkeys.ECDSA(t, elliptic.P521()),
		"rsa3072": sshkeys.RSA(t, 3072),
	}
	for name, k := range ok {
		pk, err := ParseAgentKey(k.AuthorizedLine("bot@host"))
		if err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
		if pk.Fingerprint != k.Fingerprint() || pk.Comment != "bot@host" || strings.Contains(pk.Line, "bot@host") {
			t.Fatalf("%s: %+v", name, pk)
		}
	}
	if _, err := ParseAgentKey(sshkeys.RSA(t, 2048).AuthorizedLine("")); err == nil || !strings.Contains(err.Error(), "3072") {
		t.Fatalf("RSA-2048 accepted: %v", err)
	}
}

func TestParseAgentKeyRejects(t *testing.T) {
	k := sshkeys.Ed25519(t)
	line := k.AuthorizedLine("")
	signer := sshkeys.Ed25519(t).Signer
	cert := &ssh.Certificate{Key: k.Public, CertType: ssh.UserCert, ValidPrincipals: []string{"x"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"options":     `restrict,from="10.0.0.0/8" ` + line,
		"two keys":    line + "\n" + sshkeys.Ed25519(t).AuthorizedLine(""),
		"garbage":     "ssh-ed25519 notbase64!!",
		"empty":       "",
		"private key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"certificate": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		"dsa":         "ssh-dss AAAAB3NzaC1kc3MAAACBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAAAAFQCXYFCPFSMLzLKSuYKi64QL8Fgc9QAAAIEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoAAACBAKKSU2PFl/qOLxIwmBZPPIcJshVe7bVUpFvyl3BbJDow8rXfskl8wO63OzP/qLmcJM0+JbcRU/53JjTuyk31drV2qxhIOsLDC9dGCWj47Y7TyhPdXh/0dthTRBy6bqGtRPxGa7gJov1xm/UuYYXPIUR/3x9MAZvZ5xvE0kYXO+rx",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAgentKey(input)
			if err == nil {
				t.Fatal("accepted")
			}
			if name == "private key" && strings.Contains(err.Error(), "b3Blbn") {
				t.Fatal("error echoes private key material")
			}
		})
	}
}

func TestCommentSanitized(t *testing.T) {
	pk, err := ParseAgentKey(sshkeys.Ed25519(t).AuthorizedLine("evil\u202eboté"))
	if err != nil || pk.Comment != "evilboté" {
		t.Fatalf("%q %v", pk.Comment, err)
	}
}

func FuzzParseAgentKey(f *testing.F) {
	f.Add(sshkeys.Ed25519(f).AuthorizedLine("seed"))
	f.Add("ssh-rsa AAAA")
	f.Add(`command="x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB`)
	f.Fuzz(func(t *testing.T, s string) {
		pk, err := ParseAgentKey(s)
		if err == nil {
			if pk.Key == nil || !strings.HasPrefix(pk.Fingerprint, "SHA256:") || CheckKeyPolicy(pk.Key) != nil {
				t.Fatalf("accepted key violates policy: %q", s)
			}
		}
	})
}
