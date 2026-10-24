package destssh

import (
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

// SR-45 (HP-SSH-004): RSA login signers never offer SHA-1 ssh-rsa, even to a destination without server-sig-algs.
func TestRestrictRSA(t *testing.T) {
	rsaKey, ed := sshkeys.RSA(t, 3072), sshkeys.Ed25519(t)
	out := RestrictRSA([]ssh.Signer{rsaKey.Signer, ed.Signer})
	if len(out) != 2 {
		t.Fatalf("%d signers", len(out))
	}
	ms, ok := out[0].(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatal("RSA signer not restricted")
	}
	if algs := ms.Algorithms(); slices.Contains(algs, ssh.KeyAlgoRSA) || !slices.Contains(algs, ssh.KeyAlgoRSASHA512) {
		t.Fatalf("algorithms %v", algs)
	}
	if _, err := ms.SignWithAlgorithm(nil, []byte("x"), ssh.KeyAlgoRSA); err == nil {
		t.Fatal("SHA-1 ssh-rsa signature produced")
	}
	if out[1] != ed.Signer {
		t.Fatal("non-RSA signer changed")
	}
}
