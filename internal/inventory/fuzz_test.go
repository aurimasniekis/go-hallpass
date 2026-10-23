package inventory

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

// HP-TST-002, HP-SRV-004: host key enrollment accepts exactly one supported plain public key (authorized_keys or
// known_hosts form) and never a certificate, option-bearing line or multi-line input.
func FuzzParseHostKey(f *testing.F) {
	ed := sshkeys.Ed25519(f)
	f.Add(ed.AuthorizedLine("host"))
	f.Add("web1.example,10.0.0.1 " + ed.AuthorizedLine(""))
	f.Add("@cert-authority *.example " + ed.AuthorizedLine(""))
	f.Add("@revoked * " + ed.AuthorizedLine(""))
	f.Add(`command="x" ` + ed.AuthorizedLine(""))
	f.Add(ed.AuthorizedLine("") + "\n" + ed.AuthorizedLine(""))
	f.Add("ssh-dss AAAAB3NzaC1kc3MAAACBAP")
	f.Add("|1|c2FsdA==|aGFzaA== " + ed.AuthorizedLine(""))
	allowed := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA}
	f.Fuzz(func(t *testing.T, line string) {
		pk, err := ParseHostKey(line)
		if err != nil {
			return
		}
		if !slices.Contains(allowed, pk.Type()) {
			t.Fatalf("unsupported host key type %q accepted", pk.Type())
		}
		if _, isCert := pk.(*ssh.Certificate); isCert {
			t.Fatal("certificate accepted as a host key")
		}
		if strings.Contains(strings.TrimSpace(line), "\n") {
			t.Fatalf("multi-line input accepted: %q", line)
		}
	})
}
