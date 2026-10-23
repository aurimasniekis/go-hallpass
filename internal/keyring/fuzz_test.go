package keyring

import (
	"bytes"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

// HP-TST-002, HP-CRY-001: KEK file parsing yields exactly 32 bytes or an error, deterministically.
func FuzzParseKEK(f *testing.F) {
	k, err := GenerateKEK()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(EncodeKEK(k))
	f.Add(k)
	f.Add([]byte("  " + string(EncodeKEK(k)) + "\n"))
	f.Add([]byte("AAAA"))
	f.Add(bytes.Repeat([]byte{'A'}, 32))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseKEK(data)
		if err != nil {
			return
		}
		if len(got) != KEKSize {
			t.Fatalf("KEK of %d bytes accepted", len(got))
		}
		again, err := ParseKEK(data)
		if err != nil || !bytes.Equal(again, got) {
			t.Fatal("ParseKEK is not deterministic")
		}
	})
}

// HP-TST-002, HP-CRY-002/003: sealed values open only with their exact purpose, AAD and bytes; MACs verify only for
// the exact data. Any mutation of a sealed value or AAD is rejected.
func FuzzSealedOpen(f *testing.F) {
	kr, _ := loadFuzzRing(f)
	type sealedRef struct {
		aad, pt []byte
	}
	known := map[string]sealedRef{}
	for i, pt := range []string{"", "secret reason", "x"} {
		aad := FieldAAD("t", "c", string(rune('a'+i)))
		s, err := kr.Seal(PurposeField, aad, []byte(pt))
		if err != nil {
			f.Fatal(err)
		}
		known[string(s)] = sealedRef{aad: aad, pt: []byte(pt)}
		f.Add(s, aad)
		f.Add(s, append(bytes.Clone(aad), '!'))
	}
	f.Fuzz(func(t *testing.T, sealed, aad []byte) {
		pt, err := kr.Open(PurposeField, aad, sealed)
		if err != nil {
			return
		}
		ref, ok := known[string(sealed)]
		if !ok || !bytes.Equal(ref.aad, aad) || !bytes.Equal(ref.pt, pt) {
			t.Fatalf("forged or rebound sealed value opened: %x aad %q", sealed, aad)
		}
		if _, err := kr.Open(PurposeCredential, aad, sealed); err == nil {
			t.Fatal("sealed value opened under another purpose")
		}
	})
}

// HP-TST-002, HP-CRY-008: MAC verification accepts only the MAC computed for the exact data.
func FuzzVerifyMAC(f *testing.F) {
	kr, _ := loadFuzzRing(f)
	data := []byte("chain-head")
	m, err := kr.MAC(PurposeManifest, data)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data, m)
	f.Add(data, m[:len(m)-1])
	f.Add([]byte("chain-hea"), m)
	f.Fuzz(func(t *testing.T, d, mac []byte) {
		if !kr.VerifyMAC(PurposeManifest, d, mac) {
			return
		}
		want, err := kr.MAC(PurposeManifest, d)
		if err != nil || !bytes.Equal(want, mac) {
			t.Fatalf("MAC %x accepted for %q", mac, d)
		}
	})
}

func loadFuzzRing(f *testing.F) (*Keyring, *LocalKEK) {
	f.Helper()
	s := storetest.Open(f)
	k, err := GenerateKEK()
	if err != nil {
		f.Fatal(err)
	}
	w, err := NewLocalKEK(k)
	if err != nil {
		f.Fatal(err)
	}
	kr, err := Load(f.Context(), s, w)
	if err != nil {
		f.Fatal(err)
	}
	return kr, w
}
