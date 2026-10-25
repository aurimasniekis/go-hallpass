package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/keyring"
)

func testKEK(t testing.TB) *keyring.LocalKEK {
	t.Helper()
	k, err := keyring.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	w, err := keyring.NewLocalKEK(k)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func seal(t testing.TB, kek keyring.KeyWrapper, data []byte, kind, id string) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Seal(&b, bytes.NewReader(data), kek, kind, id); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func open(kek keyring.KeyWrapper, sealed []byte, kind, id string) ([]byte, error) {
	r, _, err := OpenSealed(bytes.NewReader(sealed), kek, kind, id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestSealedRoundTrip(t *testing.T) {
	kek := testKEK(t)
	for _, n := range []int{0, 1, sealedFrameMax - 1, sealedFrameMax, sealedFrameMax + 1, 3 * sealedFrameMax, 3*sealedFrameMax + 7} {
		data := make([]byte, n)
		_, _ = rand.Read(data)
		sealed := seal(t, kek, data, SealedKindDatabase, "bkp_1")
		if bytes.Contains(sealed, data[:min(n, 64)]) && n >= 16 {
			t.Fatalf("%d bytes: plaintext visible in the sealed object", n)
		}
		got, err := open(kek, sealed, SealedKindDatabase, "bkp_1")
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: round trip %v (%d bytes back)", n, err, len(got))
		}
	}
}

func TestSealedRejects(t *testing.T) {
	kek := testKEK(t)
	data := make([]byte, 2*sealedFrameMax+100)
	_, _ = rand.Read(data)
	sealed := seal(t, kek, data, SealedKindDatabase, "bkp_1")

	if _, err := open(testKEK(t), sealed, SealedKindDatabase, "bkp_1"); !errors.Is(err, ErrKEKMismatch) {
		t.Errorf("other KEK: %v", err)
	}
	if _, err := open(kek, sealed, SealedKindManifest, "bkp_1"); !errors.Is(err, ErrSealed) {
		t.Errorf("wrong kind: %v", err)
	}
	if _, err := open(kek, sealed, SealedKindDatabase, "bkp_2"); !errors.Is(err, ErrSealed) {
		t.Errorf("wrong backup: %v", err)
	}
	// Truncation at every frame boundary region and mid-frame.
	for _, cut := range []int{10, len(SealedMagic) + 4 + 20, len(sealed) - 1, len(sealed) - 16, len(sealed) - 200, len(sealed) / 2} {
		if _, err := open(kek, sealed[:cut], SealedKindDatabase, "bkp_1"); !errors.Is(err, ErrSealed) {
			t.Errorf("truncated at %d of %d accepted: %v", cut, len(sealed), err)
		}
	}
	// Dropping the final frame entirely (cut exactly after the second full frame).
	full := len(SealedMagic) + 4 + headerLen(sealed) + 2*(4+sealedFrameMax+16)
	if _, err := open(kek, sealed[:full], SealedKindDatabase, "bkp_1"); !errors.Is(err, ErrSealed) {
		t.Errorf("missing final frame accepted: %v", err)
	}
	if _, err := open(kek, append(append([]byte(nil), sealed...), 0), SealedKindDatabase, "bkp_1"); !errors.Is(err, ErrSealed) {
		t.Errorf("trailing data accepted: %v", err)
	}
	for _, pos := range []int{len(SealedMagic) + 4 + 3, len(sealed) / 3, len(sealed) - 5} {
		bad := append([]byte(nil), sealed...)
		bad[pos] ^= 0x40
		if _, err := open(kek, bad, SealedKindDatabase, "bkp_1"); err == nil {
			t.Errorf("bit flip at %d accepted", pos)
		}
	}
	// A wrapped key copied into another object's header does not open it (the AAD names the backup).
	other := seal(t, kek, []byte("x"), SealedKindDatabase, "bkp_2")
	swapped := append(append([]byte(nil), other[:len(SealedMagic)+4+headerLen(other)]...), sealed[len(SealedMagic)+4+headerLen(sealed):]...)
	if _, err := open(kek, swapped, SealedKindDatabase, "bkp_2"); err == nil {
		t.Error("frames of one object opened under another object's header")
	}
}

func headerLen(sealed []byte) int {
	return int(sealed[len(SealedMagic)])<<24 | int(sealed[len(SealedMagic)+1])<<16 | int(sealed[len(SealedMagic)+2])<<8 | int(sealed[len(SealedMagic)+3])
}

func FuzzOpenSealed(f *testing.F) {
	kek := testKEK(f)
	f.Add(seal(f, kek, []byte("hello"), SealedKindManifest, "bkp_1"))
	f.Add(seal(f, kek, nil, SealedKindManifest, "bkp_1"))
	f.Add([]byte(SealedMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _, err := OpenSealed(bytes.NewReader(b), kek, "", "")
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(r, 1<<20))
	})
}
