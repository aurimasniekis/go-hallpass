package opauth

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// HP-TST-002, HP-AUTH-003: password normalization is NFKC, bounded, NUL-free and idempotent; it never truncates.
func FuzzNormalizePassword(f *testing.F) {
	for _, s := range []string{"correct horse battery", "ｐａｓｓｗｏｒｄ１２３４", "a\x00bcdefghijklm", strings.Repeat("ﷺ", 300),
		strings.Repeat("a", 1025), "éééééé"} {
		f.Add(s, 12)
	}
	f.Fuzz(func(t *testing.T, pw string, minBytes int) {
		minBytes = max(0, min(minBytes, 128))
		got, err := NormalizePassword(pw, minBytes)
		if err != nil {
			return
		}
		s := string(got)
		switch {
		case len(got) > MaxPasswordBytes || len(got) < minBytes:
			t.Fatalf("length %d outside [%d,%d]", len(got), minBytes, MaxPasswordBytes)
		case strings.ContainsRune(s, 0):
			t.Fatal("NUL accepted")
		case s != norm.NFKC.String(pw):
			t.Fatal("result is not the NFKC form of the input (truncated or altered)")
		case utf8.ValidString(pw) && !norm.NFKC.IsNormalString(s):
			t.Fatal("result is not NFKC-normal")
		}
		again, err := NormalizePassword(s, minBytes)
		if err != nil || string(again) != s {
			t.Fatalf("normalization not idempotent: %v", err)
		}
	})
}

// HP-TST-002, HP-AUTH-004: email normalization yields a lowercase, bounded, idempotent single address.
func FuzzNormalizeEmail(f *testing.F) {
	for _, s := range []string{"Alice@Example.com", " bob@example.com ", "Eve <eve@example.com>", "a@b", "@", "a@b,c@d", "\"a b\"@example.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, e string) {
		got, err := NormalizeEmail(e)
		if err != nil {
			return
		}
		if got != strings.ToLower(got) || len(got) > 254 || !strings.Contains(got, "@") || strings.ContainsAny(got, " <>,\r\n") && !strings.HasPrefix(got, "\"") {
			t.Fatalf("%q normalized to %q", e, got)
		}
		again, err := NormalizeEmail(got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q (%v)", got, again, err)
		}
	})
}

// HP-TST-002, HP-AUTH-007: a TOTP code verifies only when it equals a code of the ±1 step window newer than the last
// used step (no reuse).
func FuzzVerifyTOTP(f *testing.F) {
	secret := []byte("0123456789abcdefghij")
	now := time.Unix(1_800_000_000, 0)
	cur := TOTPStep(now)
	f.Add(TOTPCode(secret, cur), int64(0))
	f.Add(" "+TOTPCode(secret, cur-1)+"\n", int64(0))
	f.Add(TOTPCode(secret, cur+1), cur+1)
	f.Add(TOTPCode(secret, cur+2), int64(0))
	f.Add("000000", int64(0))
	f.Add("12345", int64(0))
	f.Fuzz(func(t *testing.T, code string, lastStep int64) {
		step, ok := VerifyTOTP(secret, code, now, lastStep)
		valid := map[string]int64{}
		for d := int64(-1); d <= 1; d++ {
			if cur+d > lastStep {
				valid[TOTPCode(secret, cur+d)] = max(valid[TOTPCode(secret, cur+d)], cur+d)
			}
		}
		want, exists := valid[strings.TrimSpace(code)]
		if ok != exists || (ok && step != want) {
			t.Fatalf("code %q last %d: got (%d,%v), want (%d,%v)", code, lastStep, step, ok, want, exists)
		}
	})
}
