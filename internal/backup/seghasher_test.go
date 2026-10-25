package backup

import (
	"crypto/sha256"
	"database/sql"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
)

func TestSegHasher(t *testing.T) {
	body := func(n int) []byte {
		b := append([]byte(hprec.Magic), 0, 0, 0, byte(n))
		b = append(b, make([]byte, n+2*hprec.SlotSize)...)
		return append(b, []byte("frames")...)
	}
	full := body(10)
	h := sha256.Sum256(full[:12+10])
	ct := sha256.Sum256([]byte("frames"))
	run := func(b []byte, rec sql.NullInt64, chunk int) string {
		s := newSegHasher(rec)
		for len(b) > 0 {
			k := min(chunk, len(b))
			_, _ = s.Write(b[:k])
			b = b[k:]
		}
		return s.check(h[:], ct[:])
	}
	for _, chunk := range []int{1, 7, 4096} {
		if p := run(full, sql.NullInt64{}, chunk); p != "" {
			t.Fatalf("chunk %d: %s", chunk, p)
		}
		if p := run(full, sql.NullInt64{Int64: int64(len(full)), Valid: true}, chunk); p != "" {
			t.Fatalf("limit chunk %d: %s", chunk, p)
		}
	}
	// Trailing bytes beyond the recorded size are not part of the frames region.
	if p := run(append(full, 'x'), sql.NullInt64{Int64: int64(len(full)), Valid: true}, 5); p != "" {
		t.Fatal(p)
	}
	for name, c := range map[string]struct {
		b    []byte
		rec  sql.NullInt64
		want string
	}{
		"short":       {full[:5], sql.NullInt64{}, "not an HPREC1"},
		"bad magic":   {append([]byte("XXXXXXXX"), full[8:]...), sql.NullInt64{}, "not an HPREC1"},
		"no slots":    {full[:40], sql.NullInt64{}, "truncated"},
		"zero header": {body(0), sql.NullInt64{}, "truncated"},
		"shorter":     {full, sql.NullInt64{Int64: int64(len(full)) + 5, Valid: true}, "shorter than recorded"},
		"frames":      {append(full[:len(full)-1], 'X'), sql.NullInt64{}, "ciphertext hash"},
	} {
		if p := run(c.b, c.rec, 3); !strings.Contains(p, c.want) {
			t.Errorf("%s: got %q want %q", name, p, c.want)
		}
	}
}
