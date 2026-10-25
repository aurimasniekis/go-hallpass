package httpapi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
)

// HP-TST-002, HP-API-004: opaque cursors decode only bounded JSON and round-trip exactly.
func FuzzDecodeCursor(f *testing.F) {
	f.Add(*encodeCursor(cursor{At: 1_700_000_000_000_000, ID: "req_01abc", Seq: 7}))
	f.Add(*encodeCursor(cursor{}))
	f.Add("")
	f.Add("e30")
	f.Add("not base64!")
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"t":1,"i":"x","s":-1,"extra":true}`)))
	f.Add(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("a"), 300)))
	// Non-canonical JSON: invalid UTF-8 grows to U+FFFD and <>& grow to < on re-encoding.
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"t":0,"i":"` + strings.Repeat("\xffM4", 60) + `"}`)))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"t":0,"i":"` + strings.Repeat("<", 40) + `"}`)))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"i":"x","t":1}`)))
	f.Fuzz(func(t *testing.T, raw string) {
		c, err := decodeCursor(raw)
		if err != nil {
			if apperr.CodeOf(err) != apperr.CodeInvalid {
				t.Fatalf("cursor error is not invalid-input: %v", err)
			}
			return
		}
		if raw == "" {
			if c != nil {
				t.Fatal("empty cursor decoded to a value")
			}
			return
		}
		if b, _ := base64.RawURLEncoding.DecodeString(raw); len(b) > 256 {
			t.Fatalf("oversized cursor accepted (%d bytes)", len(b))
		}
		again, err := decodeCursor(*encodeCursor(*c))
		if err != nil || *again != *c {
			t.Fatalf("round trip %+v -> %+v (%v)", c, again, err)
		}
	})
}

// HP-TST-002, HP-API-002: request bodies decode strictly (unknown fields and trailing data rejected) and every
// failure is a bounded invalid-input error, never a panic.
func FuzzDecodeBody(f *testing.F) {
	for _, s := range []string{``, `{}`, `{"name":"x","count":1,"tags":["a"]}`, `{"name":"x"} {}`, `{"bogus":1}`, `[]`, `null`,
		`{"name":` + strings.Repeat(`"`, 10), `{"count":1e400}`, `{"name":"\ud800"}`, strings.Repeat(`[`, 20000)} {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	type body struct {
		Name  string   `json:"name"`
		Count int      `json:"count"`
		Tags  []string `json:"tags"`
	}
	f.Fuzz(func(t *testing.T, data []byte, optional bool) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/x", bytes.NewReader(data))
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var v body
		err := decode(&gen.Call{W: w, R: r}, &v, optional)
		if err == nil {
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return
		}
		if apperr.CodeOf(err) != apperr.CodeInvalid {
			t.Fatalf("decode error is not invalid-input: %v", err)
		}
		if len(err.Error()) > 300 {
			t.Fatalf("unbounded error message (%d bytes)", len(err.Error()))
		}
	})
}

// HP-TST-002, HP-API-003: If-Match yields a positive version or an error.
func FuzzIfMatch(f *testing.F) {
	for _, s := range []string{``, `"3"`, `W/"3"`, `3`, `"0"`, `"-1"`, `"9223372036854775808"`, `W/""`, `*`} {
		f.Add(s, int64(0))
		f.Add(s, int64(5))
	}
	f.Fuzz(func(t *testing.T, h string, fallback int64) {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/x", nil)
		if h != "" {
			r.Header["If-Match"] = []string{h}
		}
		v, err := ifMatch(&gen.Call{R: r}, fallback)
		if err == nil && v <= 0 {
			t.Fatalf("non-positive version %d from %q (fallback %d)", v, h, fallback)
		}
	})
}
