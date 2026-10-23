package ids

import (
	"strings"
	"testing"
)

// HP-TST-002: identifier parsing accepts only the expected prefix and canonical base32 body, and canonicalizes
// idempotently.
func FuzzParse(f *testing.F) {
	f.Add(Request, New(Request))
	f.Add(Request, strings.ToUpper(New(Request)))
	f.Add(Grant, New(Request))
	f.Add(Request, "req_")
	f.Add(Request, "req_"+strings.Repeat("z", 26))
	f.Add(Request, "req_"+strings.Repeat("0", 25)+"é")
	f.Fuzz(func(t *testing.T, prefix, id string) {
		got, err := Parse(prefix, id)
		if err != nil {
			if Valid(prefix, id) {
				t.Fatal("Valid disagrees with Parse")
			}
			return
		}
		body, ok := strings.CutPrefix(got, prefix+"_")
		if !ok || len(body) != encodedLen || body != strings.ToLower(body) || !strings.EqualFold(body, id[len(prefix)+1:]) {
			t.Fatalf("%q/%q canonicalized to %q", prefix, id, got)
		}
		again, err := Parse(prefix, got)
		if err != nil || again != got {
			t.Fatalf("not idempotent: %q -> %q (%v)", got, again, err)
		}
		if _, err := Time(got); err != nil {
			t.Fatalf("valid id without a timestamp: %v", err)
		}
	})
}
