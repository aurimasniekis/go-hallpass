package telegram

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// HP-TST-002, HP-NTF-007: the webhook accepts a request only with exactly one secret-token header equal to the
// configured secret, and bounds the body.
func FuzzWebhookVerify(f *testing.F) {
	f.Add(testSecret, true, []byte(`{"update_id":1}`))
	f.Add(testSecret+" ", true, []byte(`{}`))
	f.Add(strings.ToUpper(testSecret), true, []byte(`{}`))
	f.Add(testSecret, false, []byte(`{}`))
	f.Add("", true, []byte(`{}`))
	f.Fuzz(func(t *testing.T, token string, set bool, body []byte) {
		wh := newWebhook(t, nil, nil)
		r := httptest.NewRequest(http.MethodPost, "/hooks/telegram", strings.NewReader(string(body)))
		if set {
			r.Header[HeaderSecretToken] = []string{token}
		}
		got, err := wh.Verify(r)
		if err != nil {
			return
		}
		if !set || token != testSecret {
			t.Fatalf("wrong secret token accepted: %q (set=%v)", token, set)
		}
		if int64(len(got)) > wh.maxBody || string(got) != string(body) {
			t.Fatal("body altered or unbounded")
		}
	})
}

// HP-TST-002, HP-NTF-007: chat IDs parse only from their canonical, non-zero decimal form.
func FuzzParseChatID(f *testing.F) {
	for _, s := range []string{"-1001234567890", "42", "0", "+42", "042", " 42", "9223372036854775808", "-0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := parseChatID(s)
		if err != nil {
			return
		}
		if id == 0 || strconv.FormatInt(id, 10) != s {
			t.Fatalf("%q parsed to %d", s, id)
		}
	})
}
