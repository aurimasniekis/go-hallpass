package slack

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

// Published example from Slack's "Verifying requests from Slack" documentation.
const (
	docSecret = "8f742231b10e8888abcd99yyyzzz85a5"
	docTS     = "1531420618"
	docBody   = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&" +
		"channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&" +
		"response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&" +
		"trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
	docSig = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
)

const testSecret = "test-signing-secret-0123456789abcdef"

func newVerifier(t *testing.T, secret string, clk clock.Clock, replay chat.ReplayCache) *Verifier {
	t.Helper()
	if replay == nil {
		replay = chat.NewMemoryReplayCache(clk, 0)
	}
	v, err := NewVerifier(VerifierConfig{SigningSecret: redact.NewSecret(secret), Replay: replay, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func signedRequest(secret string, ts string, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/hooks/slack/interactions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set(HeaderTimestamp, ts)
	r.Header.Set(HeaderSignature, SignatureHeader([]byte(secret), ts, []byte(body)))
	return r
}

func TestSignatureVector(t *testing.T) {
	if got := SignatureHeader([]byte(docSecret), docTS, []byte(docBody)); got != docSig {
		t.Fatalf("signature = %s, want %s", got, docSig)
	}
	clk := clock.NewFake(time.Unix(1531420618+30, 0))
	v := newVerifier(t, docSecret, clk, nil)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(docBody))
	r.Header.Set(HeaderTimestamp, docTS)
	r.Header.Set(HeaderSignature, docSig)
	body, err := v.Verify(r)
	if err != nil || string(body) != docBody {
		t.Fatalf("doc vector rejected: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	body := "payload=%7B%7D"
	cases := []struct {
		name string
		req  func() *http.Request
		want chat.RejectReason
	}{
		{"wrong secret", func() *http.Request { return signedRequest("other-secret", ts, body) }, chat.RejectBadSignature},
		{"tampered body", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Body = io.NopCloser(strings.NewReader(body + "x"))
			r.ContentLength = -1
			return r
		}, chat.RejectBadSignature},
		{"skewed past", func() *http.Request {
			old := strconv.FormatInt(now.Add(-301*time.Second).Unix(), 10)
			return signedRequest(testSecret, old, body)
		}, chat.RejectStale},
		{"skewed future", func() *http.Request {
			f := strconv.FormatInt(now.Add(301*time.Second).Unix(), 10)
			return signedRequest(testSecret, f, body)
		}, chat.RejectStale},
		{"non-numeric ts", func() *http.Request { return signedRequest(testSecret, "17e8", body) }, chat.RejectStale},
		{"negative ts", func() *http.Request { return signedRequest(testSecret, "-1700000000", body) }, chat.RejectStale},
		{"huge ts", func() *http.Request { return signedRequest(testSecret, strings.Repeat("9", 30), body) }, chat.RejectStale},
		{"missing ts", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Header.Del(HeaderTimestamp)
			return r
		}, chat.RejectBadSignature},
		{"missing sig", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Header.Del(HeaderSignature)
			return r
		}, chat.RejectBadSignature},
		{"repeated sig", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Header.Add(HeaderSignature, r.Header.Get(HeaderSignature))
			return r
		}, chat.RejectBadSignature},
		{"v1 sig", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Header.Set(HeaderSignature, "v1="+strings.TrimPrefix(r.Header.Get(HeaderSignature), "v0="))
			return r
		}, chat.RejectBadSignature},
		{"short sig", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Header.Set(HeaderSignature, r.Header.Get(HeaderSignature)[:40])
			return r
		}, chat.RejectBadSignature},
		{"non-hex sig", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Header.Set(HeaderSignature, "v0="+strings.Repeat("zz", 32))
			return r
		}, chat.RejectBadSignature},
		{"too large by content-length", func() *http.Request {
			return signedRequest(testSecret, ts, strings.Repeat("a", DefaultMaxBody+1))
		}, chat.RejectTooLarge},
		{"too large chunked", func() *http.Request {
			r := signedRequest(testSecret, ts, strings.Repeat("a", DefaultMaxBody+1))
			r.ContentLength = -1
			return r
		}, chat.RejectTooLarge},
		{"read error", func() *http.Request {
			r := signedRequest(testSecret, ts, body)
			r.Body = io.NopCloser(errReader{})
			return r
		}, chat.RejectMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newVerifier(t, testSecret, clock.NewFake(now), nil)
			_, err := v.Verify(c.req())
			if chat.ReasonOf(err) != c.want {
				t.Fatalf("reason = %v (%v), want %s", chat.ReasonOf(err), err, c.want)
			}
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestVerifyWindowBoundaryAndReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clk := clock.NewFake(now)
	v := newVerifier(t, testSecret, clk, nil)
	edge := strconv.FormatInt(now.Add(-300*time.Second).Unix(), 10)
	if _, err := v.Verify(signedRequest(testSecret, edge, "a=1")); err != nil {
		t.Fatalf("edge of window rejected: %v", err)
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	req := func() *http.Request { return signedRequest(testSecret, ts, "a=2") }
	if _, err := v.Verify(req()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(req()); chat.ReasonOf(err) != chat.RejectReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	// Uppercase hex encodes the same MAC and must hit the same replay entry.
	r := req()
	r.Header.Set(HeaderSignature, "v0="+strings.ToUpper(strings.TrimPrefix(r.Header.Get(HeaderSignature), "v0=")))
	if _, err := v.Verify(r); chat.ReasonOf(err) != chat.RejectReplay {
		t.Fatalf("hex-case replay accepted: %v", err)
	}
	// A rejected (bad signature) request must not consume replay entries.
	clk.Advance(time.Second)
	ts2 := strconv.FormatInt(clk.Now().Unix(), 10)
	bad := signedRequest("wrong", ts2, "a=3")
	if _, err := v.Verify(bad); chat.ReasonOf(err) != chat.RejectBadSignature {
		t.Fatal(err)
	}
	if _, err := v.Verify(signedRequest(testSecret, ts2, "a=3")); err != nil {
		t.Fatalf("good request after bad one: %v", err)
	}
}

func TestVerifyReplayCacheFailureFailsClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newVerifier(t, testSecret, clock.NewFake(now), chattest.FailingReplay{})
	_, err := v.Verify(signedRequest(testSecret, strconv.FormatInt(now.Unix(), 10), "a=1"))
	if chat.ReasonOf(err) != chat.RejectInternal {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyBodyTooLarge(t *testing.T) {
	v, err := NewVerifier(VerifierConfig{SigningSecret: redact.NewSecret("s"), Replay: chat.NewMemoryReplayCache(nil, 0), MaxBody: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyBody(context.Background(), http.Header{}, bytes.Repeat([]byte("x"), 5)); chat.ReasonOf(err) != chat.RejectTooLarge {
		t.Fatal(err)
	}
}

func TestNewVerifierValidation(t *testing.T) {
	if _, err := NewVerifier(VerifierConfig{Replay: chat.NewMemoryReplayCache(nil, 0)}); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := NewVerifier(VerifierConfig{SigningSecret: redact.NewSecret("s")}); err == nil {
		t.Fatal("missing replay accepted")
	}
	v, err := NewVerifier(VerifierConfig{SigningSecret: redact.NewSecret("s"), Replay: chat.NewMemoryReplayCache(nil, 0)})
	if err != nil || v.maxBody != DefaultMaxBody || v.tolerance != DefaultTolerance {
		t.Fatal("defaults", err)
	}
}
