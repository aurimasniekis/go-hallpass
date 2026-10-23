package slack

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
)

// HP-TST-002, HP-NTF-006: a Slack request is accepted only with a single fresh timestamp, a single v0 signature that
// equals HMAC-SHA256 over exactly that timestamp and body, and only once (replay cache).
func FuzzVerifyBody(f *testing.F) {
	now := time.Unix(1_800_000_000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	good := func(ts string, body []byte) string { return SignatureHeader([]byte(testSecret), ts, body) }
	f.Add(ts, good(ts, []byte("a=b")), []byte("a=b"), false)
	f.Add(ts, strings.ToUpper(good(ts, []byte("a=b"))), []byte("a=b"), false)
	f.Add(ts, good(ts, []byte("a=b")), []byte("a=c"), false)
	f.Add("0"+ts, good(ts, []byte("a=b")), []byte("a=b"), false)
	f.Add(strconv.FormatInt(now.Unix()-301, 10), "", []byte("x"), true)
	f.Add(" "+ts, "", []byte("x"), true)
	f.Add("+"+ts, "", []byte("x"), true)
	f.Add(ts, "v1="+strings.Repeat("0", 64), []byte(""), false)
	f.Fuzz(func(t *testing.T, tsHeader, sigHeader string, body []byte, signIt bool) {
		clk := clock.NewFake(now)
		v := newVerifier(t, testSecret, clk, chat.NewMemoryReplayCache(clk, 0))
		if signIt {
			sigHeader = good(tsHeader, body)
		}
		h := http.Header{}
		h.Set(HeaderTimestamp, tsHeader)
		h.Set(HeaderSignature, sigHeader)
		err := v.VerifyBody(context.Background(), h, body)
		if err != nil {
			return
		}
		mac, ok := parseSignature(sigHeader)
		if !ok || !hmac.Equal(mac, Sign([]byte(testSecret), tsHeader, body)) {
			t.Fatalf("bad signature accepted: ts %q sig %q", tsHeader, sigHeader)
		}
		n, perr := strconv.ParseInt(tsHeader, 10, 64)
		if perr != nil || strings.TrimLeft(tsHeader, "0123456789") != "" || n < now.Unix()-300 || n > now.Unix()+300 {
			t.Fatalf("stale or malformed timestamp accepted: %q", tsHeader)
		}
		// Replays (including hex-case variants of the same MAC) are refused.
		h.Set(HeaderSignature, "v0="+strings.ToUpper(hex.EncodeToString(mac)))
		if err := v.VerifyBody(context.Background(), h, body); err == nil {
			t.Fatal("replayed request accepted")
		}
		if len(body) > DefaultMaxBody {
			t.Fatalf("oversized body accepted (%d)", len(body))
		}
	})
}

// HP-TST-002, HP-NTF-006: action IDs round-trip exactly and carry a valid action token.
func FuzzParseActionID(f *testing.F) {
	f.Add(ActionID(chat.ActionApprove, chattest.Token(1)))
	f.Add(ActionID(chat.ActionDeny, chattest.Token(2)))
	f.Add("hp1:x:" + chattest.Token(1))
	f.Add("hp1:a:" + chattest.Token(1) + "\n")
	f.Fuzz(func(t *testing.T, s string) {
		kind, tok, ok := ParseActionID(s)
		if !ok {
			return
		}
		if !chat.ValidActionTokenID(tok) || ActionID(kind, tok) != s || !bytes.Equal([]byte(s), []byte(strings.TrimSpace(s))) {
			t.Fatalf("%q parsed to (%s,%q)", s, kind, tok)
		}
	})
}
