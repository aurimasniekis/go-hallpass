package slack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

type recordingResponder struct {
	mu    sync.Mutex
	urls  []string
	texts []string
	err   error
}

func (r *recordingResponder) Respond(_ context.Context, u string, reply chat.Reply) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.urls = append(r.urls, u)
	r.texts = append(r.texts, reply.Text)
	return r.err
}

type handlerFixture struct {
	h    *Handler
	sink *chattest.Sink
	resp *recordingResponder
	clk  *clock.Fake
}

func newHandler(t *testing.T, replay chat.ReplayCache) *handlerFixture {
	t.Helper()
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	if replay == nil {
		replay = chat.NewMemoryReplayCache(clk, 0)
	}
	v, err := NewVerifier(VerifierConfig{SigningSecret: redact.NewSecret(testSecret), Replay: replay, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	fx := &handlerFixture{sink: &chattest.Sink{}, resp: &recordingResponder{}, clk: clk}
	fx.h, err = NewHandler(HandlerConfig{Verifier: v, Sink: fx.sink, TeamID: testTeam, Responder: fx.resp, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return fx
}

func (fx *handlerFixture) do(body []byte, secret string) *httptest.ResponseRecorder {
	ts := strconv.FormatInt(fx.clk.Now().Unix(), 10)
	w := httptest.NewRecorder()
	fx.h.ServeHTTP(w, signedRequest(secret, ts, string(body)))
	fx.h.Wait()
	return w
}

func TestHandlerInteraction(t *testing.T) {
	fx := newHandler(t, nil)
	fx.sink.Reply = "Approved <!channel>"
	w := fx.do(formBody(interaction(nil)), testSecret)
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	events, rej := fx.sink.Snapshot()
	if len(events) != 1 || len(rej) != 0 || events[0].Interaction.ActionTokenID != chattest.Token(2) {
		t.Fatalf("%+v %+v", events, rej)
	}
	if len(fx.resp.urls) != 1 || fx.resp.urls[0] != "https://hooks.slack.com/actions/T0HALLPASS/1/abc" || fx.resp.texts[0] != "Approved <!channel>" {
		t.Fatalf("responder %+v", fx.resp)
	}
	// The same signed request again is a replay: acknowledged, not forwarded.
	w = fx.do(formBody(interaction(nil)), testSecret)
	if w.Code != http.StatusOK || fx.sink.LastRejection() != chat.RejectReplay {
		t.Fatalf("replay: %d %v", w.Code, fx.sink.LastRejection())
	}
	if events, _ := fx.sink.Snapshot(); len(events) != 1 {
		t.Fatal("replay forwarded")
	}
}

func TestHandlerNoReplyWithoutText(t *testing.T) {
	fx := newHandler(t, nil)
	fx.resp.err = errors.New("boom")
	fx.do(formBody(interaction(nil)), testSecret)
	if len(fx.resp.urls) != 0 {
		t.Fatal("empty reply posted")
	}
	fx.sink.Reply = "x"
	fx.clk.Advance(time.Second)
	fx.do(formBody(interaction(func(p map[string]any) { p["trigger_id"] = "2" })), testSecret)
	if len(fx.resp.urls) != 1 {
		t.Fatal("reply not attempted")
	}
}

func TestHandlerCommand(t *testing.T) {
	fx := newHandler(t, nil)
	fx.sink.Reply = "Linked as <@U1> & co"
	w := fx.do(command("link ABCD1234", nil), testSecret)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatal(w.Code, w.Header())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["response_type"] != "ephemeral" || resp["text"] != "Hallpass" {
		t.Fatalf("%v", resp)
	}
	assertSafeBlocks(t, resp["blocks"])
	if !strings.Contains(allText(w.Body.Bytes()), "Linked as &lt;@U1&gt; &amp; co") {
		t.Fatal(w.Body.String())
	}
	events, _ := fx.sink.Snapshot()
	if len(events) != 1 || events[0].Link.Code != "ABCD1234" {
		t.Fatal(events)
	}
	// Help is answered locally.
	fx.clk.Advance(time.Second)
	w = fx.do(command("help", nil), testSecret)
	if !strings.Contains(allText(w.Body.Bytes()), "link &lt;code&gt;") {
		t.Fatal(w.Body.String())
	}
	if events, _ := fx.sink.Snapshot(); len(events) != 1 {
		t.Fatal("help reached the core")
	}
	// Empty core reply → empty 200.
	fx.sink.Reply = ""
	fx.clk.Advance(time.Second)
	if w = fx.do(command("link ABCD1235", nil), testSecret); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal(w.Body.String())
	}
}

func TestHandlerRejections(t *testing.T) {
	cases := []struct {
		name   string
		body   []byte
		secret string
		status int
		reason chat.RejectReason
		auth   bool
	}{
		{"bad signature", formBody(interaction(nil)), "wrong", 401, chat.RejectBadSignature, false},
		{"wrong team", formBody(interaction(func(p map[string]any) { p["team"] = map[string]any{"id": "T0EVIL"} })), testSecret, 403, chat.RejectWorkspace, true},
		{"malformed", []byte("payload=%7B"), testSecret, 400, chat.RejectMalformed, true},
		{"unsupported", formBody(interaction(func(p map[string]any) { p["type"] = "shortcut" })), testSecret, 200, chat.RejectUnsupported, true},
		{"too large", []byte(strings.Repeat("a", DefaultMaxBody+1)), testSecret, 413, chat.RejectTooLarge, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newHandler(t, nil)
			w := fx.do(c.body, c.secret)
			if w.Code != c.status {
				t.Fatalf("status %d", w.Code)
			}
			events, rej := fx.sink.Snapshot()
			if len(events) != 0 || len(rej) != 1 || rej[0].Reason != c.reason || rej[0].Authenticated != c.auth ||
				rej[0].Provider != chat.ProviderSlack || rej[0].At.IsZero() {
				t.Fatalf("%+v %+v", events, rej)
			}
		})
	}
}

func TestHandlerStaleAndCacheFailure(t *testing.T) {
	fx := newHandler(t, nil)
	ts := strconv.FormatInt(fx.clk.Now().Add(-time.Hour).Unix(), 10)
	w := httptest.NewRecorder()
	fx.h.ServeHTTP(w, signedRequest(testSecret, ts, string(formBody(interaction(nil)))))
	if w.Code != 401 || fx.sink.LastRejection() != chat.RejectStale {
		t.Fatal(w.Code, fx.sink.LastRejection())
	}
	fx = newHandler(t, chattest.FailingReplay{})
	if w := fx.do(formBody(interaction(nil)), testSecret); w.Code != 503 || fx.sink.LastRejection() != chat.RejectInternal {
		t.Fatal(w.Code)
	}
	if events, _ := fx.sink.Snapshot(); len(events) != 0 {
		t.Fatal("event forwarded despite replay cache failure")
	}
}

func TestHandlerMethodAndConfig(t *testing.T) {
	fx := newHandler(t, nil)
	w := httptest.NewRecorder()
	fx.h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Fatal(w.Code)
	}
	v, _ := NewVerifier(VerifierConfig{SigningSecret: redact.NewSecret("s"), Replay: chat.NewMemoryReplayCache(nil, 0)})
	for _, cfg := range []HandlerConfig{
		{Sink: &chattest.Sink{}, TeamID: testTeam},
		{Verifier: v, TeamID: testTeam},
		{Verifier: v, Sink: &chattest.Sink{}, TeamID: "bad team"},
	} {
		if _, err := NewHandler(cfg); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
	h, err := NewHandler(HandlerConfig{Verifier: v, Sink: &chattest.Sink{}, TeamID: testTeam})
	if err != nil || h.cfg.Command != DefaultCommand || h.cfg.ReplyTimeout != 5*time.Second {
		t.Fatal(err)
	}
}

// TestHandlerEndToEndWithClient wires Handler → real Client.Respond → fake response_url server.
func TestHandlerEndToEndWithClient(t *testing.T) {
	var mu sync.Mutex
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer srv.Close()
	client, err := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), ResponseURLBase: srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	v, _ := NewVerifier(VerifierConfig{SigningSecret: redact.NewSecret(testSecret), Replay: chat.NewMemoryReplayCache(clk, 0), Clock: clk})
	sink := &chattest.Sink{Reply: "Your Slack account is not linked to a Hallpass approver."}
	h, _ := NewHandler(HandlerConfig{Verifier: v, Sink: sink, TeamID: testTeam, Responder: client, ResponseURLBase: srv.URL + "/", Clock: clk})
	body := formBody(interaction(func(p map[string]any) { p["response_url"] = srv.URL + "/actions/1" }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(testSecret, strconv.FormatInt(clk.Now().Unix(), 10), string(body)))
	h.Wait()
	mu.Lock()
	defer mu.Unlock()
	if w.Code != 200 || hits != 1 {
		t.Fatal(w.Code, hits)
	}
}
