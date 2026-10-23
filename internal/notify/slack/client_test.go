package slack

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

const testBotToken = "xoxb-123456789012-SECRETSECRETSECRET"

// fakeSlack is a minimal Slack Web API.
type fakeSlack struct {
	t       *testing.T
	mu      sync.Mutex
	calls   []fakeCall
	respond func(method string, body map[string]any) (int, http.Header, string)
}

type fakeCall struct {
	Method string
	Auth   string
	Body   map[string]any
}

func (f *fakeSlack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		f.t.Errorf("fake slack: invalid json: %v", err)
	}
	method := strings.TrimPrefix(r.URL.Path, "/api/")
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{Method: method, Auth: r.Header.Get("Authorization"), Body: body})
	f.mu.Unlock()
	status, h, resp := http.StatusOK, http.Header{}, `{"ok":true,"channel":"C0APPROVE","ts":"1700000000.000100"}`
	if f.respond != nil {
		status, h, resp = f.respond(method, body)
	}
	for k, v := range h {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, resp)
}

func (f *fakeSlack) last() fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func newFake(t *testing.T) (*fakeSlack, *Client, *httptest.Server) {
	t.Helper()
	f := &fakeSlack{t: t}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{
		BotToken: redact.NewSecret(testBotToken), BaseURL: srv.URL + "/api", ResponseURLBase: srv.URL + "/hooks/",
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, c, srv
}

func TestClientSend(t *testing.T) {
	f, c, _ := newFake(t)
	m := chattest.Message()
	ref, err := c.Send(context.Background(), chat.Destination{ID: "C0APPROVE"}, m)
	if err != nil {
		t.Fatal(err)
	}
	if ref != (chat.MessageRef{Provider: chat.ProviderSlack, ChatID: "C0APPROVE", MessageID: "1700000000.000100"}) {
		t.Fatalf("ref %+v", ref)
	}
	call := f.last()
	if call.Method != "chat.postMessage" || call.Auth != "Bearer "+testBotToken {
		t.Fatalf("call %s auth %q", call.Method, call.Auth)
	}
	b := call.Body
	if b["channel"] != "C0APPROVE" || b["parse"] != "none" || b["link_names"] != false || b["unfurl_links"] != false ||
		b["unfurl_media"] != false || b["text"] != fallbackText(m.RequestID) {
		t.Fatalf("body flags %v", b)
	}
	assertSafeBlocks(t, b["blocks"])
	if c.Name() != chat.ProviderSlack {
		t.Fatal("name")
	}
}

func TestClientSendFallsBackToDestinationChannel(t *testing.T) {
	f, c, _ := newFake(t)
	f.respond = func(string, map[string]any) (int, http.Header, string) {
		return 200, nil, `{"ok":true,"ts":"1.2"}`
	}
	ref, err := c.Send(context.Background(), chat.Destination{ID: "C0X"}, chattest.Message())
	if err != nil || ref.ChatID != "C0X" {
		t.Fatal(ref, err)
	}
	f.respond = func(string, map[string]any) (int, http.Header, string) { return 200, nil, `{"ok":true}` }
	if _, err := c.Send(context.Background(), chat.Destination{ID: "C0X"}, chattest.Message()); err == nil || chat.IsPermanent(err) {
		t.Fatal("missing ts must be a retryable error", err)
	}
}

func TestClientUpdate(t *testing.T) {
	f, c, _ := newFake(t)
	m := chattest.Message()
	ref := chat.MessageRef{Provider: chat.ProviderSlack, ChatID: "C0APPROVE", MessageID: "1700000000.000100"}
	u := chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateApproved, DecidedBy: "<!here> Ann", Duration: time.Hour, Original: &m}
	if err := c.Update(context.Background(), ref, u); err != nil {
		t.Fatal(err)
	}
	call := f.last()
	if call.Method != "chat.update" || call.Body["ts"] != ref.MessageID || call.Body["channel"] != ref.ChatID || call.Body["parse"] != "none" {
		t.Fatalf("%+v", call)
	}
	assertSafeBlocks(t, call.Body["blocks"])
	if s := mustJSON(call.Body["blocks"]); strings.Contains(s, `"actions"`) || !strings.Contains(s, "Approved by") {
		t.Fatalf("update blocks %s", s)
	}
	u.Original = nil
	if err := c.Update(context.Background(), ref, u); err != nil {
		t.Fatal(err)
	}
}

func TestClientInputValidation(t *testing.T) {
	f, c, _ := newFake(t)
	ctx := context.Background()
	m := chattest.Message()
	bad := chattest.Message()
	bad.Actions = nil
	ref := chat.MessageRef{Provider: chat.ProviderSlack, ChatID: "C0APPROVE", MessageID: "1.2"}
	errs := []error{
		func() error { _, err := c.Send(ctx, chat.Destination{ID: "#general"}, m); return err }(),
		func() error { _, err := c.Send(ctx, chat.Destination{ID: "C0X"}, bad); return err }(),
		c.Update(ctx, chat.MessageRef{Provider: "telegram", ChatID: "C0X", MessageID: "1.2"}, chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateDenied}),
		c.Update(ctx, chat.MessageRef{Provider: chat.ProviderSlack, ChatID: "C0X", MessageID: "x"}, chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateDenied}),
		c.Update(ctx, ref, chat.StatusUpdate{RequestID: m.RequestID, State: "pending"}),
		c.Update(ctx, ref, chat.StatusUpdate{RequestID: bad.RequestID, State: chat.StateDenied, Original: &bad}),
	}
	for i, err := range errs {
		if !chat.IsPermanent(err) {
			t.Errorf("%d: %v", i, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid input reached the API")
	}
}

func TestClientErrors(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		header    http.Header
		body      string
		permanent bool
		retry     time.Duration
		limited   bool
	}{
		{"http 429", 429, http.Header{"Retry-After": {"7"}}, `{"ok":false,"error":"ratelimited"}`, false, 7 * time.Second, true},
		{"ok false ratelimited", 200, http.Header{"Retry-After": {"3"}}, `{"ok":false,"error":"ratelimited"}`, false, 3 * time.Second, true},
		{"429 bad retry-after", 429, http.Header{"Retry-After": {"soon"}}, ``, false, 0, true},
		{"channel_not_found", 200, nil, `{"ok":false,"error":"channel_not_found"}`, true, 0, false},
		{"invalid_auth", 200, nil, `{"ok":false,"error":"invalid_auth"}`, true, 0, false},
		{"internal_error", 200, nil, `{"ok":false,"error":"internal_error"}`, false, 0, false},
		{"hostile error code", 200, nil, `{"ok":false,"error":"<!channel>\n` + testBotToken + `"}`, false, 0, false},
		{"http 500", 500, nil, `oops`, false, 0, false},
		{"http 404", 404, nil, `{}`, true, 0, false},
		{"http 302", 302, http.Header{"Location": {"http://127.0.0.1:1/steal"}}, ``, true, 0, false},
		{"not json", 200, nil, `<html>`, false, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, cl, _ := newFake(t)
			f.respond = func(string, map[string]any) (int, http.Header, string) { return c.status, c.header, c.body }
			_, err := cl.Send(context.Background(), chat.Destination{ID: "C0X"}, chattest.Message())
			if err == nil {
				t.Fatal("expected error")
			}
			if chat.IsPermanent(err) != c.permanent {
				t.Fatalf("permanent = %v: %v", chat.IsPermanent(err), err)
			}
			d, limited := chat.RetryAfter(err)
			if limited != c.limited || d != c.retry {
				t.Fatalf("retry %v %v: %v", d, limited, err)
			}
			assertNoSecret(t, err)
			if strings.ContainsAny(err.Error(), "<\n") {
				t.Fatalf("provider text not sanitized: %q", err.Error())
			}
			if len(f.calls) != 1 {
				t.Fatalf("redirect followed: %d calls", len(f.calls))
			}
		})
	}
}

func assertNoSecret(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range []string{testBotToken, "SECRETSECRETSECRET", "/hooks/"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks %q: %v", s, err)
		}
	}
}

func TestClientTransportErrors(t *testing.T) {
	// Timeout.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	c, err := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: srv.URL, Timeout: 50 * time.Millisecond, HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Send(context.Background(), chat.Destination{ID: "C0X"}, chattest.Message())
	if err == nil || chat.IsPermanent(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	assertNoSecret(t, err)
	// Connection refused.
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	c, _ = NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: url})
	_, err = c.Send(context.Background(), chat.Destination{ID: "C0X"}, chattest.Message())
	if err == nil || chat.IsPermanent(err) {
		t.Fatalf("refused: %v", err)
	}
	assertNoSecret(t, err)
	// Canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Update(ctx, chat.MessageRef{Provider: chat.ProviderSlack, ChatID: "C0X", MessageID: "1.2"},
		chat.StatusUpdate{RequestID: chattest.Message().RequestID, State: chat.StateExpired}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestTransportErrRedactsToken(t *testing.T) {
	c, _ := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken)})
	err := c.transportErr(errors.New("dial " + testBotToken))
	if strings.Contains(err.Error(), testBotToken) {
		t.Fatal(err)
	}
}

func TestClientRespond(t *testing.T) {
	var mu sync.Mutex
	var got map[string]any
	var auth string
	f, c, srv := newFake(t)
	_ = f
	hooks := http.NewServeMux()
	hooks.HandleFunc("/hooks/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
	})
	hooks.Handle("/api/", f)
	srv.Config.Handler = hooks
	if err := c.Respond(context.Background(), srv.URL+"/hooks/actions/T1/2/x", chat.Reply{Text: "Not linked <!channel>"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if auth != "" {
		t.Fatal("bot token sent to response_url")
	}
	if got["response_type"] != "ephemeral" || got["replace_original"] != false {
		t.Fatalf("%v", got)
	}
	assertSafeBlocks(t, got["blocks"])
	err := c.Respond(context.Background(), "https://evil.example/hooks/x", chat.Reply{Text: "x"})
	if !chat.IsPermanent(err) {
		t.Fatal("foreign response url accepted", err)
	}
}

func TestClientRespondErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), ResponseURLBase: srv.URL + "/hooks/"})
	err := c.Respond(context.Background(), srv.URL+"/hooks/expired", chat.Reply{Text: "x"})
	if !chat.IsPermanent(err) {
		t.Fatal(err)
	}
	assertNoSecret(t, err)
	srv.Close()
	err = c.Respond(context.Background(), srv.URL+"/hooks/expired", chat.Reply{Text: "x"})
	if err == nil || chat.IsPermanent(err) {
		t.Fatal(err)
	}
	assertNoSecret(t, err)
}

func TestNewClientValidation(t *testing.T) {
	for _, cfg := range []ClientConfig{
		{},
		{BotToken: redact.NewSecret("xoxb bad")},
		{BotToken: redact.NewSecret(testBotToken), BaseURL: "ftp://x"},
	} {
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
	c, err := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken)})
	if err != nil || c.base != DefaultBaseURL || c.timeout != DefaultTimeout || c.responseBase != DefaultResponseURLBase {
		t.Fatal(err)
	}
}

func TestSafeCodeAndRetryAfter(t *testing.T) {
	if safeCode("") != "unknown_error" || safeCode(strings.Repeat("a", 65)) != "unknown_error" || safeCode("ok_1") != "ok_1" {
		t.Fatal("safeCode")
	}
	if retryAfter(http.Header{"Retry-After": {"99999"}}) != 0 || retryAfter(http.Header{"Retry-After": {"-1"}}) != 0 {
		t.Fatal("retryAfter bounds")
	}
}
