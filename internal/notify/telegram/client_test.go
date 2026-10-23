package telegram

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

// fakeBotAPI is a minimal Telegram Bot API.
type fakeBotAPI struct {
	t       *testing.T
	mu      sync.Mutex
	calls   []botCall
	respond func(method string, body map[string]any) (int, string)
}

type botCall struct {
	Method string
	Body   map[string]any
}

func (f *fakeBotAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := "/bot" + testBotToken + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, prefix)
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		f.t.Errorf("fake bot api: invalid json: %v", err)
	}
	f.mu.Lock()
	f.calls = append(f.calls, botCall{Method: method, Body: body})
	f.mu.Unlock()
	status, resp := http.StatusOK, `{"ok":true,"result":{"message_id":77,"chat":{"id":-1001234567890}}}`
	if f.respond != nil {
		status, resp = f.respond(method, body)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, resp)
}

func (f *fakeBotAPI) last() botCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func newFakeClient(t *testing.T) (*fakeBotAPI, *Client) {
	t.Helper()
	f := &fakeBotAPI{t: t}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: srv.URL + "/", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func assertNoToken(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	_, secret, _ := strings.Cut(testBotToken, ":")
	if strings.Contains(err.Error(), testBotToken) || strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the bot token: %v", err)
	}
}

func TestClientSend(t *testing.T) {
	f, c := newFakeClient(t)
	m := chattest.Message()
	ref, err := c.Send(context.Background(), chat.Destination{ID: "-1001234567890"}, m)
	if err != nil {
		t.Fatal(err)
	}
	if ref != (chat.MessageRef{Provider: chat.ProviderTelegram, ChatID: "-1001234567890", MessageID: "77"}) {
		t.Fatalf("%+v", ref)
	}
	call := f.last()
	b := call.Body
	if call.Method != "sendMessage" || b["chat_id"] != float64(-1001234567890) {
		t.Fatalf("%+v", call)
	}
	if _, ok := b["parse_mode"]; ok {
		t.Fatal("parse_mode must not be set")
	}
	if b["link_preview_options"].(map[string]any)["is_disabled"] != true {
		t.Fatal("link previews not disabled")
	}
	kb := b["reply_markup"].(map[string]any)["inline_keyboard"].([]any)
	if len(kb) != 2 {
		t.Fatalf("keyboard %v", kb)
	}
	if len(b["entities"].([]any)) == 0 || !strings.Contains(b["text"].(string), "build-bot") {
		t.Fatal("entities/text")
	}
	if c.Name() != chat.ProviderTelegram || c.BotID() != testBotID {
		t.Fatal("identity")
	}
}

func TestClientUpdate(t *testing.T) {
	f, c := newFakeClient(t)
	m := chattest.Message()
	ref := chat.MessageRef{Provider: chat.ProviderTelegram, ChatID: "-1001234567890", MessageID: "77"}
	u := chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateDenied, DecidedBy: "Ann", Original: &m}
	if err := c.Update(context.Background(), ref, u); err != nil {
		t.Fatal(err)
	}
	call := f.last()
	if call.Method != "editMessageText" || call.Body["message_id"] != float64(77) {
		t.Fatalf("%+v", call)
	}
	if kb := call.Body["reply_markup"].(map[string]any)["inline_keyboard"].([]any); len(kb) != 0 {
		t.Fatal("buttons not removed")
	}
	if !strings.Contains(call.Body["text"].(string), "Denied") {
		t.Fatal("status missing")
	}
	// Redelivered update: "message is not modified" is success.
	f.respond = func(string, map[string]any) (int, string) {
		return 400, `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified: specified new message content and reply markup are exactly the same"}`
	}
	if err := c.Update(context.Background(), ref, u); err != nil {
		t.Fatalf("not-modified must be success: %v", err)
	}
}

func TestClientValidation(t *testing.T) {
	f, c := newFakeClient(t)
	ctx := context.Background()
	m := chattest.Message()
	bad := chattest.Message()
	bad.Actions = nil
	st := chat.StatusUpdate{RequestID: m.RequestID, State: chat.StateExpired}
	ref := chat.MessageRef{Provider: chat.ProviderTelegram, ChatID: "-1", MessageID: "1"}
	errs := []error{
		func() error { _, err := c.Send(ctx, chat.Destination{ID: "@channel"}, m); return err }(),
		func() error { _, err := c.Send(ctx, chat.Destination{ID: "0"}, m); return err }(),
		func() error { _, err := c.Send(ctx, chat.Destination{ID: "007"}, m); return err }(),
		func() error { _, err := c.Send(ctx, chat.Destination{ID: "1"}, bad); return err }(),
		c.Update(ctx, chat.MessageRef{Provider: "slack", ChatID: "1", MessageID: "1"}, st),
		c.Update(ctx, chat.MessageRef{Provider: chat.ProviderTelegram, ChatID: "x", MessageID: "1"}, st),
		c.Update(ctx, chat.MessageRef{Provider: chat.ProviderTelegram, ChatID: "1", MessageID: "0"}, st),
		c.Update(ctx, ref, chat.StatusUpdate{RequestID: "x", State: chat.StateExpired}),
		c.Update(ctx, ref, chat.StatusUpdate{RequestID: bad.RequestID, State: chat.StateExpired, Original: &bad}),
		c.AnswerCallback(ctx, "", "x"),
		c.SetWebhook(ctx, "http://insecure.example/hook", redact.NewSecret(testSecret), false),
		c.SetWebhook(ctx, "https://ok.example/hook", redact.NewSecret("short"), false),
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

func TestClientAnswerAndSetWebhook(t *testing.T) {
	f, c := newFakeClient(t)
	f.respond = func(string, map[string]any) (int, string) { return 200, `{"ok":true,"result":true}` }
	if err := c.AnswerCallback(context.Background(), "cbid", "Approved\n"+strings.Repeat("x", 500)); err != nil {
		t.Fatal(err)
	}
	if b := f.last().Body; b["callback_query_id"] != "cbid" || len([]rune(b["text"].(string))) > MaxCallbackAlert {
		t.Fatal(b)
	}
	if err := c.SetWebhook(context.Background(), "https://hallpass.example/hooks/telegram/int_1", redact.NewSecret(testSecret), true); err != nil {
		t.Fatal(err)
	}
	b := f.last().Body
	if b["url"] != "https://hallpass.example/hooks/telegram/int_1" || b["secret_token"] != testSecret || b["drop_pending_updates"] != true {
		t.Fatal(b)
	}
	if up := b["allowed_updates"].([]any); len(up) != 2 || up[0] != "callback_query" || up[1] != "message" {
		t.Fatal(up)
	}
	f.respond = func(string, map[string]any) (int, string) { return 200, `{"ok":true,"result":{}}` }
	if _, err := c.Send(context.Background(), chat.Destination{ID: "5"}, chattest.Message()); err == nil || chat.IsPermanent(err) {
		t.Fatal("missing message_id must be retryable", err)
	}
	f.respond = func(string, map[string]any) (int, string) { return 200, `{"ok":true,"result":{"message_id":3}}` }
	if ref, err := c.Send(context.Background(), chat.Destination{ID: "5"}, chattest.Message()); err != nil || ref.ChatID != "5" {
		t.Fatal(ref, err)
	}
}

func TestClientErrors(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		permanent bool
		limited   bool
		retry     time.Duration
	}{
		{"429 retry_after", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 12","parameters":{"retry_after":12}}`, false, true, 12 * time.Second},
		{"429 no params", 429, `{"ok":false,"error_code":429}`, false, true, 0},
		{"429 not json", 429, `slow down`, false, true, 0},
		{"403 kicked", 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was kicked from the group chat"}`, true, false, 0},
		{"400 chat not found", 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`, true, false, 0},
		{"401 echoing token", 401, `{"ok":false,"error_code":401,"description":"Unauthorized ` + testBotToken + `"}`, true, false, 0},
		{"500", 500, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`, false, false, 0},
		{"502 html", 502, `<html>bad gateway</html>`, false, false, 0},
		{"200 not ok", 200, `{"ok":false,"description":"weird"}`, false, false, 0},
		{"302 redirect", 302, ``, false, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, cl := newFakeClient(t)
			f.respond = func(string, map[string]any) (int, string) { return c.status, c.body }
			_, err := cl.Send(context.Background(), chat.Destination{ID: "-1001234567890"}, chattest.Message())
			if err == nil {
				t.Fatal("expected error")
			}
			if chat.IsPermanent(err) != c.permanent {
				t.Fatalf("permanent=%v: %v", chat.IsPermanent(err), err)
			}
			if d, ok := chat.RetryAfter(err); ok != c.limited || d != c.retry {
				t.Fatalf("retry %v %v", d, ok)
			}
			assertNoToken(t, err)
		})
	}
}

func TestClientRetryAfterHeaderFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "9")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: srv.URL})
	err := c.AnswerCallback(context.Background(), "id", "x")
	if d, ok := chat.RetryAfter(err); !ok || d != 9*time.Second {
		t.Fatal(err)
	}
}

func TestClientRedirectNotFollowed(t *testing.T) {
	var stolen bool
	thief := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { stolen = true }))
	defer thief.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, thief.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: srv.URL})
	err := c.AnswerCallback(context.Background(), "id", "x")
	if err == nil || stolen {
		t.Fatalf("redirect followed (stolen=%v): %v", stolen, err)
	}
	assertNoToken(t, err)
}

func TestClientTransportErrorsNeverLeakToken(t *testing.T) {
	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(block)
	c, err := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: slow.URL, Timeout: 50 * time.Millisecond, HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Send(context.Background(), chat.Destination{ID: "1"}, chattest.Message())
	if err == nil || chat.IsPermanent(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	assertNoToken(t, err)

	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	c, _ = NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: deadURL})
	_, err = c.Send(context.Background(), chat.Destination{ID: "1"}, chattest.Message())
	if err == nil || chat.IsPermanent(err) {
		t.Fatalf("refused: %v", err)
	}
	assertNoToken(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = c.Update(ctx, chat.MessageRef{Provider: chat.ProviderTelegram, ChatID: "1", MessageID: "1"},
		chat.StatusUpdate{RequestID: chattest.Message().RequestID, State: chat.StateCanceled})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	assertNoToken(t, err)

	// An unresolvable host produces a *url.Error that embeds the full URL (and so the token) before unwrapping.
	c, _ = NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken), BaseURL: "http://hallpass-test.invalid"})
	err = c.AnswerCallback(context.Background(), "id", "x")
	if err == nil {
		t.Fatal("expected dns error")
	}
	assertNoToken(t, err)

	if got := c.transportErr(errors.New("x " + testBotToken)); strings.Contains(got.Error(), testBotToken) {
		t.Fatal(got)
	}
}

func TestNewClientValidation(t *testing.T) {
	for _, cfg := range []ClientConfig{
		{},
		{BotToken: redact.NewSecret("not-a-token")},
		{BotToken: redact.NewSecret(testBotToken), BaseURL: "file:///etc"},
	} {
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("accepted %v", cfg)
		} else {
			assertNoToken(t, err)
		}
	}
	c, err := NewClient(ClientConfig{BotToken: redact.NewSecret(testBotToken)})
	if err != nil || c.base != DefaultBaseURL || c.timeout != DefaultTimeout {
		t.Fatal(err)
	}
}
