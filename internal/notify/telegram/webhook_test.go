package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

const (
	testBotToken  = "123456789:AAH-secretSECRETsecretSECRET_xyz"
	testBotID     = "123456789"
	testSecret    = "webhook-secret-0123456789abcdefghijklmnop"
	approvalsChat = int64(-1001234567890)
	aliceID       = int64(42)
	malloryID     = int64(666)
)

type errAllow struct{ chatErr bool }

func (e errAllow) ChatAllowed(context.Context, int64) (bool, error) {
	if e.chatErr {
		return false, errors.New("db down")
	}
	return true, nil
}

func (errAllow) UserAllowed(context.Context, int64) (bool, error) {
	return false, errors.New("db down")
}

func newWebhook(t testing.TB, allow Allowlist, replay chat.ReplayCache) *Webhook {
	t.Helper()
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	if allow == nil {
		allow = NewStaticAllowlist([]int64{approvalsChat}, []int64{aliceID})
	}
	if replay == nil {
		replay = chat.NewMemoryReplayCache(clk, 0)
	}
	wh, err := NewWebhook(WebhookConfig{
		SecretToken: redact.NewSecret(testSecret), BotID: testBotID, BotUsername: "Hallpass_Bot", Allowlist: allow,
		Replay: replay, Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wh
}

var nextUpdate int64 = 1000

func callbackUpdate(mut func(u map[string]any)) []byte {
	nextUpdate++
	u := map[string]any{
		"update_id": nextUpdate,
		"callback_query": map[string]any{
			"id":            "4382bfdwdsb323b2d9",
			"from":          map[string]any{"id": aliceID, "is_bot": false, "first_name": "Alice", "username": "alice"},
			"chat_instance": "-1",
			"data":          "hp1:a:" + chattest.Token(2),
			"message": map[string]any{
				"message_id": 77, "date": 1700000000, "text": "Hallpass access request",
				"chat": map[string]any{"id": approvalsChat, "type": "supergroup", "title": "Approvals"},
			},
		},
	}
	if mut != nil {
		mut(u)
	}
	b, _ := json.Marshal(u)
	return b
}

func cb(u map[string]any) map[string]any { return u["callback_query"].(map[string]any) }

func messageUpdate(text string, chatID int64, chatType string, from int64) []byte {
	nextUpdate++
	b, _ := json.Marshal(map[string]any{
		"update_id": nextUpdate,
		"message": map[string]any{
			"message_id": 9, "date": 1700000000, "text": text,
			"from": map[string]any{"id": from, "is_bot": false, "first_name": "Alice"},
			"chat": map[string]any{"id": chatID, "type": chatType},
		},
	})
	return b
}

func hookRequest(secret string, body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/hooks/telegram/int_x", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		r.Header.Set(HeaderSecretToken, secret)
	}
	return r
}

func TestVerifySecretToken(t *testing.T) {
	wh := newWebhook(t, nil, nil)
	body := callbackUpdate(nil)
	if got, err := wh.Verify(hookRequest(testSecret, body)); err != nil || string(got) != string(body) {
		t.Fatal(err)
	}
	for name, r := range map[string]*http.Request{
		"missing": hookRequest("", body),
		"wrong":   hookRequest(testSecret[:len(testSecret)-1]+"X", body),
		"prefix":  hookRequest(testSecret[:10], body),
		"longer":  hookRequest(testSecret+"x", body),
		"repeated": func() *http.Request {
			r := hookRequest(testSecret, body)
			r.Header.Add(HeaderSecretToken, testSecret)
			return r
		}(),
	} {
		if _, err := wh.Verify(r); chat.ReasonOf(err) != chat.RejectBadSignature {
			t.Errorf("%s: %v", name, err)
		}
	}
	big := hookRequest(testSecret, []byte(strings.Repeat("x", DefaultMaxBody+1)))
	if _, err := wh.Verify(big); chat.ReasonOf(err) != chat.RejectTooLarge {
		t.Fatal(err)
	}
	big = hookRequest(testSecret, []byte(strings.Repeat("x", DefaultMaxBody+1)))
	big.ContentLength = -1
	if _, err := wh.Verify(big); chat.ReasonOf(err) != chat.RejectTooLarge {
		t.Fatal(err)
	}
	broken := hookRequest(testSecret, body)
	broken.Body = io.NopCloser(errReader{})
	if _, err := wh.Verify(broken); chat.ReasonOf(err) != chat.RejectMalformed {
		t.Fatal(err)
	}
	if _, err := wh.Parse(context.Background(), []byte(strings.Repeat("x", DefaultMaxBody+1))); chat.ReasonOf(err) != chat.RejectTooLarge {
		t.Fatal(err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestParseCallback(t *testing.T) {
	wh := newWebhook(t, nil, nil)
	in, err := wh.Parse(context.Background(), callbackUpdate(nil))
	if err != nil {
		t.Fatal(err)
	}
	if in.CallbackQueryID != "4382bfdwdsb323b2d9" || in.Event == nil || in.Event.Kind != chat.EventInteraction {
		t.Fatalf("%+v", in)
	}
	want := chat.Interaction{
		Identity: chat.Identity{
			Provider: chat.ProviderTelegram, Workspace: testBotID, UserID: "42", UserName: "alice", ChatID: "-1001234567890",
		},
		ActionTokenID: chattest.Token(2), Kind: chat.ActionApprove,
		Message:    chat.MessageRef{Provider: chat.ProviderTelegram, ChatID: "-1001234567890", MessageID: "77"},
		ReceivedAt: time.Unix(1_700_000_000, 0),
	}
	if *in.Event.Interaction != want {
		t.Fatalf("got %+v\nwant %+v", *in.Event.Interaction, want)
	}
}

func TestParseCallbackRejections(t *testing.T) {
	cases := map[string]struct {
		mut  func(u map[string]any)
		want chat.RejectReason
	}{
		"unlisted chat": {func(u map[string]any) {
			cb(u)["message"].(map[string]any)["chat"] = map[string]any{"id": -100999, "type": "group"}
		}, chat.RejectChatNotAllowed},
		"unlisted user": {func(u map[string]any) { cb(u)["from"] = map[string]any{"id": malloryID, "first_name": "M"} }, chat.RejectUserNotAllowed},
		"bot sender":    {func(u map[string]any) { cb(u)["from"] = map[string]any{"id": aliceID, "is_bot": true} }, chat.RejectUserNotAllowed},
		"no message":    {func(u map[string]any) { delete(cb(u), "message") }, chat.RejectUnsupported},
		"no sender":     {func(u map[string]any) { delete(cb(u), "from") }, chat.RejectMalformed},
		"no id":         {func(u map[string]any) { delete(cb(u), "id") }, chat.RejectMalformed},
		"foreign data":  {func(u map[string]any) { cb(u)["data"] = "approve" }, chat.RejectMalformed},
		"bad kind":      {func(u map[string]any) { cb(u)["data"] = "hp1:x:" + chattest.Token(2) }, chat.RejectMalformed},
		"long data":     {func(u map[string]any) { cb(u)["data"] = "hp1:a:" + strings.Repeat("a", 60) }, chat.RejectMalformed},
		"no update id":  {func(u map[string]any) { delete(u, "update_id") }, chat.RejectMalformed},
		"negative id":   {func(u map[string]any) { u["update_id"] = -5 }, chat.RejectMalformed},
		"edited msg": {func(u map[string]any) {
			delete(u, "callback_query")
			u["edited_message"] = map[string]any{}
		}, chat.RejectUnsupported},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			wh := newWebhook(t, nil, nil)
			in, err := wh.Parse(context.Background(), callbackUpdate(c.mut))
			if chat.ReasonOf(err) != c.want {
				t.Fatalf("reason %v (%v), want %s", chat.ReasonOf(err), err, c.want)
			}
			if in.Event != nil {
				t.Fatal("event despite rejection")
			}
		})
	}
	// Allowlist rejections carry the platform-vouched identity for auditing.
	wh := newWebhook(t, nil, nil)
	in, err := wh.Parse(context.Background(), callbackUpdate(func(u map[string]any) {
		cb(u)["from"] = map[string]any{"id": malloryID, "first_name": "M"}
	}))
	if chat.ReasonOf(err) != chat.RejectUserNotAllowed || in.Identity.UserID != "666" || in.Identity.ChatID != "-1001234567890" {
		t.Fatalf("%+v %v", in, err)
	}
	for _, json := range []string{`{`, `[]`, `{"update_id":"x"}`} {
		if _, err := wh.Parse(context.Background(), []byte(json)); chat.ReasonOf(err) != chat.RejectMalformed {
			t.Errorf("%s: %v", json, err)
		}
	}
}

func TestParseReplayAndFailures(t *testing.T) {
	wh := newWebhook(t, nil, nil)
	body := callbackUpdate(nil)
	if _, err := wh.Parse(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if _, err := wh.Parse(context.Background(), body); chat.ReasonOf(err) != chat.RejectReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	wh = newWebhook(t, nil, chattest.FailingReplay{})
	if _, err := wh.Parse(context.Background(), callbackUpdate(nil)); chat.ReasonOf(err) != chat.RejectInternal {
		t.Fatal(err)
	}
	for _, a := range []Allowlist{errAllow{chatErr: true}, errAllow{}} {
		wh = newWebhook(t, a, nil)
		if _, err := wh.Parse(context.Background(), callbackUpdate(nil)); chat.ReasonOf(err) != chat.RejectInternal {
			t.Fatalf("allowlist error must fail closed: %v", err)
		}
	}
}

func TestParseMessages(t *testing.T) {
	wh := newWebhook(t, nil, nil)
	ctx := context.Background()
	// /link in a private chat from a not-yet-allowlisted user is forwarded (bootstrap).
	in, err := wh.Parse(ctx, messageUpdate("/link abcd1234", malloryID, "private", malloryID))
	if err != nil || in.Event == nil || in.Event.Kind != chat.EventLink {
		t.Fatalf("%v %+v", err, in)
	}
	if l := in.Event.Link; l.Code != "ABCD1234" || !l.PrivateChat || l.UserID != "666" || l.Workspace != testBotID || in.ReplyChatID != malloryID {
		t.Fatalf("%+v", l)
	}
	in, err = wh.Parse(ctx, messageUpdate("/link@hallpass_bot ABCD1234", aliceID, "private", aliceID))
	if err != nil || in.Event == nil {
		t.Fatal(err)
	}
	// /link in a group is forwarded as non-private so the core burns the code.
	in, err = wh.Parse(ctx, messageUpdate("/link ABCD1234", approvalsChat, "supergroup", aliceID))
	if err != nil || in.Event == nil || in.Event.Link.PrivateChat {
		t.Fatalf("%v %+v", err, in)
	}
	// A "private" chat whose ID differs from the sender is not private.
	in, err = wh.Parse(ctx, messageUpdate("/link ABCD1234", 7, "private", aliceID))
	if err != nil || in.Event.Link.PrivateChat {
		t.Fatal("private mismatch")
	}
	local := map[string]string{
		"/link":            "Usage: /link <code>",
		"/link a b":        "Usage: /link <code>",
		"/link <!channel>": "Usage: /link <code>",
		"/start":           HelpText,
		"/HELP":            HelpText,
	}
	for text, want := range local {
		in, err := wh.Parse(ctx, messageUpdate(text, aliceID, "private", aliceID))
		if err != nil || in.Event != nil || in.LocalReply != want {
			t.Errorf("%q: %v %+v", text, err, in)
		}
	}
	rejected := map[string]chat.RejectReason{
		"hello":                        chat.RejectUnsupported,
		"/link@other_bot X1":           chat.RejectUnsupported,
		"/approve":                     chat.RejectUnsupported,
		"/":                            chat.RejectUnsupported,
		"/" + strings.Repeat("a", 600): chat.RejectUnsupported,
	}
	for text, want := range rejected {
		if _, err := wh.Parse(ctx, messageUpdate(text, aliceID, "private", aliceID)); chat.ReasonOf(err) != want {
			t.Errorf("%q: %v", text, err)
		}
	}
	if _, err := wh.Parse(ctx, messageUpdate("/start", approvalsChat, "group", aliceID)); chat.ReasonOf(err) != chat.RejectUnsupported {
		t.Fatal("/start in group answered")
	}
	if _, err := wh.Parse(ctx, messageUpdate("/link bad!", approvalsChat, "group", aliceID)); chat.ReasonOf(err) != chat.RejectMalformed {
		t.Fatal("bad link in group")
	}
	nextUpdate++
	noFrom, _ := json.Marshal(map[string]any{"update_id": nextUpdate, "message": map[string]any{"text": "/link X", "chat": map[string]any{"id": 1}}})
	if _, err := wh.Parse(ctx, noFrom); chat.ReasonOf(err) != chat.RejectUnsupported {
		t.Fatal("message without sender")
	}
	// Without a configured bot username, addressed commands are not ours.
	wh2, _ := NewWebhook(WebhookConfig{SecretToken: redact.NewSecret(testSecret), BotID: testBotID,
		Allowlist: NewStaticAllowlist(nil, nil), Replay: chat.NewMemoryReplayCache(nil, 0)})
	if _, err := wh2.Parse(ctx, messageUpdate("/link@hallpass_bot X1", aliceID, "private", aliceID)); chat.ReasonOf(err) != chat.RejectUnsupported {
		t.Fatal(err)
	}
}

func TestCallbackData(t *testing.T) {
	max := strings.Repeat("Z", chat.MaxActionTokenIDLen)
	for _, k := range []chat.ActionKind{chat.ActionApprove, chat.ActionDeny} {
		for _, tok := range []string{chattest.Token(1), max} {
			s, err := CallbackData(k, tok)
			if err != nil || len(s) > MaxCallbackData {
				t.Fatalf("%q %v", s, err)
			}
			kind, got, ok := ParseCallbackData(s)
			if !ok || kind != k || got != tok {
				t.Fatal("round trip")
			}
		}
	}
	if s, _ := CallbackData(chat.ActionApprove, chattest.Token(1)); s != "hp1:a:"+chattest.Token(1) || len(s) != 28 {
		t.Fatalf("format %q", s)
	}
	if _, err := CallbackData(chat.ActionApprove, max+"Z"); err == nil {
		t.Fatal("oversized token accepted")
	}
	for _, bad := range []string{"", "hp1:", "hp1:a", "hp1:ab", "hp1:a:short", "xx1:a:" + chattest.Token(1), strings.Repeat("a", 65)} {
		if _, _, ok := ParseCallbackData(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTokensAndSecrets(t *testing.T) {
	if id, err := BotIDFromToken(testBotToken); err != nil || id != testBotID {
		t.Fatal(id, err)
	}
	for _, bad := range []string{"", "123", "abc:AAAAAAAAAAAAAAAAAAAAAAAA", "0123:AAAAAAAAAAAAAAAAAAAAAAAA", "123:short",
		"123:AAAAAAAAAAAAAAAAAAAA AAAA", "123:" + strings.Repeat("A", 129), "-5:AAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := BotIDFromToken(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	s, err := GenerateSecretToken()
	if err != nil || !ValidSecretToken(s) || len(s) != 43 {
		t.Fatal(s, err)
	}
	s2, _ := GenerateSecretToken()
	if s == s2 {
		t.Fatal("secret not random")
	}
	for _, bad := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 257), strings.Repeat("a", 31) + "!"} {
		if ValidSecretToken(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestNewWebhookValidation(t *testing.T) {
	good := WebhookConfig{SecretToken: redact.NewSecret(testSecret), BotID: testBotID, Allowlist: NewStaticAllowlist(nil, nil), Replay: chat.NewMemoryReplayCache(nil, 0)}
	mut := func(f func(c *WebhookConfig)) WebhookConfig {
		c := good
		f(&c)
		return c
	}
	for name, cfg := range map[string]WebhookConfig{
		"short secret": mut(func(c *WebhookConfig) { c.SecretToken = redact.NewSecret("short") }),
		"bot id":       mut(func(c *WebhookConfig) { c.BotID = "bot" }),
		"allowlist":    mut(func(c *WebhookConfig) { c.Allowlist = nil }),
		"replay":       mut(func(c *WebhookConfig) { c.Replay = nil }),
	} {
		if _, err := NewWebhook(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	wh, err := NewWebhook(good)
	if err != nil || wh.maxBody != DefaultMaxBody || wh.BotID() != testBotID {
		t.Fatal(err)
	}
}

func FuzzParseUpdate(f *testing.F) {
	f.Add(callbackUpdate(nil))
	f.Add(messageUpdate("/link ABCD1234", aliceID, "private", aliceID))
	f.Add(messageUpdate("/start", aliceID, "private", aliceID))
	f.Add([]byte(`{"update_id":1,"callback_query":{"id":"x","from":{"id":42},"message":{"message_id":1,"chat":{"id":-1001234567890}},"data":"hp1:d:abcdefghij"}}`))
	for _, h := range chattest.Hostile[:8] {
		f.Add(callbackUpdate(func(u map[string]any) { cb(u)["data"] = h; cb(u)["from"].(map[string]any)["username"] = h }))
		f.Add(messageUpdate("/link "+h, aliceID, "private", aliceID))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		wh := newWebhook(t, nil, nil)
		in, err := wh.Parse(context.Background(), body)
		if err != nil {
			if _, ok := errors.AsType[*chat.RejectError](err); !ok {
				t.Fatalf("non-reject error %T", err)
			}
			if in.Event != nil {
				t.Fatal("event with error")
			}
			return
		}
		if in.Event == nil {
			if in.LocalReply == "" {
				t.Fatal("neither event nor reply")
			}
			return
		}
		id := in.Event.Identity()
		if id.Workspace != testBotID || id.Provider != chat.ProviderTelegram || len([]rune(id.UserName)) > maxUserName {
			t.Fatalf("identity %+v", id)
		}
		switch in.Event.Kind {
		case chat.EventInteraction:
			ia := in.Event.Interaction
			if id.ChatID != "-1001234567890" || id.UserID != "42" || !chat.ValidActionTokenID(ia.ActionTokenID) || in.CallbackQueryID == "" {
				t.Fatalf("interaction escaped allowlist: %+v", ia)
			}
		case chat.EventLink:
			if _, ok := chat.NormalizeLinkCode(in.Event.Link.Code); !ok {
				t.Fatal("bad link code")
			}
		default:
			t.Fatalf("unexpected kind %s", in.Event.Kind)
		}
	})
}

func FuzzParseCallbackData(f *testing.F) {
	f.Add("hp1:a:" + chattest.Token(1))
	f.Add("hp1:d:" + strings.Repeat("_", 40))
	f.Fuzz(func(t *testing.T, s string) {
		kind, tok, ok := ParseCallbackData(s)
		if !ok {
			return
		}
		again, err := CallbackData(kind, tok)
		if err != nil || again != s || len(s) > MaxCallbackData {
			t.Fatalf("%q -> %q %v", s, again, err)
		}
	})
}
