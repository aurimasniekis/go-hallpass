package telegram

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat/chattest"
)

func newTestHandler(t *testing.T, wh *Webhook) (*Handler, *chattest.Sink) {
	t.Helper()
	if wh == nil {
		wh = newWebhook(t, nil, nil)
	}
	sink := &chattest.Sink{}
	h, err := NewHandler(HandlerConfig{Webhook: wh, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	return h, sink
}

func serve(h http.Handler, r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var body map[string]any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &body)
	}
	return w, body
}

func TestHandlerCallback(t *testing.T) {
	h, sink := newTestHandler(t, nil)
	sink.Reply = "Approved for 1h\nby you \u202e"
	w, body := serve(h, hookRequest(testSecret, callbackUpdate(nil)))
	if w.Code != 200 || body["method"] != "answerCallbackQuery" || body["callback_query_id"] != "4382bfdwdsb323b2d9" ||
		body["text"] != "Approved for 1h by you" {
		t.Fatalf("%d %v", w.Code, body)
	}
	events, rej := sink.Snapshot()
	if len(events) != 1 || len(rej) != 0 || events[0].Interaction.UserID != "42" {
		t.Fatal(events, rej)
	}
	// Empty core reply still answers the callback (stops the client spinner).
	sink.Reply = ""
	_, body = serve(h, hookRequest(testSecret, callbackUpdate(nil)))
	if body["method"] != "answerCallbackQuery" {
		t.Fatal(body)
	}
	if _, ok := body["text"]; ok {
		t.Fatal("empty text must be omitted")
	}
}

func TestHandlerLinkAndHelp(t *testing.T) {
	h, sink := newTestHandler(t, nil)
	sink.Reply = "Linked to operator Ann."
	w, body := serve(h, hookRequest(testSecret, messageUpdate("/link ABCD1234", malloryID, "private", malloryID)))
	if w.Code != 200 || body["method"] != "sendMessage" || body["chat_id"] != float64(malloryID) || body["text"] != "Linked to operator Ann." ||
		body["link_preview_options"].(map[string]any)["is_disabled"] != true {
		t.Fatal(w.Code, body)
	}
	_, body = serve(h, hookRequest(testSecret, messageUpdate("/start", aliceID, "private", aliceID)))
	if body["text"] != HelpText {
		t.Fatal(body)
	}
	if events, _ := sink.Snapshot(); len(events) != 1 {
		t.Fatal("help reached the core")
	}
	sink.Reply = ""
	if w, _ := serve(h, hookRequest(testSecret, messageUpdate("/link ABCD1234", aliceID, "private", aliceID))); w.Body.Len() != 0 {
		t.Fatal("empty reply produced a body")
	}
}

func TestHandlerRejections(t *testing.T) {
	cases := []struct {
		name   string
		req    func() *http.Request
		status int
		reason chat.RejectReason
		auth   bool
		user   string
	}{
		{"wrong secret", func() *http.Request { return hookRequest("x"+testSecret[1:], callbackUpdate(nil)) }, 401, chat.RejectBadSignature, false, ""},
		{"too large", func() *http.Request { return hookRequest(testSecret, []byte(strings.Repeat("x", DefaultMaxBody+1))) }, 413, chat.RejectTooLarge, false, ""},
		{"unlisted user", func() *http.Request {
			return hookRequest(testSecret, callbackUpdate(func(u map[string]any) { cb(u)["from"] = map[string]any{"id": malloryID} }))
		}, 200, chat.RejectUserNotAllowed, true, "666"},
		{"unlisted chat", func() *http.Request {
			return hookRequest(testSecret, callbackUpdate(func(u map[string]any) {
				cb(u)["message"].(map[string]any)["chat"] = map[string]any{"id": 5, "type": "group"}
			}))
		}, 200, chat.RejectChatNotAllowed, true, "42"},
		{"malformed", func() *http.Request { return hookRequest(testSecret, []byte("{")) }, 200, chat.RejectMalformed, true, ""},
		{"chatter", func() *http.Request {
			return hookRequest(testSecret, messageUpdate("hi", approvalsChat, "group", aliceID))
		}, 200, chat.RejectUnsupported, true, "42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, sink := newTestHandler(t, nil)
			w, _ := serve(h, c.req())
			if w.Code != c.status {
				t.Fatalf("status %d", w.Code)
			}
			events, rej := sink.Snapshot()
			if len(events) != 0 || len(rej) != 1 || rej[0].Reason != c.reason || rej[0].Authenticated != c.auth ||
				rej[0].UserID != c.user || rej[0].Workspace != testBotID || rej[0].Provider != chat.ProviderTelegram {
				t.Fatalf("%+v %+v", events, rej)
			}
		})
	}
}

func TestHandlerReplayAndFailClosed(t *testing.T) {
	h, sink := newTestHandler(t, nil)
	body := callbackUpdate(nil)
	serve(h, hookRequest(testSecret, body))
	w, resp := serve(h, hookRequest(testSecret, body))
	if w.Code != 200 || resp != nil || sink.LastRejection() != chat.RejectReplay {
		t.Fatal(w.Code, resp, sink.LastRejection())
	}
	h, sink = newTestHandler(t, newWebhook(t, nil, chattest.FailingReplay{}))
	if w, _ := serve(h, hookRequest(testSecret, callbackUpdate(nil))); w.Code != 503 || sink.LastRejection() != chat.RejectInternal {
		t.Fatal(w.Code)
	}
	if events, _ := sink.Snapshot(); len(events) != 0 {
		t.Fatal("forwarded despite cache failure")
	}
}

func TestHandlerMethodAndConfig(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	w, _ := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 405 || w.Header().Get("Allow") != "POST" {
		t.Fatal(w.Code)
	}
	if _, err := NewHandler(HandlerConfig{Sink: &chattest.Sink{}}); err == nil {
		t.Fatal("missing webhook accepted")
	}
	if _, err := NewHandler(HandlerConfig{Webhook: newWebhook(t, nil, nil)}); err == nil {
		t.Fatal("missing sink accepted")
	}
}
