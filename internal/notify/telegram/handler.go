package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
)

// HandlerConfig configures a Handler.
type HandlerConfig struct {
	Webhook *Webhook    // required
	Sink    chat.Sink   // required: the core
	Clock   clock.Clock // default clock.System
}

// Handler serves the Telegram webhook (/hooks/telegram/{integration_id}). It verifies, parses and forwards; it
// never decides. Replies are returned in the webhook response body as a Bot API method call, so answering needs no
// extra request and no token.
type Handler struct {
	cfg HandlerConfig
}

// NewHandler validates cfg and returns a Handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if cfg.Webhook == nil || cfg.Sink == nil {
		return nil, errors.New("telegram: webhook and sink are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	return &Handler{cfg: cfg}, nil
}

type answerCallback struct {
	Method          string `json:"method,omitempty"`
	CallbackQueryID string `json:"callback_query_id"`
	Text            string `json:"text,omitempty"`
}

type replyMessage struct {
	Method             string      `json:"method"`
	ChatID             int64       `json:"chat_id"`
	Text               string      `json:"text"`
	LinkPreviewOptions linkPreview `json:"link_preview_options"`
}

// ServeHTTP implements http.Handler.
//
// Status codes: 405 non-POST; 401 wrong or missing secret token; 413 too large; 503 replay cache or allowlist
// failure (fail closed; Telegram retries); 200 for everything else, including ignored updates, so Telegram does not
// redeliver them. Callback queries that reach the core are always answered (PLAN §10.5); ignored callbacks are not.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	body, err := h.cfg.Webhook.Verify(r)
	if err != nil {
		h.reject(ctx, err, false, chat.Identity{})
		h.writeStatus(w, chat.ReasonOf(err))
		return
	}
	in, err := h.cfg.Webhook.Parse(ctx, body)
	if err != nil {
		h.reject(ctx, err, true, in.Identity)
		h.writeStatus(w, chat.ReasonOf(err))
		return
	}
	reply := in.LocalReply
	if in.Event != nil {
		reply = h.cfg.Sink.HandleEvent(ctx, *in.Event).Text
	}
	switch {
	case in.CallbackQueryID != "":
		writeJSON(w, answerCallback{
			Method: "answerCallbackQuery", CallbackQueryID: in.CallbackQueryID, Text: replyText(reply, MaxCallbackAlert),
		})
	case reply != "" && in.ReplyChatID != 0:
		writeJSON(w, replyMessage{
			Method: "sendMessage", ChatID: in.ReplyChatID, Text: replyText(reply, chat.MaxReplyRunes),
			LinkPreviewOptions: linkPreview{IsDisabled: true},
		})
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) reject(ctx context.Context, err error, authenticated bool, id chat.Identity) {
	h.cfg.Sink.Rejected(ctx, chat.Rejection{
		Provider: chat.ProviderTelegram, Workspace: h.cfg.Webhook.BotID(), Reason: chat.ReasonOf(err),
		Authenticated: authenticated, UserID: id.UserID, ChatID: id.ChatID, Err: err, At: h.cfg.Clock.Now(),
	})
}

func (h *Handler) writeStatus(w http.ResponseWriter, reason chat.RejectReason) {
	code := http.StatusOK
	switch reason {
	case chat.RejectBadSignature:
		code = http.StatusUnauthorized
	case chat.RejectTooLarge:
		code = http.StatusRequestEntityTooLarge
	case chat.RejectInternal:
		code = http.StatusServiceUnavailable
	}
	if code == http.StatusOK {
		w.WriteHeader(code)
		return
	}
	http.Error(w, http.StatusText(code), code)
}

func writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}
