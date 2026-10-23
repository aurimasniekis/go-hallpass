package slack

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
)

// Responder posts replies to response_url. *Client implements it.
type Responder interface {
	Respond(ctx context.Context, responseURL string, reply chat.Reply) error
}

// HandlerConfig configures a Handler.
type HandlerConfig struct {
	Verifier        *Verifier     // required
	Sink            chat.Sink     // required: the core
	TeamID          string        // required: the Slack workspace (team) ID
	Command         string        // default DefaultCommand
	ResponseURLBase string        // default DefaultResponseURLBase
	Responder       Responder     // optional: posts interaction replies; nil disables them
	ReplyTimeout    time.Duration // default 5s
	Clock           clock.Clock   // default clock.System
	Logger          *slog.Logger  // optional; never receives secrets, bodies or response URLs
}

// Handler serves Slack interactivity and slash-command requests. Mount it at /hooks/slack/interactions (and the
// slash-command URL). It verifies, parses and forwards; it never decides.
type Handler struct {
	cfg HandlerConfig
	wg  sync.WaitGroup
}

// NewHandler validates cfg and returns a Handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if cfg.Verifier == nil || cfg.Sink == nil {
		return nil, errors.New("slack: verifier and sink are required")
	}
	if !validSlackID(cfg.TeamID) {
		return nil, errors.New("slack: a valid team id is required")
	}
	if cfg.Command == "" {
		cfg.Command = DefaultCommand
	}
	if cfg.ResponseURLBase == "" {
		cfg.ResponseURLBase = DefaultResponseURLBase
	}
	if cfg.ReplyTimeout <= 0 {
		cfg.ReplyTimeout = 5 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Handler{cfg: cfg}, nil
}

// ServeHTTP implements http.Handler.
//
// Status codes: 405 non-POST; 413 too large; 401 bad signature or stale timestamp; 503 replay cache failure (fail
// closed); 403 other team; 400 malformed; 200 for replays and unsupported-but-authentic payloads (so Slack does not
// show errors for ignored clicks); 200 with an ephemeral JSON body for slash commands.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	now := h.cfg.Clock.Now()
	body, err := h.cfg.Verifier.Verify(r)
	if err != nil {
		h.reject(ctx, err, false, chat.Identity{}, now)
		h.writeStatus(w, chat.ReasonOf(err))
		return
	}
	in, err := ParseBody(body, ParseOptions{
		TeamID: h.cfg.TeamID, Command: h.cfg.Command, ResponseURLBase: h.cfg.ResponseURLBase, Now: now,
	})
	if err != nil {
		h.reject(ctx, err, true, chat.Identity{}, now)
		h.writeStatus(w, chat.ReasonOf(err))
		return
	}
	reply := in.LocalReply
	if in.Event != nil {
		reply = h.cfg.Sink.HandleEvent(ctx, *in.Event).Text
	}
	if in.IsCommand {
		writeEphemeral(w, reply)
		return
	}
	w.WriteHeader(http.StatusOK)
	if reply != "" && in.ResponseURL != "" && h.cfg.Responder != nil {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), h.cfg.ReplyTimeout)
			defer cancel()
			if err := h.cfg.Responder.Respond(rctx, in.ResponseURL, chat.Reply{Text: reply}); err != nil {
				h.cfg.Logger.WarnContext(rctx, "slack reply failed", slog.String("error.message", err.Error()))
			}
		}()
	}
}

// Wait blocks until in-flight asynchronous replies finish (for shutdown and tests).
func (h *Handler) Wait() { h.wg.Wait() }

func (h *Handler) reject(ctx context.Context, err error, authenticated bool, id chat.Identity, now time.Time) {
	h.cfg.Sink.Rejected(ctx, chat.Rejection{
		Provider: chat.ProviderSlack, Workspace: h.cfg.TeamID, Reason: chat.ReasonOf(err), Authenticated: authenticated,
		UserID: id.UserID, ChatID: id.ChatID, Err: err, At: now,
	})
}

func (h *Handler) writeStatus(w http.ResponseWriter, reason chat.RejectReason) {
	code := http.StatusBadRequest
	switch reason {
	case chat.RejectTooLarge:
		code = http.StatusRequestEntityTooLarge
	case chat.RejectBadSignature, chat.RejectStale:
		code = http.StatusUnauthorized
	case chat.RejectInternal:
		code = http.StatusServiceUnavailable
	case chat.RejectWorkspace:
		code = http.StatusForbidden
	case chat.RejectReplay, chat.RejectUnsupported:
		code = http.StatusOK
	}
	if code == http.StatusOK {
		w.WriteHeader(code)
		return
	}
	http.Error(w, http.StatusText(code), code)
}

func writeEphemeral(w http.ResponseWriter, text string) {
	if text == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	fallback, blocks := renderReply(text)
	body, err := json.Marshal(responseMessage{ResponseType: "ephemeral", Text: fallback, Blocks: blocks})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}
