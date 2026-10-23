package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

// Client defaults.
const (
	DefaultBaseURL = "https://api.telegram.org"
	DefaultTimeout = 10 * time.Second
	maxResponse    = 1 << 20
	maxDescription = 200
)

// AllowedUpdates is the setWebhook allowed_updates list (PLAN §10.5).
var AllowedUpdates = []string{"callback_query", "message"}

// ClientConfig configures a Client.
type ClientConfig struct {
	BotToken   redact.Secret[string] // required ("<bot id>:<secret>"); used only in the URL path, never logged
	BaseURL    string                // default DefaultBaseURL
	HTTPClient *http.Client          // optional; copied, redirects are always disabled
	Timeout    time.Duration         // per call, default DefaultTimeout
}

// Client calls the Telegram Bot API. It implements chat.Provider.
type Client struct {
	token   redact.Secret[string]
	botID   string
	base    string
	hc      *http.Client
	timeout time.Duration
}

var _ chat.Provider = (*Client)(nil)

// NewClient validates cfg and returns a Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	botID, err := BotIDFromToken(cfg.BotToken.Reveal())
	if err != nil {
		return nil, err
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if !chat.ValidHTTPURL(cfg.BaseURL) {
		return nil, errors.New("telegram: invalid base url")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	hc := &http.Client{Timeout: cfg.Timeout}
	if cfg.HTTPClient != nil {
		c := *cfg.HTTPClient
		hc = &c
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{token: cfg.BotToken, botID: botID, base: strings.TrimSuffix(cfg.BaseURL, "/"), hc: hc, timeout: cfg.Timeout}, nil
}

// Name implements chat.Provider.
func (*Client) Name() string { return chat.ProviderTelegram }

// BotID returns the bot's numeric ID (the provider_links workspace).
func (c *Client) BotID() string { return c.botID }

// linkPreview is link_preview_options (Bot API 7.0+). The deprecated disable_web_page_preview is deliberately not sent
// alongside it.
type linkPreview struct {
	IsDisabled bool `json:"is_disabled"`
}

type sendMessage struct {
	ChatID             int64           `json:"chat_id"`
	MessageID          int64           `json:"message_id,omitempty"`
	Text               string          `json:"text"`
	Entities           []entity        `json:"entities,omitempty"`
	ReplyMarkup        *inlineKeyboard `json:"reply_markup,omitempty"`
	LinkPreviewOptions linkPreview     `json:"link_preview_options"`
}

type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  *struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// Send implements chat.Provider (sendMessage).
func (c *Client) Send(ctx context.Context, dest chat.Destination, msg chat.ApprovalMessage) (chat.MessageRef, error) {
	chatID, err := parseChatID(dest.ID)
	if err != nil {
		return chat.MessageRef{}, err
	}
	if err := msg.Validate(); err != nil {
		return chat.MessageRef{}, fmt.Errorf("telegram: %w", err)
	}
	body, err := renderApproval(&msg)
	if err != nil {
		return chat.MessageRef{}, err
	}
	kb, err := keyboard(&msg)
	if err != nil {
		return chat.MessageRef{}, err
	}
	raw, err := c.call(ctx, "sendMessage", sendMessage{
		ChatID: chatID, Text: body.Text, Entities: body.Entities, ReplyMarkup: &kb,
		LinkPreviewOptions: linkPreview{IsDisabled: true},
	})
	if err != nil {
		return chat.MessageRef{}, err
	}
	var res struct {
		MessageID int64 `json:"message_id"`
		Chat      struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.MessageID <= 0 {
		return chat.MessageRef{}, errors.New("telegram: sendMessage: response without message_id")
	}
	if res.Chat.ID == 0 {
		res.Chat.ID = chatID
	}
	return chat.MessageRef{
		Provider: chat.ProviderTelegram, ChatID: strconv.FormatInt(res.Chat.ID, 10), MessageID: strconv.FormatInt(res.MessageID, 10),
	}, nil
}

// Update implements chat.Provider (editMessageText). The inline keyboard is removed and the outcome shown. A
// "message is not modified" answer counts as success (idempotent redelivery).
func (c *Client) Update(ctx context.Context, ref chat.MessageRef, u chat.StatusUpdate) error {
	if ref.Provider != chat.ProviderTelegram {
		return fmt.Errorf("telegram: %w: invalid message reference", chat.ErrPermanent)
	}
	chatID, err := parseChatID(ref.ChatID)
	if err != nil {
		return err
	}
	msgID, err := strconv.ParseInt(ref.MessageID, 10, 64)
	if err != nil || msgID <= 0 {
		return fmt.Errorf("telegram: %w: invalid message id", chat.ErrPermanent)
	}
	if err := u.Validate(); err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	if u.Original != nil {
		if err := u.Original.Validate(); err != nil {
			return fmt.Errorf("telegram: %w", err)
		}
	}
	body, err := renderStatus(&u)
	if err != nil {
		return err
	}
	_, err = c.call(ctx, "editMessageText", sendMessage{
		ChatID: chatID, MessageID: msgID, Text: body.Text, Entities: body.Entities,
		ReplyMarkup:        &inlineKeyboard{InlineKeyboard: [][]inlineButton{}},
		LinkPreviewOptions: linkPreview{IsDisabled: true},
	})
	if err != nil && errors.Is(err, errNotModified) {
		return nil
	}
	return err
}

// AnswerCallback calls answerCallbackQuery. Handler answers through the webhook response instead; this is for
// callers that answer asynchronously.
func (c *Client) AnswerCallback(ctx context.Context, callbackQueryID, text string) error {
	if callbackQueryID == "" || len(callbackQueryID) > 128 {
		return fmt.Errorf("telegram: %w: invalid callback query id", chat.ErrPermanent)
	}
	_, err := c.call(ctx, "answerCallbackQuery", answerCallback{
		CallbackQueryID: callbackQueryID, Text: replyText(text, MaxCallbackAlert),
	})
	return err
}

type setWebhook struct {
	URL                string   `json:"url"`
	SecretToken        string   `json:"secret_token"`
	AllowedUpdates     []string `json:"allowed_updates"`
	DropPendingUpdates bool     `json:"drop_pending_updates"`
}

// SetWebhook registers the webhook URL (https only) with the secret token and AllowedUpdates.
func (c *Client) SetWebhook(ctx context.Context, webhookURL string, secretToken redact.Secret[string], dropPending bool) error {
	u, err := url.Parse(webhookURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("telegram: %w: webhook url must be an absolute https url", chat.ErrPermanent)
	}
	if !ValidSecretToken(secretToken.Reveal()) {
		return fmt.Errorf("telegram: %w: invalid webhook secret token", chat.ErrPermanent)
	}
	_, err = c.call(ctx, "setWebhook", setWebhook{
		URL: webhookURL, SecretToken: secretToken.Reveal(), AllowedUpdates: AllowedUpdates, DropPendingUpdates: dropPending,
	})
	return err
}

var errNotModified = errors.New("message is not modified")

func (c *Client) call(ctx context.Context, method string, payload any) (json.RawMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("telegram: %s: encode: %w", method, err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+c.token.Reveal()+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("telegram: %s: cannot build request", method) // never wrap: it may contain the URL
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telegram: %s: %w", method, c.transportErr(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("telegram: %s: read response: %w", method, c.transportErr(err))
	}
	var res apiResponse
	jerr := json.Unmarshal(raw, &res)
	if jerr == nil && res.OK && resp.StatusCode == http.StatusOK {
		return res.Result, nil
	}
	return nil, c.apiError(method, resp, &res, jerr)
}

// apiError classifies a failure: 429 → rate limited (retry_after), 5xx or unparseable → retryable,
// "message is not modified" → errNotModified, other 4xx → permanent.
func (c *Client) apiError(method string, resp *http.Response, res *apiResponse, jerr error) error {
	code := resp.StatusCode
	if jerr == nil && res.ErrorCode != 0 {
		code = res.ErrorCode
	}
	desc := ""
	if jerr == nil {
		desc = c.redact(chat.CleanText(res.Description, maxDescription))
	}
	switch {
	case code == http.StatusTooManyRequests:
		var after time.Duration
		if jerr == nil && res.Parameters != nil && res.Parameters.RetryAfter > 0 && res.Parameters.RetryAfter <= 3600 {
			after = time.Duration(res.Parameters.RetryAfter) * time.Second
		} else if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 && n <= 3600 {
			after = time.Duration(n) * time.Second
		}
		return &chat.RateLimitError{Provider: chat.ProviderTelegram, Method: method, After: after}
	case code == http.StatusBadRequest && strings.Contains(desc, "message is not modified"):
		return fmt.Errorf("telegram: %s: %w", method, errNotModified)
	case code >= 500 || jerr != nil:
		return fmt.Errorf("telegram: %s: http %d %s", method, code, desc)
	case code >= 400:
		return fmt.Errorf("telegram: %s: %w: http %d %s", method, chat.ErrPermanent, code, desc)
	}
	return fmt.Errorf("telegram: %s: unexpected response (http %d) %s", method, code, desc)
}

// transportErr removes the request URL (which contains the bot token) from transport errors. Context errors stay
// matchable with errors.Is.
func (c *Client) transportErr(err error) error {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	if s := err.Error(); c.redact(s) != s {
		return errors.New("transport error (details redacted)")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("transport error: %w", err)
}

// redact removes the bot token, and its secret half, from s.
func (c *Client) redact(s string) string {
	tok := c.token.Reveal()
	s = strings.ReplaceAll(s, tok, redact.Redacted)
	if _, secret, ok := strings.Cut(tok, ":"); ok && secret != "" {
		s = strings.ReplaceAll(s, secret, redact.Redacted)
	}
	return s
}

func parseChatID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id == 0 || strconv.FormatInt(id, 10) != s {
		return 0, fmt.Errorf("telegram: %w: invalid chat id", chat.ErrPermanent)
	}
	return id, nil
}
