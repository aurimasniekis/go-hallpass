package slack

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
	DefaultBaseURL = "https://slack.com/api/"
	DefaultTimeout = 10 * time.Second
	maxResponse    = 1 << 20
)

// ClientConfig configures a Client.
type ClientConfig struct {
	BotToken        redact.Secret[string] // required (xoxb-…); sent only in the Authorization header
	BaseURL         string                // default DefaultBaseURL
	ResponseURLBase string                // allowed response_url prefix, default DefaultResponseURLBase
	HTTPClient      *http.Client          // optional; copied, redirects are always disabled
	Timeout         time.Duration         // per call, default DefaultTimeout
}

// Client calls the Slack Web API. It implements chat.Provider.
type Client struct {
	token        redact.Secret[string]
	base         string
	responseBase string
	hc           *http.Client
	timeout      time.Duration
}

var _ chat.Provider = (*Client)(nil)

// NewClient validates cfg and returns a Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	tok := cfg.BotToken.Reveal()
	if tok == "" || strings.ContainsAny(tok, " \t\r\n") {
		return nil, errors.New("slack: bot token is required")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if !chat.ValidHTTPURL(cfg.BaseURL) {
		return nil, errors.New("slack: invalid base url")
	}
	if !strings.HasSuffix(cfg.BaseURL, "/") {
		cfg.BaseURL += "/"
	}
	if cfg.ResponseURLBase == "" {
		cfg.ResponseURLBase = DefaultResponseURLBase
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
	return &Client{token: cfg.BotToken, base: cfg.BaseURL, responseBase: cfg.ResponseURLBase, hc: hc, timeout: cfg.Timeout}, nil
}

// Name implements chat.Provider.
func (*Client) Name() string { return chat.ProviderSlack }

type postMessage struct {
	Channel     string  `json:"channel"`
	TS          string  `json:"ts,omitempty"`
	Text        string  `json:"text"`
	Blocks      []block `json:"blocks"`
	Parse       string  `json:"parse"`
	LinkNames   bool    `json:"link_names"`
	UnfurlLinks *bool   `json:"unfurl_links,omitempty"`
	UnfurlMedia *bool   `json:"unfurl_media,omitempty"`
}

type apiResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Channel string `json:"channel"`
	TS      string `json:"ts"`
}

// Send implements chat.Provider (chat.postMessage).
func (c *Client) Send(ctx context.Context, dest chat.Destination, msg chat.ApprovalMessage) (chat.MessageRef, error) {
	if !validSlackID(dest.ID) {
		return chat.MessageRef{}, fmt.Errorf("slack: %w: invalid channel id", chat.ErrPermanent)
	}
	if err := msg.Validate(); err != nil {
		return chat.MessageRef{}, fmt.Errorf("slack: %w", err)
	}
	f := false
	res, err := c.call(ctx, "chat.postMessage", postMessage{
		Channel: dest.ID, Text: fallbackText(msg.RequestID), Blocks: renderApproval(&msg, true),
		Parse: "none", UnfurlLinks: &f, UnfurlMedia: &f,
	})
	if err != nil {
		return chat.MessageRef{}, err
	}
	if !validTS(res.TS) {
		return chat.MessageRef{}, errors.New("slack: chat.postMessage: response without message ts")
	}
	ch := res.Channel
	if !validSlackID(ch) {
		ch = dest.ID
	}
	return chat.MessageRef{Provider: chat.ProviderSlack, ChatID: ch, MessageID: res.TS}, nil
}

// Update implements chat.Provider (chat.update). The buttons are removed and the outcome is shown.
func (c *Client) Update(ctx context.Context, ref chat.MessageRef, u chat.StatusUpdate) error {
	if ref.Provider != chat.ProviderSlack || !validSlackID(ref.ChatID) || !validTS(ref.MessageID) {
		return fmt.Errorf("slack: %w: invalid message reference", chat.ErrPermanent)
	}
	if err := u.Validate(); err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	if u.Original != nil {
		if err := u.Original.Validate(); err != nil {
			return fmt.Errorf("slack: %w", err)
		}
	}
	_, err := c.call(ctx, "chat.update", postMessage{
		Channel: ref.ChatID, TS: ref.MessageID, Text: "Hallpass access request " + u.RequestID + ": " + chat.StateLabel(u.State),
		Blocks: renderStatus(&u), Parse: "none",
	})
	return err
}

type responseMessage struct {
	ResponseType    string  `json:"response_type"`
	ReplaceOriginal bool    `json:"replace_original"`
	Text            string  `json:"text"`
	Blocks          []block `json:"blocks"`
}

// Respond posts an ephemeral reply to an interaction's response_url. The URL must be under ResponseURLBase; the bot
// token is not sent (response URLs are self-authenticating capability URLs and are never logged).
func (c *Client) Respond(ctx context.Context, responseURL string, reply chat.Reply) error {
	u := validResponseURL(responseURL, c.responseBase)
	if u == "" {
		return fmt.Errorf("slack: %w: response url not allowed", chat.ErrPermanent)
	}
	text, blocks := renderReply(reply.Text)
	body, err := json.Marshal(responseMessage{ResponseType: "ephemeral", Text: text, Blocks: blocks})
	if err != nil {
		return fmt.Errorf("slack: encode response: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("slack: respond: cannot build request")
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("slack: respond: %w", c.transportErr(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	if err := statusErr("respond", resp); err != nil {
		return err
	}
	return nil
}

func (c *Client) call(ctx context.Context, method string, payload any) (*apiResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("slack: %s: encode: %w", method, err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+method, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("slack: %s: cannot build request", method)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+c.token.Reveal())
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: %s: %w", method, c.transportErr(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("slack: %s: read response: %w", method, c.transportErr(err))
	}
	if err := statusErr(method, resp); err != nil {
		return nil, err
	}
	var res apiResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("slack: %s: invalid response json", method)
	}
	if !res.OK {
		return nil, apiError(method, res.Error, resp.Header)
	}
	return &res, nil
}

// statusErr classifies non-200 HTTP responses: 429 → rate limited, 5xx → retryable, other 4xx → permanent.
func statusErr(method string, resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return &chat.RateLimitError{Provider: chat.ProviderSlack, Method: method, After: retryAfter(resp.Header)}
	case resp.StatusCode >= 500:
		return fmt.Errorf("slack: %s: http %d", method, resp.StatusCode)
	default:
		return fmt.Errorf("slack: %s: %w: http %d", method, chat.ErrPermanent, resp.StatusCode)
	}
}

// permanentErrors are Slack error codes that retrying cannot fix.
var permanentErrors = map[string]bool{
	"channel_not_found": true, "not_in_channel": true, "is_archived": true, "msg_too_long": true, "no_text": true,
	"invalid_blocks": true, "invalid_blocks_format": true, "too_many_attachments": true, "restricted_action": true,
	"invalid_auth": true, "not_authed": true, "account_inactive": true, "token_revoked": true, "token_expired": true,
	"no_permission": true, "missing_scope": true, "org_login_required": true, "ekm_access_denied": true,
	"invalid_arguments": true, "invalid_arg_name": true, "invalid_charset": true, "invalid_form_data": true,
	"invalid_post_type": true, "missing_post_type": true, "message_not_found": true, "cant_update_message": true,
	"edit_window_closed": true, "team_access_not_granted": true, "access_denied": true, "not_allowed_token_type": true,
	"method_deprecated": true, "deprecated_endpoint": true, "invalid_json": true, "json_not_object": true,
	"channel_is_archived": true, "user_not_found": true, "duplicate_channel_not_found": true,
}

func apiError(method, code string, h http.Header) error {
	code = safeCode(code)
	switch {
	case code == "ratelimited" || code == "rate_limited":
		return &chat.RateLimitError{Provider: chat.ProviderSlack, Method: method, After: retryAfter(h)}
	case permanentErrors[code]:
		return fmt.Errorf("slack: %s: %w: %s", method, chat.ErrPermanent, code)
	}
	return fmt.Errorf("slack: %s: %s", method, code)
}

// safeCode bounds a Slack error code to [a-z0-9_]{1,64} so provider output cannot inject into logs.
func safeCode(s string) string {
	if s == "" || len(s) > 64 {
		return "unknown_error"
	}
	for i := range len(s) {
		if c := s[i]; !isLowerCode(c) {
			return "unknown_error"
		}
	}
	return s
}

func isLowerCode(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' }

func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 3600 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// transportErr strips the request URL (a response_url is a capability) and guards against any token echo. Context
// errors stay matchable with errors.Is.
func (c *Client) transportErr(err error) error {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	if tok := c.token.Reveal(); tok != "" && strings.Contains(err.Error(), tok) {
		return errors.New("transport error (details redacted)")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("transport error: %w", err)
}
