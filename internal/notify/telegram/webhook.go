package telegram

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/obs/redact"
)

// Webhook parameters.
const (
	HeaderSecretToken = "X-Telegram-Bot-Api-Secret-Token" //nolint:gosec // header name, not a credential
	DefaultMaxBody    = 64 << 10
	// ReplayTTL covers Telegram's redelivery window for unacknowledged updates (24 h) with margin.
	ReplayTTL = 48 * time.Hour
	// MinSecretTokenLen is the minimum accepted webhook secret length (PLAN §10.5 uses 32 random bytes, base64url).
	MinSecretTokenLen = 32
	maxSecretTokenLen = 256 // Telegram limit
	// MaxCallbackData is Telegram's callback_data limit in bytes.
	MaxCallbackData = 64

	callbackPrefix = "hp1:"
	maxUserName    = 64
)

// Allowlist decides which chats and users may interact. The core implements UserAllowed with provider_links
// (linked, enabled operators); StaticAllowlist serves configuration and tests. Errors fail closed.
type Allowlist interface {
	ChatAllowed(ctx context.Context, chatID int64) (bool, error)
	UserAllowed(ctx context.Context, userID int64) (bool, error)
}

// StaticAllowlist is a fixed Allowlist.
type StaticAllowlist struct {
	chats map[int64]bool
	users map[int64]bool
}

// NewStaticAllowlist returns an allowlist of the given chat and user IDs.
func NewStaticAllowlist(chats, users []int64) *StaticAllowlist {
	s := &StaticAllowlist{chats: map[int64]bool{}, users: map[int64]bool{}}
	for _, c := range chats {
		s.chats[c] = true
	}
	for _, u := range users {
		s.users[u] = true
	}
	return s
}

// ChatAllowed implements Allowlist.
func (s *StaticAllowlist) ChatAllowed(_ context.Context, id int64) (bool, error) {
	return s.chats[id], nil
}

// UserAllowed implements Allowlist.
func (s *StaticAllowlist) UserAllowed(_ context.Context, id int64) (bool, error) {
	return s.users[id], nil
}

// WebhookConfig configures a Webhook.
type WebhookConfig struct {
	SecretToken redact.Secret[string] // required; MinSecretTokenLen..256 chars of [A-Za-z0-9_-]
	BotID       string                // required; the workspace in provider_links (BotIDFromToken)
	BotUsername string                // optional; accepts "/link@<BotUsername>"
	Allowlist   Allowlist             // required
	Replay      chat.ReplayCache      // required
	Clock       clock.Clock           // default clock.System
	MaxBody     int64                 // default DefaultMaxBody
}

// Webhook verifies and parses Telegram webhook requests.
type Webhook struct {
	secretHash [sha256.Size]byte
	botID      string
	botUser    string
	allow      Allowlist
	replay     chat.ReplayCache
	clock      clock.Clock
	maxBody    int64
}

// NewWebhook validates cfg and returns a Webhook.
func NewWebhook(cfg WebhookConfig) (*Webhook, error) {
	if !ValidSecretToken(cfg.SecretToken.Reveal()) {
		return nil, errors.New("telegram: webhook secret token must be 32..256 characters of [A-Za-z0-9_-]")
	}
	if !validBotID(cfg.BotID) {
		return nil, errors.New("telegram: invalid bot id")
	}
	if cfg.Allowlist == nil || cfg.Replay == nil {
		return nil, errors.New("telegram: allowlist and replay cache are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	return &Webhook{
		secretHash: sha256.Sum256([]byte(cfg.SecretToken.Reveal())), botID: cfg.BotID,
		botUser: strings.ToLower(cfg.BotUsername), allow: cfg.Allowlist, replay: cfg.Replay, clock: cfg.Clock,
		maxBody: cfg.MaxBody,
	}, nil
}

// BotID returns the configured bot ID (the provider_links workspace).
func (wh *Webhook) BotID() string { return wh.botID }

// ValidSecretToken reports whether s is an acceptable webhook secret token.
func ValidSecretToken(s string) bool {
	if len(s) < MinSecretTokenLen || len(s) > maxSecretTokenLen {
		return false
	}
	for i := range len(s) {
		if !isB64URL(s[i]) {
			return false
		}
	}
	return true
}

// GenerateSecretToken returns a fresh webhook secret: 32 random bytes, base64url without padding (PLAN §10.5).
func GenerateSecretToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Inbound is a parsed, verified update.
type Inbound struct {
	Event *chat.Event
	// LocalReply is set when the update is answered without the core (/start, /help).
	LocalReply string
	// CallbackQueryID is set for callback queries; the handler always answers them.
	CallbackQueryID string
	// ReplyChatID is the chat to reply to for messages.
	ReplyChatID int64
	// Identity is set whenever the platform vouched for a user, including for allowlist rejections.
	Identity chat.Identity
}

type tgUser struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
}

type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      *tgChat `json:"chat"`
	Text      string  `json:"text"`
}

type tgCallback struct {
	ID      string     `json:"id"`
	From    *tgUser    `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUpdate struct {
	UpdateID      *int64      `json:"update_id"`
	Message       *tgMessage  `json:"message"`
	CallbackQuery *tgCallback `json:"callback_query"`
}

// HelpText answers /start and /help in a private chat.
const HelpText = "Hallpass approvals bot. To link your Telegram account, create a link code in the Hallpass web UI and " +
	"send /link <code> here."

// Verify checks the secret token and reads the bounded body. Errors are *chat.RejectError.
func (wh *Webhook) Verify(r *http.Request) ([]byte, error) {
	got := r.Header.Values(HeaderSecretToken)
	if len(got) != 1 {
		return nil, chat.Reject(chat.RejectBadSignature, "missing or repeated secret token")
	}
	gh := sha256.Sum256([]byte(got[0]))
	if subtle.ConstantTimeCompare(gh[:], wh.secretHash[:]) != 1 {
		return nil, chat.Reject(chat.RejectBadSignature, "secret token mismatch")
	}
	if r.ContentLength > wh.maxBody {
		return nil, chat.Reject(chat.RejectTooLarge, "body exceeds %d bytes", wh.maxBody)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, wh.maxBody+1))
	if err != nil {
		return nil, chat.Reject(chat.RejectMalformed, "read body: %w", err)
	}
	if int64(len(body)) > wh.maxBody {
		return nil, chat.Reject(chat.RejectTooLarge, "body exceeds %d bytes", wh.maxBody)
	}
	return body, nil
}

// Parse decodes an authenticated update, applies the replay cache and the allowlists, and returns the event.
// Errors are *chat.RejectError; the returned Inbound carries Identity and CallbackQueryID even on allowlist
// rejections so the caller can audit and acknowledge.
func (wh *Webhook) Parse(ctx context.Context, body []byte) (Inbound, error) {
	if int64(len(body)) > wh.maxBody {
		return Inbound{}, chat.Reject(chat.RejectTooLarge, "body exceeds %d bytes", wh.maxBody)
	}
	var u tgUpdate
	if err := json.Unmarshal(body, &u); err != nil {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "invalid update json")
	}
	if u.UpdateID == nil || *u.UpdateID < 0 {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "missing update_id")
	}
	now := wh.clock.Now()
	fresh, err := wh.replay.Remember(ctx, "telegram:"+wh.botID+":"+strconv.FormatInt(*u.UpdateID, 10), now.Add(ReplayTTL))
	if err != nil {
		return Inbound{}, chat.Reject(chat.RejectInternal, "replay cache: %w", err)
	}
	if !fresh {
		return Inbound{}, chat.Reject(chat.RejectReplay, "update already seen")
	}
	switch {
	case u.CallbackQuery != nil:
		return wh.parseCallback(ctx, u.CallbackQuery, now)
	case u.Message != nil:
		return wh.parseMessage(u.Message, now)
	}
	return Inbound{}, chat.Reject(chat.RejectUnsupported, "unsupported update type")
}

func (wh *Webhook) identity(from *tgUser, c *tgChat) chat.Identity {
	name := from.Username
	if name == "" {
		name = from.FirstName
	}
	return chat.Identity{
		Provider:    chat.ProviderTelegram,
		Workspace:   wh.botID,
		UserID:      strconv.FormatInt(from.ID, 10),
		UserName:    chat.CleanText(name, maxUserName),
		ChatID:      strconv.FormatInt(c.ID, 10),
		PrivateChat: c.Type == "private" && c.ID == from.ID,
	}
}

func (wh *Webhook) parseCallback(ctx context.Context, cb *tgCallback, now time.Time) (Inbound, error) {
	if cb.ID == "" || len(cb.ID) > 128 || cb.From == nil || cb.From.ID <= 0 {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "callback without id or sender")
	}
	in := Inbound{CallbackQueryID: cb.ID}
	if cb.From.IsBot {
		return in, chat.Reject(chat.RejectUserNotAllowed, "callback from a bot")
	}
	if cb.Message == nil || cb.Message.Chat == nil || cb.Message.MessageID <= 0 {
		return in, chat.Reject(chat.RejectUnsupported, "callback without an accessible message")
	}
	in.Identity = wh.identity(cb.From, cb.Message.Chat)
	ok, err := wh.allow.ChatAllowed(ctx, cb.Message.Chat.ID)
	if err != nil {
		return in, chat.Reject(chat.RejectInternal, "chat allowlist: %w", err)
	}
	if !ok {
		return in, chat.Reject(chat.RejectChatNotAllowed, "chat not allowlisted")
	}
	ok, err = wh.allow.UserAllowed(ctx, cb.From.ID)
	if err != nil {
		return in, chat.Reject(chat.RejectInternal, "user allowlist: %w", err)
	}
	if !ok {
		return in, chat.Reject(chat.RejectUserNotAllowed, "user not allowlisted")
	}
	kind, token, ok := ParseCallbackData(cb.Data)
	if !ok {
		return in, chat.Reject(chat.RejectMalformed, "invalid callback data")
	}
	in.Event = &chat.Event{Kind: chat.EventInteraction, Interaction: &chat.Interaction{
		Identity:      in.Identity,
		ActionTokenID: token,
		Kind:          kind,
		Message: chat.MessageRef{
			Provider: chat.ProviderTelegram, ChatID: in.Identity.ChatID, MessageID: strconv.FormatInt(cb.Message.MessageID, 10),
		},
		ReceivedAt: now,
	}}
	return in, nil
}

func (wh *Webhook) parseMessage(m *tgMessage, now time.Time) (Inbound, error) {
	if m.From == nil || m.Chat == nil || m.From.ID <= 0 || m.From.IsBot {
		return Inbound{}, chat.Reject(chat.RejectUnsupported, "message without a human sender")
	}
	in := Inbound{Identity: wh.identity(m.From, m.Chat), ReplyChatID: m.Chat.ID}
	cmd, args, ok := wh.command(m.Text)
	if !ok {
		return in, chat.Reject(chat.RejectUnsupported, "not a command")
	}
	private := in.Identity.PrivateChat
	switch {
	case cmd == "link":
		code, valid := "", len(args) == 1
		if valid {
			code, valid = chat.NormalizeLinkCode(args[0])
		}
		if !valid {
			if private {
				in.LocalReply = "Usage: /link <code>"
				return in, nil
			}
			return in, chat.Reject(chat.RejectMalformed, "invalid link command")
		}
		in.Event = &chat.Event{Kind: chat.EventLink, Link: &chat.LinkRequest{Identity: in.Identity, Code: code, ReceivedAt: now}}
		return in, nil
	case (cmd == "start" || cmd == "help") && private:
		in.LocalReply = HelpText
		return in, nil
	}
	return in, chat.Reject(chat.RejectUnsupported, "unsupported command")
}

// command splits "/cmd[@bot] args…". Commands addressed to another bot are not ours.
func (wh *Webhook) command(text string) (string, []string, bool) {
	if !strings.HasPrefix(text, "/") || len(text) > 512 {
		return "", nil, false
	}
	fields := strings.Fields(text)
	name := strings.ToLower(strings.TrimPrefix(fields[0], "/"))
	if base, bot, ok := strings.Cut(name, "@"); ok {
		if wh.botUser == "" || bot != wh.botUser {
			return "", nil, false
		}
		name = base
	}
	return name, fields[1:], name != ""
}

// CallbackData encodes a button's callback_data: "hp1:a:<token>" (approve) or "hp1:d:<token>" (deny).
func CallbackData(kind chat.ActionKind, token string) (string, error) {
	if !chat.ValidActionTokenID(token) {
		return "", errors.New("telegram: invalid action token id")
	}
	k := "d"
	if kind == chat.ActionApprove {
		k = "a"
	}
	s := callbackPrefix + k + ":" + token
	if len(s) > MaxCallbackData {
		return "", errors.New("telegram: callback_data exceeds 64 bytes")
	}
	return s, nil
}

// ParseCallbackData decodes callback_data produced by CallbackData.
func ParseCallbackData(s string) (chat.ActionKind, string, bool) {
	if len(s) > MaxCallbackData {
		return "", "", false
	}
	rest, ok := strings.CutPrefix(s, callbackPrefix)
	if !ok || len(rest) < 2 || rest[1] != ':' {
		return "", "", false
	}
	var kind chat.ActionKind
	switch rest[0] {
	case 'a':
		kind = chat.ActionApprove
	case 'd':
		kind = chat.ActionDeny
	default:
		return "", "", false
	}
	if !chat.ValidActionTokenID(rest[2:]) {
		return "", "", false
	}
	return kind, rest[2:], true
}

// BotIDFromToken returns the numeric bot ID prefix of a bot token ("123456:AA…" → "123456").
func BotIDFromToken(token string) (string, error) {
	id, secret, ok := strings.Cut(token, ":")
	if !ok || !validBotID(id) || len(secret) < 20 || len(secret) > 128 {
		return "", errors.New("telegram: malformed bot token")
	}
	for i := range len(secret) {
		if !isB64URL(secret[i]) {
			return "", errors.New("telegram: malformed bot token")
		}
	}
	return id, nil
}

func isB64URL(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func validBotID(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
}
