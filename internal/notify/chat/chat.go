package chat

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
)

// Provider names.
const (
	ProviderSlack    = "slack"
	ProviderTelegram = "telegram"
)

// Limits shared by all providers.
const (
	// MaxActionTokenIDLen bounds the opaque action-token ID carried in buttons (PLAN §10.3 tokens are 22 chars).
	MaxActionTokenIDLen = 40
	// MinActionTokenIDLen rejects obviously truncated or garbage token IDs.
	MinActionTokenIDLen = 8
	// MaxApproveActions bounds the approve buttons per message (PLAN §10.2: max 5 durations shown).
	MaxApproveActions = 5
	// MaxReasonRunes is the chat truncation bound for the agent-provided reason (PLAN §10.2).
	MaxReasonRunes = 500
	// MaxNameRunes bounds agent, server and role names in chat.
	MaxNameRunes = 100
	// MaxDescriptionRunes bounds server and role descriptions in chat.
	MaxDescriptionRunes = 200
	// MaxCapabilities bounds the number of capabilities listed; the rest are summarized.
	MaxCapabilities = 10
	// MaxCapabilityRunes bounds one capability label.
	MaxCapabilityRunes = 64
	// MaxReplyRunes bounds a Reply text.
	MaxReplyRunes = 1000
	// MaxLinkCodeLen bounds a user-typed link code (PLAN §10.6 codes are 8 chars; separators are tolerated).
	MaxLinkCodeLen = 32
)

// ActionKind is the kind of a button.
type ActionKind string

// Action kinds.
const (
	ActionApprove ActionKind = "approve"
	ActionDeny    ActionKind = "deny"
)

// Action is one button on an approval message. Each button has its own single-use action token (PLAN §10.3).
type Action struct {
	Kind ActionKind
	// Duration is the grant duration offered by an approve button. Zero for deny.
	Duration time.Duration
	// TokenID is the opaque action-token ID (base64url alphabet, MinActionTokenIDLen..MaxActionTokenIDLen chars).
	// It is the only thing a provider puts into button payloads.
	TokenID string
}

// ApprovalMessage is the content of a pending-request notification (HP-NTF-002). Every string field except RequestID,
// the token IDs and DetailsURL is untrusted and is cleaned and escaped by the provider. There are deliberately no fields
// for destination addresses, remote usernames or credentials (HP-NTF-004).
type ApprovalMessage struct {
	RequestID string // ids "req_…"

	AgentName           string
	AgentID             string
	AgentKeyFingerprint string

	Server            string // server alias
	ServerDescription string
	Role              string // role alias
	RoleDescription   string
	Capabilities      []string

	Reason            string // agent-provided, untrusted; truncated to MaxReasonRunes in chat
	RequestedDuration time.Duration
	ExpiresAt         time.Time

	// Actions holds 1..MaxApproveActions approve buttons (smallest duration first) and at most one deny button.
	Actions []Action
	// DetailsURL is the dashboard deep link (/requests/{id}); absolute http(s) URL, optional.
	DetailsURL string
}

// Destination addresses a chat: a Slack channel ID (C…/G…/D…) or a Telegram chat ID (decimal int64).
type Destination struct {
	ID string
}

// MessageRef identifies a delivered message so that it can be updated later. The core stores it (e.g. JSON-encoded as
// outbox ProviderRef).
type MessageRef struct {
	Provider  string `json:"provider"`
	ChatID    string `json:"chat_id"`
	MessageID string `json:"message_id"` // Slack ts, Telegram message_id
}

// DecisionState is the final state shown on an updated message.
type DecisionState string

// Decision states.
const (
	StateApproved DecisionState = "approved"
	StateDenied   DecisionState = "denied"
	StateExpired  DecisionState = "expired"
	StateCanceled DecisionState = "canceled"
)

// StatusUpdate replaces the buttons of a delivered message with the outcome.
type StatusUpdate struct {
	RequestID string
	State     DecisionState
	DecidedBy string        // operator display name; untrusted text, may be empty (expired, canceled)
	Duration  time.Duration // granted duration for StateApproved, else zero
	At        time.Time
	// Original, if set, is re-rendered without buttons above the outcome so the message keeps its context. If nil the
	// message is replaced by a compact status line.
	Original *ApprovalMessage
}

// Provider delivers and updates approval messages. Implementations are safe for concurrent use.
type Provider interface {
	Name() string
	Send(ctx context.Context, dest Destination, msg ApprovalMessage) (MessageRef, error)
	Update(ctx context.Context, ref MessageRef, u StatusUpdate) error
}

// Identity is the provider-verified identity of the user behind an inbound event. Provider, Workspace and UserID are
// the provider_links lookup key (HP-NTF-011). UserName is display-only and untrusted.
type Identity struct {
	Provider    string
	Workspace   string // Slack team ID; Telegram bot ID
	UserID      string // Slack user ID; Telegram from.id
	UserName    string // display only, cleaned, never used for mapping
	ChatID      string // Slack channel ID; Telegram chat ID
	PrivateChat bool   // Telegram private chat with the bot; Slack DM channel
}

// Interaction is a verified button click. It identifies who clicked what; it authorizes nothing.
type Interaction struct {
	Identity
	ActionTokenID string
	// Kind is the action encoded in the button. It is a hint only: the core must take the action from the token
	// record and reject a mismatch.
	Kind       ActionKind
	Message    MessageRef // the message the button was on, when known
	ReceivedAt time.Time
}

// LinkRequest is a user-typed link code from the provider (PLAN §10.6). The core verifies it.
type LinkRequest struct {
	Identity
	Code       string
	ReceivedAt time.Time
}

// StatusQuery asks for a request's status (Slack "/hallpass status <req>").
type StatusQuery struct {
	Identity
	RequestID  string
	ReceivedAt time.Time
}

// EventKind discriminates Event.
type EventKind string

// Event kinds.
const (
	EventInteraction EventKind = "interaction"
	EventLink        EventKind = "link"
	EventStatus      EventKind = "status"
)

// Event is a verified inbound event. Exactly one pointer matching Kind is set.
type Event struct {
	Kind        EventKind
	Interaction *Interaction
	Link        *LinkRequest
	Status      *StatusQuery
}

// Identity returns the identity of whichever event is set.
func (e Event) Identity() Identity {
	switch {
	case e.Interaction != nil:
		return e.Interaction.Identity
	case e.Link != nil:
		return e.Link.Identity
	case e.Status != nil:
		return e.Status.Identity
	}
	return Identity{}
}

// Reply is the short text shown back to the provider user (Slack ephemeral message, Telegram callback toast or chat
// reply). It is treated as untrusted text by the provider. Empty means no visible reply.
type Reply struct {
	Text string
}

// Sink is implemented by the core. Provider webhook handlers call HandleEvent for each verified event and Rejected for
// every refused request (for audit and metrics; the core rate limits auditing). HandleEvent must be fast: Slack
// expects an answer within 3 s.
type Sink interface {
	HandleEvent(ctx context.Context, ev Event) Reply
	Rejected(ctx context.Context, r Rejection)
}

// RejectReason classifies a refused inbound request.
type RejectReason string

// Reject reasons.
const (
	RejectTooLarge       RejectReason = "too_large"
	RejectStale          RejectReason = "stale_timestamp"
	RejectBadSignature   RejectReason = "bad_signature" // includes a wrong or missing Telegram secret token
	RejectReplay         RejectReason = "replay"
	RejectMalformed      RejectReason = "malformed"
	RejectUnsupported    RejectReason = "unsupported"
	RejectWorkspace      RejectReason = "wrong_workspace"
	RejectChatNotAllowed RejectReason = "chat_not_allowed"
	RejectUserNotAllowed RejectReason = "user_not_allowed"
	RejectInternal       RejectReason = "internal" // e.g. replay cache unavailable; fails closed
)

// Rejection describes a refused inbound request.
type Rejection struct {
	Provider  string
	Workspace string
	Reason    RejectReason
	// Authenticated is true when the platform was authenticated (valid signature or secret token), so UserID and
	// ChatID were vouched for by the platform. When false they are empty.
	Authenticated bool
	UserID        string
	ChatID        string
	Err           error
	At            time.Time
}

// RejectError is returned by inbound verification and parsing.
type RejectError struct {
	Reason RejectReason
	Err    error
}

func (e *RejectError) Error() string {
	if e.Err == nil {
		return "chat: rejected: " + string(e.Reason)
	}
	return "chat: rejected: " + string(e.Reason) + ": " + e.Err.Error()
}

func (e *RejectError) Unwrap() error { return e.Err }

// Reject returns a *RejectError.
func Reject(reason RejectReason, format string, args ...any) error {
	return &RejectError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// ReasonOf returns the RejectReason of err, or RejectInternal if err is not a *RejectError.
func ReasonOf(err error) RejectReason {
	if re, ok := errors.AsType[*RejectError](err); ok {
		return re.Reason
	}
	return RejectInternal
}

// Validate checks the message structure (not the untrusted text, which providers clean).
func (m *ApprovalMessage) Validate() error {
	if !ids.Valid(ids.Request, m.RequestID) {
		return fmt.Errorf("%w: invalid request id", ErrPermanent)
	}
	if len(m.Actions) == 0 {
		return fmt.Errorf("%w: no actions", ErrPermanent)
	}
	approves, denies := 0, 0
	seen := make(map[string]bool, len(m.Actions))
	for _, a := range m.Actions {
		if !ValidActionTokenID(a.TokenID) {
			return fmt.Errorf("%w: invalid action token id", ErrPermanent)
		}
		if seen[a.TokenID] {
			return fmt.Errorf("%w: duplicate action token id", ErrPermanent)
		}
		seen[a.TokenID] = true
		switch a.Kind {
		case ActionApprove:
			if a.Duration <= 0 {
				return fmt.Errorf("%w: approve action without duration", ErrPermanent)
			}
			approves++
		case ActionDeny:
			denies++
		default:
			return fmt.Errorf("%w: unknown action kind", ErrPermanent)
		}
	}
	if approves > MaxApproveActions || denies > 1 {
		return fmt.Errorf("%w: too many actions (%d approve, %d deny)", ErrPermanent, approves, denies)
	}
	if m.DetailsURL != "" && !ValidHTTPURL(m.DetailsURL) {
		return fmt.Errorf("%w: invalid details url", ErrPermanent)
	}
	return nil
}

// Validate checks a status update.
func (u *StatusUpdate) Validate() error {
	if !ids.Valid(ids.Request, u.RequestID) {
		return fmt.Errorf("%w: invalid request id", ErrPermanent)
	}
	switch u.State {
	case StateApproved, StateDenied, StateExpired, StateCanceled:
	default:
		return fmt.Errorf("%w: unknown decision state", ErrPermanent)
	}
	if u.Original != nil && u.Original.RequestID != u.RequestID {
		return fmt.Errorf("%w: original message belongs to another request", ErrPermanent)
	}
	return nil
}

// ValidHTTPURL reports whether s is an absolute http or https URL with a host and no user info.
func ValidHTTPURL(s string) bool {
	if len(s) > 2000 {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}
