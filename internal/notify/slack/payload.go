package slack

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
)

// Defaults for parsing.
const (
	DefaultCommand         = "/hallpass"
	DefaultResponseURLBase = "https://hooks.slack.com/"

	// actionPrefix versions the button payload format: "hp1:a:<token>" (approve) or "hp1:d:<token>" (deny).
	actionPrefix    = "hp1:"
	detailsActionID = "hp1:details" // URL button; Slack still posts an interaction, which is ignored
	maxSlackIDLen   = 32
	maxUserName     = 64
)

// ParseOptions configure ParseBody.
type ParseOptions struct {
	TeamID          string    // required: the only workspace accepted
	Command         string    // slash command name, default DefaultCommand
	ResponseURLBase string    // allowed response_url prefix, default DefaultResponseURLBase
	Now             time.Time // ReceivedAt stamp
}

// Inbound is a parsed, verified Slack request.
type Inbound struct {
	// Event is set for interactions, link and status commands.
	Event *chat.Event
	// LocalReply is set when the request is answered without the core (help, usage errors).
	LocalReply string
	// ResponseURL is the validated response_url, or empty if absent or not on the allowed host. It is a capability
	// URL: never log it.
	ResponseURL string
	// IsCommand is true for slash commands (reply synchronously in the HTTP response).
	IsCommand bool
}

// HelpText is the slash-command help.
const HelpText = "Hallpass commands: \"link <code>\" links your Slack account using a code from the Hallpass web UI; " +
	"\"status <request-id>\" shows a request's status."

type interactionPayload struct {
	Type string `json:"type"`
	Team struct {
		ID string `json:"id"`
	} `json:"team"`
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
	} `json:"user"`
	Channel *struct {
		ID string `json:"id"`
	} `json:"channel"`
	Container struct {
		Type      string `json:"type"`
		MessageTS string `json:"message_ts"`
		ChannelID string `json:"channel_id"`
	} `json:"container"`
	ResponseURL string `json:"response_url"`
	Actions     []struct {
		Type     string `json:"type"`
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
}

// ParseBody parses an authenticated request body (application/x-www-form-urlencoded): either an interactive payload
// ("payload" field) or a slash command ("command" field). Errors are *chat.RejectError.
func ParseBody(body []byte, o ParseOptions) (Inbound, error) {
	if o.Command == "" {
		o.Command = DefaultCommand
	}
	if o.ResponseURLBase == "" {
		o.ResponseURLBase = DefaultResponseURLBase
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "invalid form encoding")
	}
	for k, v := range form {
		if len(v) != 1 {
			return Inbound{}, chat.Reject(chat.RejectMalformed, "repeated form field %q", truncKey(k))
		}
	}
	switch {
	case form.Has("payload") && form.Has("command"):
		return Inbound{}, chat.Reject(chat.RejectMalformed, "ambiguous request")
	case form.Has("payload"):
		return parseInteraction([]byte(form.Get("payload")), o)
	case form.Has("command"):
		return parseCommand(form, o)
	}
	return Inbound{}, chat.Reject(chat.RejectUnsupported, "neither payload nor command")
}

func parseInteraction(raw []byte, o ParseOptions) (Inbound, error) {
	var p interactionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "invalid payload json")
	}
	if p.Type != "block_actions" {
		return Inbound{}, chat.Reject(chat.RejectUnsupported, "unsupported interaction type")
	}
	if !validSlackID(p.Team.ID) || !validSlackID(p.User.ID) {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "missing team or user id")
	}
	if p.Team.ID != o.TeamID {
		return Inbound{}, chat.Reject(chat.RejectWorkspace, "team not allowed")
	}
	if len(p.Actions) != 1 {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "expected exactly one action")
	}
	a := p.Actions[0]
	if a.Type != "button" || a.ActionID == detailsActionID {
		return Inbound{}, chat.Reject(chat.RejectUnsupported, "unsupported action element")
	}
	kind, token, ok := ParseActionID(a.ActionID)
	if !ok || a.Value != token {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "invalid action")
	}
	channel := p.Container.ChannelID
	if p.Channel != nil && p.Channel.ID != "" {
		if channel != "" && channel != p.Channel.ID {
			return Inbound{}, chat.Reject(chat.RejectMalformed, "inconsistent channel")
		}
		channel = p.Channel.ID
	}
	if !validSlackID(channel) {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "missing channel")
	}
	var ref chat.MessageRef
	if p.Container.Type == "message" && validTS(p.Container.MessageTS) {
		ref = chat.MessageRef{Provider: chat.ProviderSlack, ChatID: channel, MessageID: p.Container.MessageTS}
	}
	name := p.User.Username
	if name == "" {
		name = p.User.Name
	}
	ia := &chat.Interaction{
		Identity:      identity(p.Team.ID, p.User.ID, name, channel),
		ActionTokenID: token,
		Kind:          kind,
		Message:       ref,
		ReceivedAt:    o.Now,
	}
	return Inbound{
		Event:       &chat.Event{Kind: chat.EventInteraction, Interaction: ia},
		ResponseURL: validResponseURL(p.ResponseURL, o.ResponseURLBase),
	}, nil
}

func parseCommand(form url.Values, o ParseOptions) (Inbound, error) {
	if form.Get("command") != o.Command {
		return Inbound{}, chat.Reject(chat.RejectUnsupported, "unknown command")
	}
	team, user, channel := form.Get("team_id"), form.Get("user_id"), form.Get("channel_id")
	if !validSlackID(team) || !validSlackID(user) || !validSlackID(channel) {
		return Inbound{}, chat.Reject(chat.RejectMalformed, "missing team, user or channel id")
	}
	if team != o.TeamID {
		return Inbound{}, chat.Reject(chat.RejectWorkspace, "team not allowed")
	}
	in := Inbound{IsCommand: true, ResponseURL: validResponseURL(form.Get("response_url"), o.ResponseURLBase)}
	id := identity(team, user, form.Get("user_name"), channel)
	args := strings.Fields(form.Get("text"))
	sub := ""
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}
	switch {
	case sub == "link" && len(args) == 2:
		code, ok := chat.NormalizeLinkCode(args[1])
		if !ok {
			in.LocalReply = "Invalid link code. Usage: " + o.Command + " link <code>"
			return in, nil
		}
		in.Event = &chat.Event{Kind: chat.EventLink, Link: &chat.LinkRequest{Identity: id, Code: code, ReceivedAt: o.Now}}
	case sub == "status" && len(args) == 2:
		reqID, ok := parseRequestID(args[1])
		if !ok {
			in.LocalReply = "Invalid request ID. Usage: " + o.Command + " status <request-id>"
			return in, nil
		}
		in.Event = &chat.Event{Kind: chat.EventStatus, Status: &chat.StatusQuery{Identity: id, RequestID: reqID, ReceivedAt: o.Now}}
	default:
		in.LocalReply = HelpText
	}
	return in, nil
}

func parseRequestID(s string) (string, bool) {
	id, err := ids.Parse(ids.Request, s)
	return id, err == nil
}

func identity(team, user, name, channel string) chat.Identity {
	return chat.Identity{
		Provider:    chat.ProviderSlack,
		Workspace:   team,
		UserID:      user,
		UserName:    chat.CleanText(name, maxUserName),
		ChatID:      channel,
		PrivateChat: strings.HasPrefix(channel, "D"),
	}
}

// ActionID encodes a button's action_id: "hp1:a:<token>" or "hp1:d:<token>".
func ActionID(kind chat.ActionKind, token string) string {
	k := "d"
	if kind == chat.ActionApprove {
		k = "a"
	}
	return actionPrefix + k + ":" + token
}

// ParseActionID decodes an action_id produced by ActionID.
func ParseActionID(s string) (chat.ActionKind, string, bool) {
	rest, ok := strings.CutPrefix(s, actionPrefix)
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
	token := rest[2:]
	if !chat.ValidActionTokenID(token) {
		return "", "", false
	}
	return kind, token, true
}

// validSlackID accepts Slack object IDs (uppercase letters and digits, e.g. T…, U…, W…, C…, G…, D…).
func validSlackID(s string) bool {
	if len(s) < 2 || len(s) > maxSlackIDLen {
		return false
	}
	for i := range len(s) {
		if c := s[i]; !isUpperAlnum(c) {
			return false
		}
	}
	return true
}

func isUpperAlnum(c byte) bool { return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }

// validTS accepts Slack message timestamps ("1700000000.123456").
func validTS(s string) bool {
	sec, frac, ok := strings.Cut(s, ".")
	if !ok || sec == "" || frac == "" || len(s) > 32 {
		return false
	}
	for _, part := range []string{sec, frac} {
		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
	}
	return true
}

// validResponseURL returns s if it is under base (same scheme and host, path prefix, no user info, query or
// fragment), else "". This prevents a forged-but-signed payload from turning replies into SSRF.
func validResponseURL(s, base string) string {
	if s == "" || len(s) > 2000 {
		return ""
	}
	u, err := url.Parse(s)
	b, berr := url.Parse(base)
	if err != nil || berr != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return ""
	}
	if u.Scheme != b.Scheme || u.Host != b.Host || !strings.HasPrefix(u.Path, b.Path) || strings.Contains(u.Path, "..") {
		return ""
	}
	return u.String()
}

func truncKey(k string) string {
	return chat.CleanText(k, 32)
}
