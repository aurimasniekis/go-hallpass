package grammar

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// JSON document schema identifiers (HP-SSH-018). Field additions are allowed within /v1; removals and renames are not.
const (
	SchemaList     = "hallpass.list/v1"
	SchemaRoles    = "hallpass.roles/v1"
	SchemaRequest  = "hallpass.request/v1"
	SchemaStatus   = "hallpass.status/v1"
	SchemaSessions = "hallpass.sessions/v1"
	SchemaWhoAmI   = "hallpass.whoami/v1"
	SchemaVersion  = "hallpass.version/v1"
	SchemaError    = "hallpass.error/v1"
)

// GrammarVersion is the agent command grammar version reported by "version".
const GrammarVersion = "1"

// Schemas returns every published schema identifier.
func Schemas() []string {
	return []string{SchemaList, SchemaRoles, SchemaRequest, SchemaStatus, SchemaSessions, SchemaWhoAmI, SchemaVersion, SchemaError}
}

// Role levels as shown to agents.
const (
	LevelVisible     = "visible"
	LevelRequestable = "requestable"
	LevelAuto        = "auto"
)

// Time is a timestamp encoded as RFC 3339 UTC with second precision ("2026-10-23T14:02:11Z").
type Time time.Time

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + FormatTime(time.Time(t)) + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	*t = Time(v.UTC())
	return nil
}

// FormatTime formats t as RFC 3339 UTC with second precision.
func FormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// TimePtr returns a *Time for t, or nil for the zero time.
func TimePtr(t time.Time) *Time {
	if t.IsZero() {
		return nil
	}
	v := Time(t)
	return &v
}

// Duration is a duration encoded as a compact Go duration string ("30m", "1h30m", "2m5s").
type Duration time.Duration

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + FormatDuration(time.Duration(d)) + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// FormatDuration formats d as a Go duration string without redundant zero units: 30m0s → 30m, 1h0m0s → 1h. The
// result always parses with time.ParseDuration.
func FormatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// NullString encodes "" as JSON null.
type NullString string

// MarshalJSON implements json.Marshaler.
func (s NullString) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte("null"), nil
	}
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *NullString) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*s = ""
		return nil
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = NullString(v)
	return nil
}

// remaining is the whole seconds left until t, never negative.
func remaining(now, t time.Time) Duration {
	d := t.Sub(now).Truncate(time.Second)
	if d < 0 {
		d = 0
	}
	return Duration(d)
}

// ActiveGrant summarizes the agent's active grant on a role.
type ActiveGrant struct {
	GrantID   string   `json:"grant_id"`
	ExpiresAt Time     `json:"expires_at"`
	Remaining Duration `json:"remaining"` // computed by the builders
}

func (g *ActiveGrant) fill(now time.Time) {
	if g != nil {
		g.Remaining = remaining(now, time.Time(g.ExpiresAt))
	}
}

// ListDoc is hallpass.list/v1.
type ListDoc struct {
	Schema  string       `json:"schema"`
	Servers []ListServer `json:"servers"`
}

// ListServer is one visible server.
type ListServer struct {
	Alias       string     `json:"alias"`
	Kind        string     `json:"kind"` // "ssh", "git" or "api"
	Description string     `json:"description"`
	Roles       []ListRole `json:"roles"`
}

// ListRole is one visible role.
type ListRole struct {
	Alias       string       `json:"alias"`
	Description string       `json:"description"`
	Level       string       `json:"level"` // LevelVisible, LevelRequestable or LevelAuto
	ActiveGrant *ActiveGrant `json:"active_grant"`
}

// NewListDoc builds hallpass.list/v1, computing remaining times at now. Order is preserved.
func NewListDoc(now time.Time, servers []ListServer) ListDoc {
	out := make([]ListServer, len(servers))
	for i, s := range servers {
		if s.Kind == "" {
			s.Kind = "ssh"
		}
		roles := make([]ListRole, len(s.Roles))
		for j, r := range s.Roles {
			r.ActiveGrant = cloneActive(r.ActiveGrant)
			r.ActiveGrant.fill(now)
			roles[j] = r
		}
		s.Roles = roles
		out[i] = s
	}
	return ListDoc{Schema: SchemaList, Servers: out}
}

func cloneActive(g *ActiveGrant) *ActiveGrant {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

// RolesDoc is hallpass.roles/v1.
type RolesDoc struct {
	Schema string       `json:"schema"`
	Server ServerRef    `json:"server"`
	Roles  []RoleDetail `json:"roles"`
}

// ServerRef identifies a visible server.
type ServerRef struct {
	Alias       string `json:"alias"`
	Description string `json:"description"`
}

// RoleDetail describes one visible role.
type RoleDetail struct {
	Alias            string       `json:"alias"`
	Description      string       `json:"description"`
	Level            string       `json:"level"`
	Capabilities     []string     `json:"capabilities"`
	DefaultDuration  Duration     `json:"default_duration"`
	MaxDuration      Duration     `json:"max_duration"`
	AllowedDurations []Duration   `json:"allowed_durations"`
	ActiveGrant      *ActiveGrant `json:"active_grant"`
}

// NewRolesDoc builds hallpass.roles/v1, computing remaining times at now.
func NewRolesDoc(now time.Time, server ServerRef, roles []RoleDetail) RolesDoc {
	out := make([]RoleDetail, len(roles))
	for i, r := range roles {
		r.Capabilities = append([]string{}, r.Capabilities...)
		r.AllowedDurations = append([]Duration{}, r.AllowedDurations...)
		r.ActiveGrant = cloneActive(r.ActiveGrant)
		r.ActiveGrant.fill(now)
		out[i] = r
	}
	return RolesDoc{Schema: SchemaRoles, Server: server, Roles: out}
}

// GrantInfo summarizes the grant created for a request.
type GrantInfo struct {
	ID        string   `json:"id"`
	State     string   `json:"state"` // active, expired or revoked
	StartsAt  Time     `json:"starts_at"`
	ExpiresAt Time     `json:"expires_at"`
	Remaining Duration `json:"remaining"` // computed by the builders; 0 unless active
}

func (g *GrantInfo) fill(now time.Time) {
	if g == nil {
		return
	}
	g.Remaining = 0
	if g.State == "active" {
		g.Remaining = remaining(now, time.Time(g.ExpiresAt))
	}
}

func cloneGrant(g *GrantInfo) *GrantInfo {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

// RequestDoc is hallpass.request/v1.
type RequestDoc struct {
	Schema  string      `json:"schema"`
	Request RequestInfo `json:"request"`
}

// RequestInfo is a created or reused request.
type RequestInfo struct {
	ID                string     `json:"id"`
	Server            string     `json:"server"`
	Role              string     `json:"role"`
	State             string     `json:"state"`
	Deduplicated      bool       `json:"deduplicated"`
	CreatedAt         Time       `json:"created_at"`
	ExpiresAt         Time       `json:"expires_at"`
	RequestedDuration Duration   `json:"requested_duration"`
	Grant             *GrantInfo `json:"grant"`
}

// NewRequestDoc builds hallpass.request/v1.
func NewRequestDoc(now time.Time, r RequestInfo) RequestDoc {
	r.Grant = cloneGrant(r.Grant)
	r.Grant.fill(now)
	return RequestDoc{Schema: SchemaRequest, Request: r}
}

// StatusDoc is hallpass.status/v1, also used for "cancel --json".
type StatusDoc struct {
	Schema  string     `json:"schema"`
	Request StatusInfo `json:"request"`
}

// StatusInfo is the state of one of the agent's own requests.
type StatusInfo struct {
	ID                string     `json:"id"`
	Server            string     `json:"server"`
	Role              string     `json:"role"`
	State             string     `json:"state"`
	StateReason       NullString `json:"state_reason"`
	CreatedAt         Time       `json:"created_at"`
	ExpiresAt         Time       `json:"expires_at"`
	DecidedAt         *Time      `json:"decided_at"`
	RequestedDuration Duration   `json:"requested_duration"`
	Grant             *GrantInfo `json:"grant"`
}

// NewStatusDoc builds hallpass.status/v1.
func NewStatusDoc(now time.Time, s StatusInfo) StatusDoc {
	s.Grant = cloneGrant(s.Grant)
	s.Grant.fill(now)
	return StatusDoc{Schema: SchemaStatus, Request: s}
}

// SessionsDoc is hallpass.sessions/v1.
type SessionsDoc struct {
	Schema   string        `json:"schema"`
	Sessions []SessionItem `json:"sessions"`
}

// SessionItem is one of the agent's grants and its access session.
type SessionItem struct {
	GrantID           string     `json:"grant_id"`
	SessionID         NullString `json:"session_id"`
	Server            string     `json:"server"`
	Role              string     `json:"role"`
	State             string     `json:"state"` // active, expired or revoked
	StartsAt          Time       `json:"starts_at"`
	ExpiresAt         Time       `json:"expires_at"`
	Remaining         Duration   `json:"remaining"` // computed by the builders; 0 unless active
	EndedAt           *Time      `json:"ended_at"`
	EndReason         NullString `json:"end_reason"`
	ActiveConnections int        `json:"active_connections"`
	TotalConnections  int        `json:"total_connections"`
}

// NewSessionsDoc builds hallpass.sessions/v1.
func NewSessionsDoc(now time.Time, items []SessionItem) SessionsDoc {
	out := make([]SessionItem, len(items))
	for i, s := range items {
		s.Remaining = 0
		if s.State == "active" {
			s.Remaining = remaining(now, time.Time(s.ExpiresAt))
		}
		out[i] = s
	}
	return SessionsDoc{Schema: SchemaSessions, Sessions: out}
}

// WhoAmIDoc is hallpass.whoami/v1.
type WhoAmIDoc struct {
	Schema         string `json:"schema"`
	AgentID        string `json:"agent_id"`
	AgentName      string `json:"agent_name"`
	KeyID          string `json:"key_id"`
	KeyFingerprint string `json:"key_fingerprint"`
	SourceIP       string `json:"source_ip"`
}

// NewWhoAmIDoc builds hallpass.whoami/v1.
func NewWhoAmIDoc(agentID, agentName, keyID, keyFingerprint, sourceIP string) WhoAmIDoc {
	return WhoAmIDoc{
		Schema: SchemaWhoAmI, AgentID: agentID, AgentName: agentName, KeyID: keyID,
		KeyFingerprint: keyFingerprint, SourceIP: sourceIP,
	}
}

// VersionDoc is hallpass.version/v1.
type VersionDoc struct {
	Schema         string     `json:"schema"`
	Version        string     `json:"version"`
	Commit         NullString `json:"commit"`
	GrammarVersion string     `json:"grammar_version"`
	Schemas        []string   `json:"schemas"`
}

// NewVersionDoc builds hallpass.version/v1.
func NewVersionDoc(version, commit string) VersionDoc {
	return VersionDoc{
		Schema: SchemaVersion, Version: version, Commit: NullString(commit),
		GrammarVersion: GrammarVersion, Schemas: Schemas(),
	}
}

// ErrUnknownDocument is returned by Marshal for values that are not output documents.
var ErrUnknownDocument = errors.New("grammar: not an output document")

// Marshal encodes an output document as one compact JSON line terminated by '\n' (stdout for --json).
func Marshal(doc any) ([]byte, error) {
	switch doc.(type) {
	case ListDoc, RolesDoc, RequestDoc, StatusDoc, SessionsDoc, WhoAmIDoc, VersionDoc, ErrorDoc:
		return marshalLine(doc)
	}
	return nil, ErrUnknownDocument
}
