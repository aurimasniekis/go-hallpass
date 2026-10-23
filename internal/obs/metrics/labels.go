package metrics

import (
	"regexp"
	"sync"
)

// Other is the fallback label value for anything outside a label's allowlist or over its cardinality cap.
const Other = "other"

// Typed label values. Methods accept these types so call sites use the constants below; every value is still
// normalized against the allowlist at runtime, so a converted free-form string can never create a new series.

// ConnResult is the outcome of an inbound agent SSH connection attempt.
type ConnResult string

// SSH connection results.
const (
	ConnAccepted        ConnResult = "accepted"         // authenticated and serving
	ConnAuthFailed      ConnResult = "auth_failed"      // public-key authentication failed
	ConnHandshakeFailed ConnResult = "handshake_failed" // protocol error or handshake timeout
	ConnPreAuthLimit    ConnResult = "preauth_limit"    // global or per-IP pre-auth limit reached (HP-SSH-013)
	ConnAgentLimit      ConnResult = "agent_limit"      // per-agent connection limit reached
	ConnShuttingDown    ConnResult = "shutting_down"    // refused during graceful shutdown
	ConnBanned          ConnResult = "banned"           // source banned after repeated failed authentication (HP-SSH-026)
)

// AuthFailReason is why agent public-key authentication failed. Values mirror internal/agents Fail* constants.
type AuthFailReason string

// SSH authentication failure reasons.
const (
	AuthUnknownKey     AuthFailReason = "unknown_key"
	AuthRevokedKey     AuthFailReason = "revoked_key"
	AuthAgentDisabled  AuthFailReason = "agent_disabled"
	AuthSourceDenied   AuthFailReason = "source_not_allowed"
	AuthKeyPolicy      AuthFailReason = "key_policy"
	AuthMethodRejected AuthFailReason = "method_rejected" // non-publickey method attempted
)

// ChannelKind is the kind of agent activity channel.
type ChannelKind string

// Channel kinds (internal/access KindShell/KindExec).
const (
	ChannelShell ChannelKind = "shell"
	ChannelExec  ChannelKind = "exec"
)

// ChannelResult is the outcome of an activity channel open attempt.
type ChannelResult string

// Channel open results.
const (
	ChannelOpened    ChannelResult = "opened"
	ChannelDenied    ChannelResult = "denied"     // no active grant / not permitted
	ChannelLimited   ChannelResult = "limited"    // concurrency limit
	ChannelFailed    ChannelResult = "failed"     // dial, recording or storage failure
	ChannelLockdown  ChannelResult = "lockdown"   // lockdown in effect
	ChannelNoStorage ChannelResult = "no_storage" // storage unavailable / below reserve (fail closed)
)

// RefusedRequest is the type of a refused SSH request or channel (HP-SSH-007).
type RefusedRequest string

// Refused SSH request types.
const (
	RefusedChannelType  RefusedRequest = "channel_type" // direct-tcpip, forwarded-tcpip, unknown channel types
	RefusedPortForward  RefusedRequest = "port_forward" // tcpip-forward global requests
	RefusedSubsystem    RefusedRequest = "subsystem"    // sftp and other subsystems
	RefusedX11          RefusedRequest = "x11"
	RefusedAgentForward RefusedRequest = "agent_forward"
)

// DialResult is the outcome of an outbound destination dial.
type DialResult string

// Dial results.
const (
	DialOK           DialResult = "ok"
	DialTimeout      DialResult = "timeout"
	DialEgressDenied DialResult = "egress_denied"
	DialHostKey      DialResult = "host_key_mismatch"
	DialAuthFailed   DialResult = "auth_failed"
	DialError        DialResult = "error"
)

// RequestState is an access request state reached by a transition.
type RequestState string

// Request states (internal/access Req*).
const (
	RequestPending  RequestState = "pending"
	RequestApproved RequestState = "approved"
	RequestDenied   RequestState = "denied"
	RequestExpired  RequestState = "expired"
	RequestCanceled RequestState = "canceled"
)

// DecisionChannel is the channel an operator decision arrived through (internal/access Channel*).
type DecisionChannel string

// Decision channels.
const (
	DecisionWeb      DecisionChannel = "web"
	DecisionSlack    DecisionChannel = "slack"
	DecisionTelegram DecisionChannel = "telegram"
	DecisionAPI      DecisionChannel = "api"
)

// DecisionOutcome is the result of a decision attempt.
type DecisionOutcome string

// Decision outcomes.
const (
	DecisionApproved  DecisionOutcome = "approved"
	DecisionDenied    DecisionOutcome = "denied"
	DecisionConflict  DecisionOutcome = "conflict"  // already decided / stale
	DecisionForbidden DecisionOutcome = "forbidden" // approver not permitted
	DecisionError     DecisionOutcome = "error"
)

// EndReason is why a grant ended or activity was terminated (internal/access Reason*).
type EndReason string

// End reasons.
const (
	EndExpired           EndReason = "expired"
	EndOperator          EndReason = "operator"
	EndAgent             EndReason = "agent"
	EndPolicyChanged     EndReason = "policy_changed"
	EndAgentDisabled     EndReason = "agent_disabled"
	EndKeyRevoked        EndReason = "key_revoked"
	EndTargetDisabled    EndReason = "target_disabled"
	EndCredentialRevoked EndReason = "credential_revoked" //nolint:gosec // G101 false positive: reason code
	EndLockdown          EndReason = "lockdown"
	EndShutdown          EndReason = "shutdown"
	EndRecordingFailed   EndReason = "recording_failed"
	EndIdle              EndReason = "idle"
)

// RecordingStage is where a recording failure happened.
type RecordingStage string

// Recording failure stages.
const (
	RecCreate       RecordingStage = "create"
	RecWrite        RecordingStage = "write"
	RecFsync        RecordingStage = "fsync"
	RecFinalize     RecordingStage = "finalize"
	RecQueueTimeout RecordingStage = "queue_timeout"
)

// SegmentResult is how a recording segment ended.
type SegmentResult string

// Segment results.
const (
	SegmentFinalized   SegmentResult = "finalized"
	SegmentInterrupted SegmentResult = "interrupted"
	SegmentFailed      SegmentResult = "failed"
)

// TxResult classifies the final outcome of a store write transaction.
type TxResult string

// Store transaction results (internal/store error classes).
const (
	TxOK         TxResult = "ok"
	TxBusy       TxResult = "busy"
	TxFull       TxResult = "full"
	TxIO         TxResult = "io"
	TxCorrupt    TxResult = "corrupt"
	TxConstraint TxResult = "constraint"
	TxConflict   TxResult = "conflict"
	TxNotFound   TxResult = "not_found"
	TxCanceled   TxResult = "canceled"
	TxError      TxResult = "error"
)

// Provider is a notification provider name.
type Provider string

// Notification providers.
const (
	ProviderSlack    Provider = "slack"
	ProviderTelegram Provider = "telegram"
	ProviderSMTP     Provider = "smtp"
	ProviderWeb      Provider = "web"
	ProviderWebhook  Provider = "webhook"
)

// DeliveryOutcome is the outcome of one notification delivery attempt (internal/outbox).
type DeliveryOutcome string

// Delivery outcomes.
const (
	DeliveryDelivered DeliveryOutcome = "delivered"
	DeliveryRetry     DeliveryOutcome = "retry"
	DeliveryDead      DeliveryOutcome = "dead"
)

// LoginMethod is an operator login method.
type LoginMethod string

// Login methods.
const (
	LoginPassword LoginMethod = "password"
	LoginOIDC     LoginMethod = "oidc"
	LoginRecovery LoginMethod = "recovery"
)

// LoginOutcome is the outcome of an operator or OIDC login.
type LoginOutcome string

// Login outcomes.
const (
	LoginSuccess   LoginOutcome = "success"
	LoginFailure   LoginOutcome = "failure"   // bad credentials / MFA failure
	LoginDenied    LoginOutcome = "denied"    // authenticated by the IdP but refused by policy (not provisioned, disabled)
	LoginThrottled LoginOutcome = "throttled" // rate limited
	LoginError     LoginOutcome = "error"     // IdP or internal error
)

// Volume names a filesystem whose capacity is exported.
type Volume string

// Volumes.
const (
	VolumeData       Volume = "data"
	VolumeRecordings Volume = "recordings"
	VolumeBackups    Volume = "backups"
)

// enum normalizes a label value against a fixed allowlist.
type enum map[string]struct{}

func newEnum[T ~string](vals ...T) enum {
	e := make(enum, len(vals))
	for _, v := range vals {
		e[string(v)] = struct{}{}
	}
	return e
}

func (e enum) norm(v string) string {
	if _, ok := e[v]; ok {
		return v
	}
	return Other
}

var (
	enumConnResult = newEnum(ConnAccepted, ConnAuthFailed, ConnHandshakeFailed, ConnPreAuthLimit, ConnAgentLimit, ConnShuttingDown, ConnBanned)
	enumAuthFail   = newEnum(AuthUnknownKey, AuthRevokedKey, AuthAgentDisabled, AuthSourceDenied, AuthKeyPolicy, AuthMethodRejected)
	enumChanKind   = newEnum(ChannelShell, ChannelExec)
	enumChanResult = newEnum(ChannelOpened, ChannelDenied, ChannelLimited, ChannelFailed, ChannelLockdown, ChannelNoStorage)
	enumRefused    = newEnum(RefusedChannelType, RefusedPortForward, RefusedSubsystem, RefusedX11, RefusedAgentForward)
	enumDial       = newEnum(DialOK, DialTimeout, DialEgressDenied, DialHostKey, DialAuthFailed, DialError)
	enumReqState   = newEnum(RequestPending, RequestApproved, RequestDenied, RequestExpired, RequestCanceled)
	enumDecChannel = newEnum(DecisionWeb, DecisionSlack, DecisionTelegram, DecisionAPI)
	enumDecOutcome = newEnum(DecisionApproved, DecisionDenied, DecisionConflict, DecisionForbidden, DecisionError)
	enumEndReason  = newEnum(EndExpired, EndOperator, EndAgent, EndPolicyChanged, EndAgentDisabled, EndKeyRevoked,
		EndTargetDisabled, EndCredentialRevoked, EndLockdown, EndShutdown, EndRecordingFailed, EndIdle)
	enumRecStage  = newEnum(RecCreate, RecWrite, RecFsync, RecFinalize, RecQueueTimeout)
	enumSegResult = newEnum(SegmentFinalized, SegmentInterrupted, SegmentFailed)
	enumTxResult  = newEnum(TxOK, TxBusy, TxFull, TxIO, TxCorrupt, TxConstraint, TxConflict, TxNotFound, TxCanceled, TxError)
	enumProvider  = newEnum(ProviderSlack, ProviderTelegram, ProviderSMTP, ProviderWeb, ProviderWebhook)
	enumDelivery  = newEnum(DeliveryDelivered, DeliveryRetry, DeliveryDead)
	enumLoginMeth = newEnum(LoginPassword, LoginOIDC, LoginRecovery)
	enumLoginOut  = newEnum(LoginSuccess, LoginFailure, LoginDenied, LoginThrottled, LoginError)
	enumVolume    = newEnum(VolumeData, VolumeRecordings, VolumeBackups)
	enumJobResult = newEnum("ok", "error")
)

// bounded admits label values that match a pattern, up to a fixed number of distinct values; the rest map to
// Other. It guards labels whose values come from code or operator configuration (transaction names, job names,
// OIDC provider slugs, HTTP route templates) against unbounded series growth.
type bounded struct {
	mu     sync.Mutex
	re     *regexp.Regexp
	max    int
	maxLen int
	seen   map[string]struct{}
	empty  string
}

func newBounded(re *regexp.Regexp, maxValues, maxLen int, empty string) *bounded {
	return &bounded{re: re, max: maxValues, maxLen: maxLen, seen: map[string]struct{}{}, empty: empty}
}

func (b *bounded) norm(v string) string {
	if v == "" {
		return b.empty
	}
	if len(v) > b.maxLen || !b.re.MatchString(v) {
		return Other
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.seen[v]; ok {
		return v
	}
	if len(b.seen) >= b.max {
		return Other
	}
	b.seen[v] = struct{}{}
	return v
}

// Cardinality caps for code- or configuration-derived labels.
const (
	MaxTxNames      = 160
	MaxJobNames     = 64
	MaxOIDCProvider = 32
	MaxRoutes       = 128
)

var (
	reDotted = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)
	reSlug   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	reRoute  = regexp.MustCompile(`^/[A-Za-z0-9/_.{}$-]{0,127}$`)
)
