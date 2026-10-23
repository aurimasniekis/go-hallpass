package grammar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ExitCode is a gateway exit status (PLAN §7.7). A destination exit status passes through unchanged when the
// destination ran; these codes are used only for gateway outcomes.
type ExitCode int

// Gateway exit codes.
const (
	ExitOK                     ExitCode = 0
	ExitInternal               ExitCode = 80
	ExitUsage                  ExitCode = 81
	ExitNotFoundOrForbidden    ExitCode = 82
	ExitDenied                 ExitCode = 83
	ExitExpired                ExitCode = 84
	ExitCanceled               ExitCode = 85
	ExitWaitTimeout            ExitCode = 86
	ExitAccessEnded            ExitCode = 87
	ExitDestinationUnavailable ExitCode = 88
	ExitLimitExceeded          ExitCode = 89
	ExitInputRequired          ExitCode = 90
)

// exitCodes lists every code in ascending order with its stable machine-readable name.
var exitCodes = []struct {
	code ExitCode
	name string
	desc string
}{
	{ExitOK, "ok", "Gateway-only command succeeded."},
	{ExitInternal, "internal", "Internal or storage failure, gateway degraded, shutdown."},
	{ExitUsage, "usage", "Parse error, unknown option, ambiguous role, invalid duration."},
	{ExitNotFoundOrForbidden, "not_found_or_forbidden", "Target, role or request unknown or not permitted."},
	{ExitDenied, "denied", "Request denied."},
	{ExitExpired, "expired", "Request expired before a decision."},
	{ExitCanceled, "canceled", "Request canceled."},
	{ExitWaitTimeout, "wait_timeout", "Still pending after the wait timeout."},
	{ExitAccessEnded, "access_ended", "Grant expired, revoked or disabled during or before activity."},
	{ExitDestinationUnavailable, "destination_unavailable", "Destination dial, host-key verification or authentication failed."},
	{ExitLimitExceeded, "limit_exceeded", "Rate limit, concurrency limit or too many pending requests."},
	{ExitInputRequired, "input_required", "Required input missing without a PTY."},
}

// ExitCodes returns every gateway exit code in ascending order.
func ExitCodes() []ExitCode {
	out := make([]ExitCode, len(exitCodes))
	for i, e := range exitCodes {
		out[i] = e.code
	}
	return out
}

// Name returns the stable error-code string (e.g. "not_found_or_forbidden"), or "" for a code that is not a
// gateway exit code.
func (c ExitCode) Name() string {
	for _, e := range exitCodes {
		if e.code == c {
			return e.name
		}
	}
	return ""
}

// Description returns the human description of the code from PLAN §7.7.
func (c ExitCode) Description() string {
	for _, e := range exitCodes {
		if e.code == c {
			return e.desc
		}
	}
	return ""
}

// Valid reports whether c is a known gateway exit code.
func (c ExitCode) Valid() bool { return c.Name() != "" }

// Canonical messages.
const (
	// MsgNotFoundOrForbidden is the single message for every unknown, hidden, disabled or unrequestable target and
	// for another agent's request (HP-POL-010). It matches access.ErrNotFoundOrForbidden.
	MsgNotFoundOrForbidden = "server or role not found or not permitted"
	// MsgInternal is shown for every internal failure; causes are logged, never sent to the agent.
	MsgInternal = "internal error; try again later"
)

// Error is a gateway error: an exit code, its stable code string, a human message and an optional request ID.
type Error struct {
	Exit      ExitCode
	Message   string
	RequestID string
}

func (e *Error) Error() string { return e.Message }

// Code returns the stable error-code string for the exit code.
func (e *Error) Code() string { return e.Exit.Name() }

// NewError builds an error. Unknown or zero exit codes are mapped to ExitInternal.
func NewError(code ExitCode, msg string) *Error {
	if code == ExitOK || !code.Valid() {
		code = ExitInternal
	}
	return &Error{Exit: code, Message: msg}
}

// WithRequestID returns a copy of e carrying a request ID.
func (e *Error) WithRequestID(id string) *Error {
	c := *e
	c.RequestID = id
	return &c
}

func usage(msg string) *Error { return &Error{Exit: ExitUsage, Message: msg} }

func usagef(format string, args ...any) *Error {
	return &Error{Exit: ExitUsage, Message: fmt.Sprintf(format, args...)}
}

// Usage returns a usage error (exit 81).
func Usage(msg string) *Error { return usage(msg) }

// NotFoundOrForbidden returns the uniform not-found-or-forbidden error (exit 82). Every variant is byte-identical.
func NotFoundOrForbidden() *Error {
	return &Error{Exit: ExitNotFoundOrForbidden, Message: MsgNotFoundOrForbidden}
}

// Internal returns the generic internal error (exit 80).
func Internal() *Error { return &Error{Exit: ExitInternal, Message: MsgInternal} }

// AmbiguousRole is returned without a PTY when no role can be chosen implicitly (HP-SSH-022). choices are the
// visible role aliases.
func AmbiguousRole(server string, choices []string) *Error {
	return usagef("server %s has several roles; choose one with --role (choices: %s)", server, strings.Join(choices, ", "))
}

// ReasonRequired is returned when policy requires a reason, none was given and there is no PTY (HP-SSH-019).
func ReasonRequired() *Error {
	return &Error{Exit: ExitInputRequired, Message: `a reason is required: add --reason "<why you need access>"`}
}

// WaitTimedOut is returned when a request is still pending after the wait timeout (HP-SSH-020/021). The request stays
// pending; the message says how to resume waiting.
func WaitTimedOut(requestID string, waited time.Duration) *Error {
	return &Error{
		Exit:      ExitWaitTimeout,
		RequestID: requestID,
		Message: fmt.Sprintf("request %s is still pending after %s; it stays pending. Resume with: status %s --wait",
			requestID, FormatDuration(waited), requestID),
	}
}

// PendingNotice is the stderr line printed before waiting (PLAN §7.6 step 4), without the "hallpass: " prefix.
func PendingNotice(requestID string, expiresAt time.Time, wait time.Duration) string {
	return fmt.Sprintf("request %s pending approval (expires %s); waiting up to %s",
		requestID, expiresAt.UTC().Format("15:04Z"), wait.String())
}

// ExitCodeOf returns the exit code for err: 0 for nil, the code of an *Error, otherwise ExitInternal.
func ExitCodeOf(err error) ExitCode {
	if err == nil {
		return ExitOK
	}
	var e *Error
	if errors.As(err, &e) && e.Exit.Valid() && e.Exit != ExitOK {
		return e.Exit
	}
	return ExitInternal
}

// asGateway converts any error to a safe *Error: errors that are not *Error never leak their text.
func asGateway(err error) *Error {
	var e *Error
	if errors.As(err, &e) && e.Exit.Valid() && e.Exit != ExitOK {
		return e
	}
	return Internal()
}

// ErrorDoc is the hallpass.error/v1 document.
type ErrorDoc struct {
	Schema    string     `json:"schema"`
	Source    string     `json:"source"`
	Code      string     `json:"code"`
	ExitCode  int        `json:"exit_code"`
	Message   string     `json:"message"`
	RequestID NullString `json:"request_id"`
}

// NewErrorDoc builds the hallpass.error/v1 document for err. Errors that are not *Error become the generic internal
// error. A request ID that is not well formed is dropped.
func NewErrorDoc(err error) ErrorDoc {
	e := asGateway(err)
	rid := e.RequestID
	if !ValidRequestID(rid) {
		rid = ""
	}
	return ErrorDoc{
		Schema:    SchemaError,
		Source:    "gateway",
		Code:      e.Code(),
		ExitCode:  int(e.Exit),
		Message:   e.Message,
		RequestID: NullString(rid),
	}
}

// ErrorJSON returns the single stderr line (terminated by '\n') for err, per PLAN §7.7:
// {"schema":"hallpass.error/v1","source":"gateway","code":…,"exit_code":…,"message":…,"request_id":…|null}.
func ErrorJSON(err error) []byte {
	b, mErr := marshalLine(NewErrorDoc(err))
	if mErr != nil { // unreachable: the document holds only strings and an int
		return []byte(`{"schema":"hallpass.error/v1","source":"gateway","code":"internal","exit_code":80,"message":"internal error; try again later","request_id":null}` + "\n")
	}
	return b
}

// ErrorText returns the human stderr line for err (terminated by '\n'), prefixed "hallpass: ".
func ErrorText(err error) string {
	e := asGateway(err)
	return "hallpass: " + sanitizeLine(e.Message) + "\n"
}

// marshalLine encodes v as compact JSON without HTML escaping, terminated by exactly one '\n'.
func marshalLine(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
