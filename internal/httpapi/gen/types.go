// Package gen holds the API operation table and server interface generated from api/openapi.yaml, plus the small
// hand-written types they use.
package gen

import (
	"net/http"

	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

// Operation is one API operation as declared in the spec.
type Operation struct {
	ID         string
	Method     string
	Path       string // spec path relative to the server base, e.g. /agents/{id}
	Permission string // x-permission
	Reauth     bool   // x-reauth: recent authentication required (HP-AUTH-014)
	MFA        bool   // x-mfa: MFA required for password sessions
	Idempotent bool   // x-idempotency-key: Idempotency-Key honored (HP-API-006)
	Stream     bool   // x-stream: the handler writes the response itself (SSE)
	Redirect   bool   // x-redirect: browser redirect endpoint outside the JSON API
	Tags       []string
}

// Call is one request to an operation.
type Call struct {
	W         http.ResponseWriter
	R         *http.Request
	Op        *Operation
	Principal *opauth.Principal // nil for public operations
	// SessionToken is the raw session cookie value (for logout, rotation).
	SessionToken string
}

// Result is a handler's response: Body is encoded as JSON with Status (default 200). A nil Body with
// Status 204 writes no content. Handlers that wrote the response themselves return a nil *Result.
type Result struct {
	Status int
	Body   any
	// SetSession replaces the session cookie (login, MFA, rotation); ClearSession removes it.
	SetSession   string
	ClearSession bool
	// Location is set for redirects (Status 302/303).
	Location string
}

// Handler serves one operation.
type Handler func(c *Call) (*Result, error)
