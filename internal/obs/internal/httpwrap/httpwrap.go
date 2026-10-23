// Package httpwrap provides the response-writer wrapper and route normalization shared by the HTTP metrics and
// tracing middleware.
package httpwrap

import (
	"net/http"
	"strings"
)

// Recorder wraps an http.ResponseWriter and remembers the status code. It forwards Flush (needed by SSE) and
// exposes Unwrap so http.ResponseController reaches the underlying writer.
type Recorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// New wraps w.
func New(w http.ResponseWriter) *Recorder { return &Recorder{ResponseWriter: w, status: http.StatusOK} }

// WriteHeader records the status code.
func (r *Recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write marks the header as written with the implicit 200.
func (r *Recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer when it supports flushing.
func (r *Recorder) Flush() {
	r.wrote = true
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

// Unwrap returns the wrapped writer for http.ResponseController.
func (r *Recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Status returns the recorded status code (200 when the handler wrote nothing).
func (r *Recorder) Status() int { return r.status }

// maxRouteLen bounds route label length.
const maxRouteLen = 128

// Route returns the path part of an http.ServeMux pattern ("GET example.org/api/v1/x/{id}" → "/api/v1/x/{id}").
// It returns "" when the pattern is empty or contains characters outside the route-template alphabet, so that
// callers can map it to a fixed fallback label. Raw request paths must never be used as labels or span names.
func Route(pattern string) string {
	p := pattern
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = strings.TrimLeft(p[i+1:], " \t")
	}
	if i := strings.IndexByte(p, '/'); i > 0 {
		p = p[i:] // strip host
	}
	if p == "" || p[0] != '/' || len(p) > maxRouteLen {
		return ""
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '_', c == '-', c == '.', c == '{', c == '}', c == '$':
		default:
			return ""
		}
	}
	return p
}

// Method normalizes an HTTP method to a fixed set; anything else is "other".
func Method(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return m
	default:
		return "other"
	}
}

// CodeClass maps a status code to "1xx".."5xx"; out-of-range codes are "other".
func CodeClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "other"
	}
}
