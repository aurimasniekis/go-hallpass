package httpwrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoute(t *testing.T) {
	for in, want := range map[string]string{
		"":                              "",
		"GET /api/v1/requests/{id}":     "/api/v1/requests/{id}",
		"POST example.org/hooks/{id}":   "/hooks/{id}",
		"/static/":                      "/static/",
		"/files/{path...}":              "/files/{path...}",
		"GET  /x/{$}":                   "/x/{$}",
		"example.org":                   "",
		"/a b":                          "",
		"/" + string(make([]byte, 200)): "",
	} {
		if got := Route(in); got != want {
			t.Errorf("Route(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMethodAndCodeClass(t *testing.T) {
	if Method("GET") != "GET" || Method("PROPFIND") != "other" {
		t.Error("method normalization")
	}
	for code, want := range map[int]string{101: "1xx", 204: "2xx", 302: "3xx", 404: "4xx", 503: "5xx", 0: "other", 999: "other"} {
		if got := CodeClass(code); got != want {
			t.Errorf("CodeClass(%d) = %q", code, got)
		}
	}
}

func TestRecorder(t *testing.T) {
	base := httptest.NewRecorder()
	r := New(base)
	if r.Status() != http.StatusOK {
		t.Error("default status")
	}
	r.WriteHeader(http.StatusCreated)
	r.WriteHeader(http.StatusInternalServerError) // ignored: first status wins
	_, _ = r.Write([]byte("x"))
	r.Flush()
	if r.Status() != http.StatusCreated || !base.Flushed || r.Unwrap() != base {
		t.Errorf("status=%d flushed=%v", r.Status(), base.Flushed)
	}
}
