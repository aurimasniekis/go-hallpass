package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A request the client abandoned (a page navigating away mid-fetch) is not a server fault: no error log, status 499
// for the operation log. A cancellation while the client is still waiting stays an internal error.
func TestProblemClientClosedRequest(t *testing.T) {
	var logs bytes.Buffer
	s := &Server{log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/system/status", nil)
	if got := s.problem(httptest.NewRecorder(), r, context.Canceled); got != statusClientClosed {
		t.Fatalf("status = %d, want %d", got, statusClientClosed)
	}
	if logs.Len() != 0 {
		t.Fatalf("logged a client cancellation: %s", logs.String())
	}

	r = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/system/status", nil)
	if got := s.problem(httptest.NewRecorder(), r, errors.Join(errors.New("query"), context.Canceled)); got != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", got)
	}
	if !bytes.Contains(logs.Bytes(), []byte("unhandled api error")) {
		t.Fatal("an internal cancellation was not logged")
	}
}
