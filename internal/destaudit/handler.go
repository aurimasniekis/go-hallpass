package destaudit

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
)

// PathValueCollectorID is the path wildcard name the handler reads ("/hooks/destaudit/{collector_id}").
const PathValueCollectorID = "collector_id"

// problem is an RFC 9457 problem document (same shape as the REST API's, HP-API-003).
type problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	LastSeq *int64 `json:"last_seq,omitempty"`
}

// Handler returns the ingestion endpoint: POST a wire.Envelope (application/json) to
// /hooks/destaudit/{collector_id}. Authentication is the batch signature by the collector's enrolled key, so the
// route must not require an operator session or CSRF token. The collector ID comes from the {collector_id} path
// wildcard, or from the last path segment when the router does not set one; it is also inside the signed payload
// and must match.
//
// Responses: 200 IngestResult; 400 malformed, oversized limits or clock skew; 401 unknown/revoked collector or bad
// signature (indistinguishable); 405; 409 replay (with last_seq); 413 body too large; 415 non-JSON; 503 storage.
func (svc *Service) Handler() http.Handler {
	return http.HandlerFunc(svc.serveHTTP)
}

func (svc *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST", nil)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeProblem(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "content type must be application/json", nil)
		return
	}
	id := r.PathValue(PathValueCollectorID)
	if id == "" {
		id = path.Base(r.URL.Path)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, svc.opts.MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large", nil)
			return
		}
		writeProblem(w, http.StatusBadRequest, string(apperr.CodeInvalid), "unreadable body", nil)
		return
	}
	res, err := svc.Ingest(r.Context(), id, body)
	if err != nil {
		svc.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(res)
}

func (svc *Service) writeError(w http.ResponseWriter, err error) {
	var re *ReplayError
	if errors.As(err, &re) {
		last := re.LastSeq
		writeProblem(w, http.StatusConflict, "replay", re.Error(), &last)
		return
	}
	var ae *apperr.Error
	if errors.As(err, &ae) {
		switch ae.Code {
		case apperr.CodeUnauthorized:
			writeProblem(w, http.StatusUnauthorized, string(ae.Code), ae.Message, nil)
		case apperr.CodeUnavailable:
			writeProblem(w, http.StatusServiceUnavailable, string(ae.Code), ae.Message, nil)
		case apperr.CodeInvalid:
			writeProblem(w, http.StatusBadRequest, string(ae.Code), ae.Message, nil)
		default:
			writeProblem(w, http.StatusConflict, string(ae.Code), ae.Message, nil)
		}
		return
	}
	svc.log.Error("destination audit ingestion failed", obs.Err(err))
	writeProblem(w, http.StatusInternalServerError, "internal", "internal error", nil)
}

func writeProblem(w http.ResponseWriter, status int, code, title string, lastSeq *int64) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Type: "https://hallpass.dev/problems/" + code, Title: title, Status: status, Code: code, LastSeq: lastSeq})
}
