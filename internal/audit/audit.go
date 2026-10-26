// Package audit writes the append-only, hash-chained audit log (HP-OBS-005).
//
// Every security-relevant action appends an event inside the same write transaction as the change it describes,
// so the audit trail and the state can never disagree. Each row stores hash = SHA-256(prev_hash || canonical row),
// which makes deletion, reordering or modification inside the database detectable by Verify. A party able to rewrite
// the whole chain (with database write access) is out of scope here; see external anchoring (HP-CRY-008).
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"sync"

	"github.com/aurimasniekis/go-hallpass/internal/events"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Actor types.
const (
	ActorOperator = "operator"
	ActorAgent    = "agent"
	ActorSystem   = "system"
	ActorPolicy   = "policy"
	ActorCLI      = "cli"
	ActorProvider = "provider"
)

// Outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Actor identifies who performed an action.
type Actor struct {
	Type string
	ID   string
	// Via names how an operator acted when it was not a browser session, e.g. "api_token:atk_…". It is recorded as
	// the "via" detail, so the event stays attributed to the operator.
	Via string
}

// System is the actor for automatic actions (expiry, reconciliation, jobs).
var System = Actor{Type: ActorSystem, ID: "hallpass"}

// Target identifies what an action applied to.
type Target struct {
	Type string
	ID   string
}

// Event is one audit record.
type Event struct {
	Actor         Actor
	Action        string // dotted, e.g. "agent.key.revoked"
	Target        Target
	Outcome       string
	SourceIP      string
	CorrelationID string
	// Details are non-sensitive structured fields stored in plaintext.
	Details map[string]any
	// Sensitive details (free text such as revocation reasons) are sealed with the field key.
	Sensitive map[string]any
}

// Record is a stored audit event as returned to readers.
type Record struct {
	ID            string         `json:"id"`
	Seq           int64          `json:"seq"`
	At            int64          `json:"at"`
	ActorType     string         `json:"actor_type"`
	ActorID       string         `json:"actor_id,omitempty"`
	Action        string         `json:"action"`
	TargetType    string         `json:"target_type,omitempty"`
	TargetID      string         `json:"target_id,omitempty"`
	Outcome       string         `json:"outcome"`
	SourceIP      string         `json:"source_ip,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
	HasSensitive  bool           `json:"has_sensitive,omitempty"`
}

// Sink receives committed audit records (e.g. a JSON-lines file for SIEM ingestion).
type Sink interface {
	Write(Record) error
}

// Writer appends audit events.
type Writer struct {
	kr     *keyring.Keyring
	mu     sync.RWMutex
	sink   Sink
	events *events.Recorder
}

// NewWriter returns a writer. kr may be nil only if events never carry sensitive details.
func NewWriter(kr *keyring.Keyring) *Writer { return &Writer{kr: kr} }

// SetSink attaches a sink that receives every record after its transaction commits.
func (w *Writer) SetSink(s Sink) {
	w.mu.Lock()
	w.sink = s
	w.mu.Unlock()
}

// SetEvents publishes every record to Pulse through r (ADR-0057); the published payload is the record as a sink
// receives it, never the sensitive details. nil turns publishing off.
func (w *Writer) SetEvents(r *events.Recorder) {
	w.mu.Lock()
	w.events = r
	w.mu.Unlock()
}

// GenesisHash is the prev_hash of the first event.
var GenesisHash = make([]byte, sha256.Size)

// Append writes ev inside tx and returns its ID.
func (w *Writer) Append(ctx context.Context, tx *store.Tx, ev Event) (string, error) {
	if ev.Action == "" || ev.Actor.Type == "" {
		return "", errors.New("audit: action and actor type are required")
	}
	if ev.Outcome == "" {
		ev.Outcome = OutcomeSuccess
	}
	if m := MetaFrom(ctx); ev.SourceIP == "" || ev.CorrelationID == "" {
		if ev.SourceIP == "" {
			ev.SourceIP = m.SourceIP
		}
		if ev.CorrelationID == "" {
			ev.CorrelationID = m.CorrelationID
		}
	}
	ev = withCorrelation(ctx, ev)
	if ev.Actor.Via != "" {
		d := make(map[string]any, len(ev.Details)+1)
		maps.Copy(d, ev.Details)
		d["via"] = ev.Actor.Via
		ev.Details = d
	}
	details, err := canonicalJSON(ev.Details)
	if err != nil {
		return "", fmt.Errorf("audit details: %w", err)
	}
	id := ids.New(ids.Audit)
	var enc []byte
	if len(ev.Sensitive) > 0 {
		if w.kr == nil {
			return "", errors.New("audit: sensitive details require a keyring")
		}
		pt, err := canonicalJSON(ev.Sensitive)
		if err != nil {
			return "", err
		}
		if enc, err = w.kr.Seal(keyring.PurposeField, keyring.FieldAAD("audit_events", "details_enc", id), []byte(pt)); err != nil {
			return "", err
		}
	}
	seq := int64(1)
	prev := GenesisHash
	last, err := tx.Q.LastAuditEvent(ctx)
	switch {
	case err == nil:
		seq, prev = last.Seq+1, last.Hash
	case !errors.Is(err, sql.ErrNoRows):
		return "", err
	}
	row := db.InsertAuditEventParams{
		ID: id, Seq: seq, At: tx.NowMicros(), ActorType: ev.Actor.Type, ActorID: nullStr(ev.Actor.ID), Action: ev.Action,
		TargetType: nullStr(ev.Target.Type), TargetID: nullStr(ev.Target.ID), Outcome: ev.Outcome,
		SourceIp: nullStr(ev.SourceIP), CorrelationID: nullStr(ev.CorrelationID), DetailsJson: details, DetailsEnc: enc,
		PrevHash: prev,
	}
	row.Hash = chainHash(prev, rowFields(row.ID, row.Seq, row.At, row.ActorType, row.ActorID.String, row.Action,
		row.TargetType.String, row.TargetID.String, row.Outcome, row.SourceIp.String, row.CorrelationID.String, row.DetailsJson, row.DetailsEnc))
	if err := tx.Q.InsertAuditEvent(ctx, row); err != nil {
		return "", err
	}
	w.mu.RLock()
	sink, rec := w.sink, w.events
	w.mu.RUnlock()
	if sink == nil && rec == nil {
		return id, nil
	}
	r := Record{ID: id, Seq: seq, At: row.At, ActorType: row.ActorType, ActorID: ev.Actor.ID, Action: ev.Action,
		TargetType: ev.Target.Type, TargetID: ev.Target.ID, Outcome: ev.Outcome, SourceIP: ev.SourceIP,
		CorrelationID: ev.CorrelationID, Details: ev.Details, HasSensitive: enc != nil}
	if err := rec.Record(ctx, tx, events.Event{ID: id, Name: ev.Action, Payload: r}); err != nil {
		return "", fmt.Errorf("audit event: %w", err)
	}
	if sink != nil {
		tx.AfterCommit(func() { _ = sink.Write(r) })
	}
	return id, nil
}

// CorrelationKey is the details key holding the correlation IDs taken from the context (HP-OBS-003).
const CorrelationKey = "correlation"

// withCorrelation fills the correlation ID (HTTP request ID, else trace ID) and records the context's trace and
// lifecycle IDs under details["correlation"], unless the caller set them. The caller's map is not modified.
func withCorrelation(ctx context.Context, ev Event) Event {
	traceID, _ := obs.TraceIDs(ctx)
	ids := obs.IDs(ctx)
	if ev.CorrelationID == "" {
		ev.CorrelationID = obs.ID(ctx, obs.FieldHTTPRequestID)
		if ev.CorrelationID == "" {
			ev.CorrelationID = traceID
		}
	}
	if traceID == "" && len(ids) == 0 {
		return ev
	}
	if _, set := ev.Details[CorrelationKey]; set {
		return ev
	}
	corr := make(map[string]any, len(ids)+1)
	if traceID != "" {
		corr["trace_id"] = traceID
	}
	for _, id := range ids {
		corr[strings.ReplaceAll(strings.TrimPrefix(id.Key(), "hallpass."), ".", "_")] = id.Value()
	}
	details := make(map[string]any, len(ev.Details)+1)
	maps.Copy(details, ev.Details)
	details[CorrelationKey] = corr
	ev.Details = details
	return ev
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

// canonicalJSON renders m with sorted keys (encoding/json sorts map keys); nil → "{}".
func canonicalJSON(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// rowFields length-prefixes every field so that no two distinct rows serialize identically.
func rowFields(id string, seq, at int64, actorType, actorID, action, targetType, targetID, outcome, sourceIP,
	correlationID, details string, enc []byte) []byte {
	var buf bytes.Buffer
	writeField := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	var n [8]byte
	writeField([]byte("hallpass/audit/v1"))
	writeField([]byte(id))
	binary.BigEndian.PutUint64(n[:], uint64(seq)) //nolint:gosec // positive by CHECK
	writeField(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(at)) //nolint:gosec // timestamps are positive
	writeField(n[:])
	for _, s := range []string{actorType, actorID, action, targetType, targetID, outcome, sourceIP, correlationID, details} {
		writeField([]byte(s))
	}
	writeField(enc)
	return buf.Bytes()
}

func chainHash(prev, fields []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(fields)
	return h.Sum(nil)
}

// VerifyResult summarizes a chain verification.
type VerifyResult struct {
	Events   int64  `json:"events"`
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Problem  string `json:"problem,omitempty"`
	HeadHash []byte `json:"head_hash,omitempty"`
}

// Verify walks the whole chain in sequence order and reports the first inconsistency (HP-OBS-005).
func Verify(ctx context.Context, q *db.Queries) (VerifyResult, error) {
	const page = 1000
	res := VerifyResult{OK: true}
	prev := GenesisHash
	var after, expectSeq int64 = 0, 1
	for {
		rows, err := q.AuditEventsFrom(ctx, db.AuditEventsFromParams{Seq: after, Limit: page})
		if err != nil {
			return res, err
		}
		for _, r := range rows {
			res.Events++
			switch {
			case r.Seq != expectSeq:
				return fail(res, r.Seq, fmt.Sprintf("sequence gap: expected %d, found %d (events deleted)", expectSeq, r.Seq)), nil
			case !bytes.Equal(r.PrevHash, prev):
				return fail(res, r.Seq, "prev_hash does not match the previous event (events reordered or deleted)"), nil
			}
			want := chainHash(prev, rowFields(r.ID, r.Seq, r.At, r.ActorType, r.ActorID.String, r.Action, r.TargetType.String,
				r.TargetID.String, r.Outcome, r.SourceIp.String, r.CorrelationID.String, r.DetailsJson, r.DetailsEnc))
			if !bytes.Equal(want, r.Hash) {
				return fail(res, r.Seq, "hash mismatch (event modified)"), nil
			}
			prev, after = r.Hash, r.Seq
			expectSeq++
		}
		if len(rows) < page {
			res.HeadHash = prev
			return res, nil
		}
	}
}

func fail(res VerifyResult, seq int64, problem string) VerifyResult {
	res.OK, res.BrokenAt, res.Problem = false, seq, problem
	return res
}

// DecodeRecord converts a stored row to a Record (without decrypting sensitive details).
func DecodeRecord(r db.AuditEvent) Record {
	rec := Record{
		ID: r.ID, Seq: r.Seq, At: r.At, ActorType: r.ActorType, ActorID: r.ActorID.String, Action: r.Action,
		TargetType: r.TargetType.String, TargetID: r.TargetID.String, Outcome: r.Outcome, SourceIP: r.SourceIp.String,
		CorrelationID: r.CorrelationID.String, HasSensitive: len(r.DetailsEnc) > 0,
	}
	if r.DetailsJson != "" && r.DetailsJson != "{}" {
		_ = json.Unmarshal([]byte(r.DetailsJson), &rec.Details)
	}
	return rec
}

// OpenSensitive decrypts the sensitive details of a stored event.
func (w *Writer) OpenSensitive(r db.AuditEvent) (map[string]any, error) {
	if len(r.DetailsEnc) == 0 {
		return nil, nil
	}
	pt, err := w.kr.Open(keyring.PurposeField, keyring.FieldAAD("audit_events", "details_enc", r.ID), r.DetailsEnc)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// JSONSink writes one JSON object per line.
type JSONSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONSink returns a sink writing to w.
func NewJSONSink(w io.Writer) *JSONSink { return &JSONSink{w: w} }

// Write implements Sink.
func (s *JSONSink) Write(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(b, '\n'))
	return err
}
