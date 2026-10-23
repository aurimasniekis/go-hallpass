package destaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Record is an ingested destination exec record. Everything in it is destination-reported (Verified is always
// false); Exe, Argv and CWD are untrusted text and may contain secrets.
type Record struct {
	ID              string    `json:"id"`
	SessionID       string    `json:"session_id"`
	ConnectionID    string    `json:"connection_id,omitempty"`
	CollectorID     string    `json:"collector_id"`
	RecordRef       string    `json:"record_ref"`
	BatchSeq        int64     `json:"batch_seq"`
	TimelineEventID string    `json:"timeline_event_id"`
	Provenance      string    `json:"provenance"`
	Verified        bool      `json:"verified"`
	Correlation     string    `json:"correlation"`
	Confidence      string    `json:"confidence"`
	AfterSessionEnd bool      `json:"after_session_end"`
	ReportedAt      time.Time `json:"reported_at"`
	ReceivedAt      time.Time `json:"received_at"`
	// Purged is set when retention removed the details (HP-REC-013).
	Purged bool `json:"purged,omitempty"`
	// Details are present only from RecordDetails.
	Exe       string   `json:"exe,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	CWD       string   `json:"cwd,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

func recordFromRow(r db.DestauditRecord) *Record {
	return &Record{ID: r.ID, SessionID: r.AccessSessionID, ConnectionID: r.ConnectionID.String, CollectorID: r.CollectorID,
		RecordRef: r.RecordRef, BatchSeq: r.BatchSeq, TimelineEventID: r.TimelineEventID, Provenance: Provenance,
		Correlation: r.Correlation, Confidence: r.Confidence, AfterSessionEnd: r.AfterSessionEnd == 1,
		ReportedAt: clock.FromMicros(r.ReportedAt), ReceivedAt: clock.FromMicros(r.ReceivedAt), Purged: r.PurgedAt.Valid}
}

// SessionRecords lists record metadata (no exec details) for an access session, oldest reported first.
func (svc *Service) SessionRecords(ctx context.Context, sessionID string, limit int) ([]*Record, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := svc.s.R().DestauditRecordsForSession(ctx, db.DestauditRecordsForSessionParams{AccessSessionID: sessionID, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]*Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, recordFromRow(r))
	}
	return out, nil
}

// RecordDetails returns one record with its decrypted exec details. Callers must enforce the same permission as
// recording playback and audit the access (HP-REC-014); the text is untrusted and must never be rendered as HTML
// or fed to a terminal emulator unescaped.
func (svc *Service) RecordDetails(ctx context.Context, id string) (*Record, error) {
	r, err := svc.s.R().GetDestauditRecord(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "destination audit record not found")
	}
	if err != nil {
		return nil, err
	}
	out := recordFromRow(r)
	if len(r.DetailsEnc) == 0 {
		out.Purged = true
		return out, nil
	}
	pt, err := svc.kr.Open(keyring.PurposeField, detailsAAD(r.ID), r.DetailsEnc)
	if err != nil {
		return nil, err
	}
	var d details
	if err := json.Unmarshal(pt, &d); err != nil {
		return nil, err
	}
	out.Exe, out.Argv, out.CWD, out.Truncated = d.Exe, d.Argv, d.CWD, d.Truncated
	return out, nil
}
