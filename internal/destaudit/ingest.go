package destaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Rejection reasons (stable codes returned to the collector).
const (
	RejectDuplicateInBatch   = "duplicate_in_batch"
	RejectFuture             = "future_timestamp"
	RejectTooOld             = "too_old"
	RejectNoIdentity         = "no_identity"
	RejectInvalidKeyID       = "invalid_key_id"
	RejectUnknownSession     = "unknown_session"
	RejectUnknownKey         = "unknown_key"
	RejectServerMismatch     = "server_mismatch"
	RejectRoleMismatch       = "role_mismatch"
	RejectUserMismatch       = "user_mismatch"
	RejectConnectionMismatch = "connection_mismatch"
	RejectOutsideWindow      = "outside_window"
	RejectNoSession          = "no_session"
	RejectAmbiguous          = "ambiguous"
	RejectLoginConflict      = "login_conflict"
)

// errUnauthorized is deliberately uniform: unknown collector, revoked collector and bad signature look the same.
var errUnauthorized = apperr.New(apperr.CodeUnauthorized, "collector authentication failed")

// ReplayError reports a batch whose sequence number is not greater than the last accepted one. LastSeq lets an
// authenticated collector resynchronize after losing its state.
type ReplayError struct{ LastSeq int64 }

func (e *ReplayError) Error() string {
	return fmt.Sprintf("batch sequence must be greater than %d (replay or stale collector state)", e.LastSeq)
}

// Rejection explains why one record was not attached.
type Rejection struct {
	RecordID string `json:"record_id"`
	Reason   string `json:"reason"`
}

// IngestResult summarizes one batch.
type IngestResult struct {
	Seq            int64       `json:"seq"`
	Records        int         `json:"records"`
	Accepted       int         `json:"accepted"`
	Duplicates     int         `json:"duplicates"`
	Rejected       int         `json:"rejected"`
	DuplicateBatch bool        `json:"duplicate_batch,omitempty"`
	Rejections     []Rejection `json:"rejections,omitempty"`
}

// match is a successful correlation of one record with HallPass state.
type match struct {
	sessionID    string
	connectionID string
	correlation  string
	confidence   string
	afterEnd     bool
	bind         bool // record the login → session binding
}

type pending struct {
	rec      *wire.Record
	m        match
	id       string
	seq      int64
	sealed   []byte
	argvLen  int
	argBytes int
}

// sessionWindow is the subset of session + grant state used to check time windows.
// Its fields mirror the generated DestauditSessionByGrantRow / DestauditSessionByIDRow so both convert to it.
type sessionWindow struct {
	SessionID  string
	OpenedAt   int64
	ClosedAt   sql.NullInt64
	GrantID    string
	ServerID   string
	RoleID     string
	RemoteUser string
	StartsAt   int64
	ExpiresAt  int64
	EndedAt    sql.NullInt64
}

// Ingest verifies and stores one batch posted by collectorID. body is the raw HTTP body (a wire.Envelope).
//
// Order of checks: collector lookup and Ed25519 signature first (nothing unauthenticated is parsed beyond the
// envelope or written), then batch structure, clock skew and replay, then per-record limits and correlation. All
// writes for the batch (sequence advance, records, timeline events, batch row and audit event) commit atomically.
func (svc *Service) Ingest(ctx context.Context, collectorID string, body []byte) (*IngestResult, error) {
	if int64(len(body)) > svc.opts.MaxBodyBytes {
		return nil, apperr.New(apperr.CodeInvalid, "batch exceeds %d bytes", svc.opts.MaxBodyBytes)
	}
	if !ids.Valid(PrefixCollector, collectorID) {
		return nil, errUnauthorized
	}
	if !svc.s.Health().AcceptsWrites(ctx) {
		return nil, apperr.New(apperr.CodeUnavailable, "storage unavailable")
	}
	c, err := svc.s.R().GetDestauditCollector(ctx, collectorID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errUnauthorized
	} else if err != nil {
		return nil, err
	}
	if c.State != StateActive {
		return nil, errUnauthorized
	}
	env, err := wire.DecodeEnvelope(body)
	if err != nil {
		return nil, apperr.New(apperr.CodeInvalid, "malformed envelope")
	}
	if err := wire.Verify(c.PublicKey, env); err != nil {
		svc.log.Warn("destination audit batch signature rejected", "collector_id", collectorID)
		return nil, errUnauthorized
	}
	// Serialize ingestion per collector, and only for authenticated batches (so unauthenticated requests cannot
	// create lock entries). Reload the row under the lock: a concurrent batch may have advanced last_seq.
	unlock := svc.lock(collectorID)
	defer unlock()
	if c, err = svc.s.R().GetDestauditCollector(ctx, collectorID); err != nil {
		return nil, err
	}
	if c.State != StateActive {
		return nil, errUnauthorized
	}
	b, err := wire.DecodeBatch(env.Payload)
	if err != nil {
		return nil, apperr.New(apperr.CodeInvalid, "malformed batch: %v", err)
	}
	if b.CollectorID != collectorID {
		return nil, apperr.New(apperr.CodeInvalid, "batch collector_id does not match the endpoint")
	}
	now := svc.opts.Clock.Now()
	if d := b.SentAt.Sub(now); d > svc.opts.MaxSkew || d < -svc.opts.MaxSkew {
		return nil, apperr.New(apperr.CodeInvalid, "sent_at is outside the allowed clock skew of %s", svc.opts.MaxSkew)
	}
	sum := sha256.Sum256(env.Payload)
	if b.Seq <= c.LastSeq {
		return svc.replay(ctx, c, b.Seq, sum[:])
	}

	res := &IngestResult{Seq: b.Seq, Records: len(b.Records)}
	accepted, err := svc.correlateAll(ctx, c, b, now, res)
	if err != nil {
		return nil, err
	}
	if err := svc.prepare(ctx, accepted); err != nil {
		return nil, err
	}
	return svc.commit(ctx, c, b, env, sum[:], accepted, res)
}

// replay handles a batch at or below the last accepted sequence: an exact resend of an accepted batch (a collector
// retry after a lost response) returns the stored result; anything else is refused.
func (svc *Service) replay(ctx context.Context, c db.DestauditCollector, seq int64, sum []byte) (*IngestResult, error) {
	prev, err := svc.s.R().GetDestauditBatch(ctx, db.GetDestauditBatchParams{CollectorID: c.ID, Seq: seq})
	if err == nil && bytes.Equal(prev.PayloadSha256, sum) {
		return &IngestResult{Seq: seq, Records: int(prev.Records), Accepted: int(prev.Accepted), Duplicates: int(prev.Duplicates),
			Rejected: int(prev.Rejected), DuplicateBatch: true}, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	svc.log.Warn("destination audit batch replay refused", "collector_id", c.ID, "seq", seq, "last_seq", c.LastSeq)
	return nil, &ReplayError{LastSeq: c.LastSeq}
}

func (svc *Service) correlateAll(ctx context.Context, c db.DestauditCollector, b *wire.Batch, now time.Time, res *IngestResult) ([]*pending, error) {
	seen := make(map[string]bool, len(b.Records))
	var out []*pending
	for i := range b.Records {
		r := &b.Records[i]
		reject := func(reason string) {
			res.Rejections = append(res.Rejections, Rejection{RecordID: truncate(r.ID, wire.MaxIDLen), Reason: reason})
		}
		if reason := r.Validate(); reason != "" {
			reject(reason)
			continue
		}
		if seen[r.ID] {
			reject(RejectDuplicateInBatch)
			continue
		}
		seen[r.ID] = true
		t := r.Time.UnixMicro()
		if t > now.Add(svc.opts.MaxSkew).UnixMicro() || r.Time.After(b.SentAt.Add(svc.opts.MaxSkew)) {
			reject(RejectFuture)
			continue
		}
		if t < now.Add(-svc.opts.MaxRecordAge).UnixMicro() {
			reject(RejectTooOld)
			continue
		}
		n, err := svc.s.R().DestauditRecordExists(ctx, db.DestauditRecordExistsParams{CollectorID: c.ID, RecordRef: r.ID})
		if err != nil {
			return nil, err
		}
		if n > 0 {
			res.Duplicates++
			continue
		}
		m, reason, err := svc.correlate(ctx, c, r, now)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			reject(reason)
			continue
		}
		out = append(out, &pending{rec: r, m: m})
	}
	return out, nil
}

// correlate maps one record to an access session using only HallPass state. It returns a rejection reason when the
// destination's claims are inconsistent with that state or ambiguous.
func (svc *Service) correlate(ctx context.Context, c db.DestauditCollector, r *wire.Record, now time.Time) (match, string, error) {
	switch {
	case r.Login.CertKeyID != "":
		return svc.correlateCert(ctx, c, r, now)
	case r.Login.KeyFingerprint != "":
		return svc.correlateKey(ctx, c, r, now)
	default:
		return match{}, RejectNoIdentity, nil
	}
}

// correlateCert: the certificate key ID names role, grant and connection (internal/credentials issueCert). The
// destination's sshd verified a certificate signed by the HallPass user CA before logging it, and each part is
// checked against HallPass state here, so a collector cannot point records at an arbitrary session.
func (svc *Service) correlateCert(ctx context.Context, c db.DestauditCollector, r *wire.Record, now time.Time) (match, string, error) {
	k, ok := wire.ParseCertKeyID(r.Login.CertKeyID)
	if !ok || !ids.Valid(ids.Role, k.RoleID) || !ids.Valid(ids.Grant, k.GrantID) || !ids.Valid(ids.Connection, k.ConnectionID) {
		return match{}, RejectInvalidKeyID, nil
	}
	row, err := svc.s.R().DestauditSessionByGrant(ctx, k.GrantID)
	if errors.Is(err, sql.ErrNoRows) {
		return match{}, RejectUnknownSession, nil
	} else if err != nil {
		return match{}, "", err
	}
	w := sessionWindow(row)
	switch {
	case w.ServerID != c.ServerID:
		return match{}, RejectServerMismatch, nil
	case w.RoleID != k.RoleID:
		return match{}, RejectRoleMismatch, nil
	case w.RemoteUser != r.Login.User:
		return match{}, RejectUserMismatch, nil
	}
	n, err := svc.s.R().DestauditConnectionInSession(ctx, db.DestauditConnectionInSessionParams{ConnectionID: k.ConnectionID,
		SessionID: w.SessionID, GrantID: w.GrantID})
	if err != nil {
		return match{}, "", err
	}
	if n == 0 {
		return match{}, RejectConnectionMismatch, nil
	}
	if !r.Login.Time.IsZero() {
		if _, reason := svc.window(w, r.Login.Time, now, false); reason != "" {
			return match{}, reason, nil
		}
	}
	afterEnd, reason := svc.window(w, r.Time, now, true)
	if reason != "" {
		return match{}, reason, nil
	}
	return match{sessionID: w.SessionID, connectionID: k.ConnectionID, correlation: CorrelationCertKeyID, confidence: ConfidenceHigh,
		afterEnd: afterEnd, bind: true}, "", nil
}

// correlateKey: a managed login key is per role and shared by every session on it, so the fingerprint only narrows
// the candidates to that role; exactly one session must have a channel using that credential around the login time.
// Later records of the same destination login reuse the binding made by the first correlated record.
func (svc *Service) correlateKey(ctx context.Context, c db.DestauditCollector, r *wire.Record, now time.Time) (match, string, error) {
	cred, err := svc.s.R().DestauditCredentialByFingerprint(ctx, r.Login.KeyFingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return match{}, RejectUnknownKey, nil
	} else if err != nil {
		return match{}, "", err
	}
	switch {
	case cred.ServerID != c.ServerID:
		return match{}, RejectServerMismatch, nil
	case cred.RemoteUser != r.Login.User:
		return match{}, RejectUserMismatch, nil
	}
	if bnd, err := svc.s.R().GetDestauditLogin(ctx, db.GetDestauditLoginParams{CollectorID: c.ID, LoginRef: r.Login.Ref}); err == nil {
		row, err := svc.s.R().DestauditSessionByID(ctx, bnd.AccessSessionID)
		if err != nil {
			return match{}, "", err
		}
		w := sessionWindow(row)
		if w.RoleID != cred.RoleID || w.ServerID != c.ServerID || w.RemoteUser != r.Login.User {
			return match{}, RejectLoginConflict, nil
		}
		afterEnd, reason := svc.window(w, r.Time, now, true)
		if reason != "" {
			return match{}, reason, nil
		}
		return match{sessionID: w.SessionID, connectionID: bnd.ConnectionID.String, correlation: CorrelationLoginBinded,
			confidence: ConfidenceMedium, afterEnd: afterEnd}, "", nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return match{}, "", err
	}
	anchor := r.Login.Time
	if anchor.IsZero() {
		anchor = r.Time
	}
	skew := svc.opts.MaxSkew
	sids, err := svc.s.R().DestauditSessionsForCredentialAt(ctx, db.DestauditSessionsForCredentialAtParams{
		CredentialRef: sql.NullString{String: cred.ID, Valid: true}, RoleID: cred.RoleID,
		Hi: anchor.Add(skew).UnixMicro(), Lo: sql.NullInt64{Int64: anchor.Add(-skew).UnixMicro(), Valid: true}})
	if err != nil {
		return match{}, "", err
	}
	switch len(sids) {
	case 0:
		return match{}, RejectNoSession, nil
	case 1:
	default:
		return match{}, RejectAmbiguous, nil
	}
	row, err := svc.s.R().DestauditSessionByID(ctx, sids[0])
	if err != nil {
		return match{}, "", err
	}
	w := sessionWindow(row)
	if w.ServerID != c.ServerID || w.RoleID != cred.RoleID || w.RemoteUser != r.Login.User {
		return match{}, RejectServerMismatch, nil
	}
	afterEnd, reason := svc.window(w, r.Time, now, true)
	if reason != "" {
		return match{}, reason, nil
	}
	return match{sessionID: w.SessionID, correlation: CorrelationKeyWindow, confidence: ConfidenceMedium, afterEnd: afterEnd, bind: true}, "", nil
}

// window checks t against the session's lifetime (grant start − skew … end + skew). Past the end it accepts up to
// PostSessionWindow when allowAfter is set (detached processes keep the audit session) and flags the record.
func (svc *Service) window(w sessionWindow, t, now time.Time, allowAfter bool) (afterEnd bool, reason string) {
	skew := svc.opts.MaxSkew
	ts := t.UnixMicro()
	start := min(w.StartsAt, w.OpenedAt)
	if ts < start-skew.Microseconds() {
		return false, RejectOutsideWindow
	}
	end := now.UnixMicro()
	switch {
	case w.ClosedAt.Valid:
		end = w.ClosedAt.Int64
	case w.EndedAt.Valid:
		end = w.EndedAt.Int64
	}
	if ts <= end+skew.Microseconds() {
		return false, ""
	}
	if allowAfter && ts <= end+svc.opts.PostSessionWindow.Microseconds() {
		return true, ""
	}
	return false, RejectOutsideWindow
}

// details is the sealed part of a record: what ran, which may contain secrets.
type details struct {
	Exe       string   `json:"exe"`
	Argv      []string `json:"argv"`
	CWD       string   `json:"cwd,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

func detailsAAD(recordID string) []byte {
	return keyring.FieldAAD("destaudit_records", "details_enc", recordID)
}

// prepare reserves timeline sequence numbers and seals details outside the write transaction (Sequencer.Next must
// not run inside one, HP-DB-004).
func (svc *Service) prepare(ctx context.Context, accepted []*pending) error {
	perSession := map[string][]*pending{}
	var order []string
	for _, p := range accepted {
		if _, ok := perSession[p.m.sessionID]; !ok {
			order = append(order, p.m.sessionID)
		}
		perSession[p.m.sessionID] = append(perSession[p.m.sessionID], p)
	}
	for _, sid := range order {
		ps := perSession[sid]
		first, err := svc.seq.Next(ctx, sid, int64(len(ps)))
		if err != nil {
			return err
		}
		for i, p := range ps {
			p.seq = first + int64(i)
		}
	}
	for _, p := range accepted {
		p.id = ids.New(PrefixRecord)
		pt, err := json.Marshal(details{Exe: p.rec.Exe, Argv: p.rec.Argv, CWD: p.rec.CWD, Truncated: p.rec.Truncated})
		if err != nil {
			return err
		}
		if p.sealed, err = svc.kr.Seal(keyring.PurposeField, detailsAAD(p.id), pt); err != nil {
			return err
		}
		p.argvLen, p.argBytes = len(p.rec.Argv), wire.ArgvBytes(p.rec.Argv)
	}
	return nil
}

func (svc *Service) commit(ctx context.Context, c db.DestauditCollector, b *wire.Batch, env *wire.Envelope, sum []byte,
	accepted []*pending, base *IngestResult) (*IngestResult, error) {
	var res IngestResult
	var sessions []string
	err := svc.s.W().TxNamed(ctx, "destaudit.ingest", func(tx *store.Tx) error {
		// Reset per attempt: the callback re-runs on SQLITE_BUSY.
		res = *base
		res.Rejections = append([]Rejection(nil), base.Rejections...)
		sessions = sessions[:0]
		seenSession := map[string]bool{}

		n, err := tx.Q.AdvanceDestauditCollector(ctx, db.AdvanceDestauditCollectorParams{Seq: b.Seq, PayloadSha256: sum,
			Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, ID: c.ID})
		if err != nil {
			return err
		}
		if n == 0 {
			cur, err := tx.Q.GetDestauditCollector(ctx, c.ID)
			if err != nil {
				return err
			}
			if cur.State != StateActive {
				return errUnauthorized
			}
			return &ReplayError{LastSeq: cur.LastSeq}
		}
		for _, p := range accepted {
			if p.m.bind {
				ok, err := bindLogin(ctx, tx, c.ID, p)
				if err != nil {
					return err
				}
				if !ok {
					res.Rejections = append(res.Rejections, Rejection{RecordID: p.rec.ID, Reason: RejectLoginConflict})
					continue
				}
			}
			evID, err := svc.insertRecord(ctx, tx, c.ID, b.Seq, p)
			if err != nil {
				return err
			}
			if evID == "" {
				res.Duplicates++
				continue
			}
			res.Accepted++
			if !seenSession[p.m.sessionID] {
				seenSession[p.m.sessionID] = true
				sessions = append(sessions, p.m.sessionID)
			}
		}
		res.Rejected = len(res.Rejections)
		if err := tx.Q.InsertDestauditBatch(ctx, db.InsertDestauditBatchParams{CollectorID: c.ID, Seq: b.Seq, PayloadSha256: sum,
			Signature: env.Signature, SentAt: b.SentAt.UnixMicro(), ReceivedAt: tx.NowMicros(), Records: int64(res.Records),
			Accepted: int64(res.Accepted), Duplicates: int64(res.Duplicates), Rejected: int64(res.Rejected)}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorProvider, ID: "destaudit:" + c.ID},
			Action: "destaudit.batch.ingested", Target: audit.Target{Type: "destaudit_collector", ID: c.ID},
			Details: map[string]any{"server_id": c.ServerID, "seq": b.Seq, "records": res.Records, "accepted": res.Accepted,
				"duplicates": res.Duplicates, "rejected": res.Rejected, "sessions": len(sessions)}})
		if err != nil {
			return err
		}
		if svc.opts.Bus != nil {
			touched := append([]string(nil), sessions...)
			tx.AfterCommit(func() {
				for _, sid := range touched {
					svc.opts.Bus.Publish(eventbus.Event{Topic: eventbus.TopicSessionUpdated, Key: sid, Payload: sid})
				}
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// bindLogin binds the destination login to the matched session, or confirms an existing binding. It reports false
// when the login is already bound to a different session (a destination login cannot span two access sessions).
func bindLogin(ctx context.Context, tx *store.Tx, collectorID string, p *pending) (bool, error) {
	if err := tx.Q.InsertDestauditLogin(ctx, db.InsertDestauditLoginParams{CollectorID: collectorID, LoginRef: p.rec.Login.Ref,
		AccessSessionID: p.m.sessionID, ConnectionID: sql.NullString{String: p.m.connectionID, Valid: p.m.connectionID != ""},
		Correlation: p.m.correlation, BoundAt: tx.NowMicros()}); err != nil {
		return false, err
	}
	bnd, err := tx.Q.GetDestauditLogin(ctx, db.GetDestauditLoginParams{CollectorID: collectorID, LoginRef: p.rec.Login.Ref})
	if err != nil {
		return false, err
	}
	return bnd.AccessSessionID == p.m.sessionID, nil
}

// insertRecord stores the record and its timeline event. It returns "" when the record already exists.
func (svc *Service) insertRecord(ctx context.Context, tx *store.Tx, collectorID string, batchSeq int64, p *pending) (string, error) {
	evID := ids.New(ids.Event)
	n, err := tx.Q.InsertDestauditRecord(ctx, db.InsertDestauditRecordParams{ID: p.id, CollectorID: collectorID, RecordRef: p.rec.ID,
		BatchSeq: batchSeq, AccessSessionID: p.m.sessionID, ConnectionID: sql.NullString{String: p.m.connectionID, Valid: p.m.connectionID != ""},
		TimelineEventID: evID, Correlation: p.m.correlation, Confidence: p.m.confidence, AfterSessionEnd: boolInt(p.m.afterEnd),
		ReportedAt: p.rec.Time.UnixMicro(), ReceivedAt: tx.NowMicros(), DetailsEnc: p.sealed})
	if err != nil || n == 0 {
		return "", err
	}
	data := map[string]any{
		"provenance":        Provenance,
		"verified":          false,
		"source":            p.rec.Source,
		"collector_id":      collectorID,
		"record_id":         p.id,
		"correlation":       p.m.correlation,
		"confidence":        p.m.confidence,
		"reported_at":       p.rec.Time.UTC().Format(time.RFC3339Nano),
		"after_session_end": p.m.afterEnd,
		"pid":               p.rec.PID,
		"ppid":              p.rec.PPID,
		"uid":               p.rec.UID,
		"auid":              p.rec.AUID,
		"success":           p.rec.Success,
		"argc":              p.argvLen,
		"argv_bytes":        p.argBytes,
	}
	if p.rec.Truncated {
		data["truncated"] = true
	}
	err = access.AppendTimeline(ctx, tx, access.TimelineEvent{ID: evID, SessionID: p.m.sessionID, Seq: p.seq, Type: access.EvDestinationExec,
		ConnectionID: p.m.connectionID, Data: data, IdempotencyKey: access.EvDestinationExec + "|" + collectorID + "|" + p.rec.ID})
	if err != nil {
		return "", err
	}
	return evID, nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
