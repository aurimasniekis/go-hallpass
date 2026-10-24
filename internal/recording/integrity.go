package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/recording/layout"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// SegmentReport is one segment's verification outcome (HP-CRY-005).
type SegmentReport struct {
	SegmentID string `json:"segment_id"`
	SessionID string `json:"session_id"`
	State     string `json:"state"`
	Status    string `json:"status"` // ok | interrupted | corrupt | missing | orphan | skipped
	Problem   string `json:"problem,omitempty"`
}

// VerifyResult summarizes a verification run.
type VerifyResult struct {
	Segments []SegmentReport `json:"segments"`
	ChainOK  bool            `json:"chain_ok"`
	ChainLen int64           `json:"chain_length"`
	Problem  string          `json:"chain_problem,omitempty"`
	OK       bool            `json:"ok"`
}

// tombstoneDoc is the canonical content authenticated by a retention tombstone's MAC.
type tombstoneDoc struct {
	SegmentID    string `json:"segment_id"`
	SessionID    string `json:"session_id"`
	PriorState   string `json:"prior_state"`
	ChainSeq     int64  `json:"chain_seq"`
	DeleteAfter  int64  `json:"delete_after"`
	DeletedAt    int64  `json:"deleted_at"`
	AuditEventID string `json:"audit_event_id"`
}

// tombstoneData is the message MAC'd with the manifest key for a tombstone (domain-separated from chain entries and
// the chain head).
func tombstoneData(t db.RecordingTombstone) []byte {
	b, _ := json.Marshal(tombstoneDoc{SegmentID: t.SegmentID, SessionID: t.AccessSessionID, PriorState: t.PriorState, ChainSeq: t.ChainSeq,
		DeleteAfter: t.DeleteAfter, DeletedAt: t.DeletedAt, AuditEventID: t.AuditEventID}) // strings and integers only
	return append([]byte("hallpass/rec/tombstone/v1|"), b...)
}

func chained(state string) bool { return state == "finalized" || state == "interrupted" }

// Verify authenticates segment files against the database and the database against the integrity chain
// (HP-CRY-005, SR-02). For every chain entry it checks the hash link and MAC and recomputes the manifest from the
// segment's current row, so changing, relabeling or removing a chained row is detected. Every finalized or
// interrupted row must have a chain entry, every deleted row an authenticated retention tombstone, and the
// authenticated head record must name the last chain entry, so removing the newest entries is detected too. Files
// are read only at their canonical location. sessionID limits the per-segment checks to one session ("" = all); the
// chain itself is always checked in full.
func (svc *Service) Verify(ctx context.Context, sessionID string) (*VerifyResult, error) {
	var segs []db.RecordingSegment
	var err error
	if sessionID != "" {
		segs, err = svc.s.R().SegmentsForSession(ctx, sessionID)
	} else {
		segs, err = svc.s.R().AllSegments(ctx)
	}
	if err != nil {
		return nil, err
	}
	sc, err := svc.scanChain(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	out := &VerifyResult{OK: true, ChainLen: sc.n}
	now := svc.opts.Clock.Now()
	for _, seg := range segs {
		var ref *chainRef
		if r, ok := sc.refs[seg.ID]; ok {
			ref = &r
		}
		r := svc.verifySegment(ctx, seg, ref)
		out.Segments = append(out.Segments, r)
		if r.Status == "corrupt" || r.Status == "missing" {
			out.OK = false
		}
		_ = svc.s.W().TxNamed(ctx, "recording.verified", func(tx *store.Tx) error {
			return tx.Q.RecordVerification(ctx, db.RecordVerificationParams{VerifiedAt: sql.NullInt64{Int64: now.UnixMicro(), Valid: true},
				VerifyResult: sql.NullString{String: r.Status, Valid: true}, ID: seg.ID})
		})
	}
	for _, r := range sc.vanished {
		out.Segments = append(out.Segments, r)
		out.OK = false
	}
	var problems []string
	if sc.linkErr != nil {
		problems = append(problems, sc.linkErr.Error())
	}
	if p, err := svc.checkHead(ctx, sc); err != nil {
		return nil, err
	} else if p != "" {
		problems = append(problems, p)
	}
	out.ChainOK = len(problems) == 0
	if !out.ChainOK {
		out.Problem, out.OK = strings.Join(problems, "; "), false
	}
	return out, nil
}

// chainRef is what the chain says about one segment.
type chainRef struct {
	seq     int64
	problem string // the row no longer matches the entry ("" = matches)
}

type chainScan struct {
	n        int64
	linkErr  error // first hash-link, sequence or MAC failure
	lastSeq  int64
	lastHash []byte
	refs     map[string]chainRef
	vanished []SegmentReport // chain entries whose segment row no longer exists
}

// scanChain walks the whole integrity chain. Link and MAC checks stop at the first failure, but every entry is still
// compared with its segment row, so one break does not hide later metadata changes.
func (svc *Service) scanChain(ctx context.Context, sessionID string) (*chainScan, error) {
	const page = 1000
	sc := &chainScan{refs: map[string]chainRef{}}
	prev := make([]byte, sha256.Size)
	var after int64
	for {
		rows, err := svc.s.R().ChainFrom(ctx, db.ChainFromParams{Seq: after, Limit: page})
		if err != nil {
			return nil, err
		}
		for _, e := range rows {
			if sc.linkErr == nil {
				sc.linkErr = svc.checkLink(e, after, prev)
			}
			prev, after = e.Hash, e.Seq
			sc.n++
			sc.lastSeq, sc.lastHash = e.Seq, e.Hash
			row, err := svc.s.R().GetSegment(ctx, e.SegmentID)
			if errors.Is(err, sql.ErrNoRows) {
				sc.vanished = append(sc.vanished, SegmentReport{SegmentID: e.SegmentID, Status: "missing",
					Problem: fmt.Sprintf("integrity-chain entry seq %d refers to a segment row that no longer exists", e.Seq)})
				continue
			}
			if err != nil {
				return nil, err
			}
			if sessionID != "" && row.AccessSessionID != sessionID {
				continue
			}
			p, err := svc.entryProblem(ctx, row, e)
			if err != nil {
				return nil, err
			}
			sc.refs[row.ID] = chainRef{seq: e.Seq, problem: p}
		}
		if len(rows) < page {
			return sc, nil
		}
	}
}

func (svc *Service) checkLink(e db.IntegrityChain, after int64, prev []byte) error {
	if e.Seq != after+1 {
		return fmt.Errorf("integrity chain gap at %d", e.Seq)
	}
	if !bytes.Equal(e.PrevHash, prev) {
		return fmt.Errorf("integrity chain link broken at %d", e.Seq)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(e.ManifestSha256)
	if !bytes.Equal(h.Sum(nil), e.Hash) {
		return fmt.Errorf("integrity chain hash mismatch at %d", e.Seq)
	}
	if !svc.kr.VerifyMAC(keyring.PurposeManifest, e.Hash, e.Mac) {
		return fmt.Errorf("integrity chain MAC invalid at %d", e.Seq)
	}
	return nil
}

// entryProblem recomputes the manifest of a chain entry from the segment's current row ("" = it matches).
func (svc *Service) entryProblem(ctx context.Context, row db.RecordingSegment, e db.IntegrityChain) (string, error) {
	state := row.State
	switch {
	case chained(state):
	case state == "deleted":
		ts, err := svc.s.R().GetTombstone(ctx, row.ID)
		if errors.Is(err, sql.ErrNoRows) {
			return "deleted without a retention tombstone", nil
		}
		if err != nil {
			return "", err
		}
		if !chained(ts.PriorState) {
			return fmt.Sprintf("tombstone prior state %q does not match integrity-chain entry seq %d", ts.PriorState, e.Seq), nil
		}
		state = ts.PriorState
	default:
		return fmt.Sprintf("segment is %s but has integrity-chain entry seq %d (metadata relabeled)", state, e.Seq), nil
	}
	if !bytes.Equal(rowManifest(row, state).sum(), e.ManifestSha256) {
		return fmt.Sprintf("segment metadata no longer matches its integrity-chain entry seq %d", e.Seq), nil
	}
	return "", nil
}

// checkHead compares the authenticated chain-head record with the last chain entry ("" = consistent).
func (svc *Service) checkHead(ctx context.Context, sc *chainScan) (string, error) {
	head, err := svc.s.R().GetChainHeadRecord(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if sc.n == 0 {
			return "", nil
		}
		return "integrity chain head record is missing (removed, or the chain was recorded before schema version 19; " +
			"see `hallpass verify --adopt-chain-head`)", nil
	case err != nil:
		return "", err
	}
	if !svc.kr.VerifyMAC(keyring.PurposeManifest, chainHeadData(head.Seq, head.Hash), head.Mac) {
		return "integrity chain head record does not authenticate (modified)", nil
	}
	if head.Seq != sc.lastSeq || !bytes.Equal(head.Hash, sc.lastHash) {
		return fmt.Sprintf("integrity chain head record names seq %d but the chain ends at seq %d (newest entries removed or rewritten)",
			head.Seq, sc.lastSeq), nil
	}
	return "", nil
}

func (svc *Service) verifySegment(ctx context.Context, seg db.RecordingSegment, ref *chainRef) SegmentReport {
	r := SegmentReport{SegmentID: seg.ID, SessionID: seg.AccessSessionID, State: seg.State}
	corrupt := func(p string) SegmentReport { r.Status, r.Problem = "corrupt", p; return r }
	path, err := svc.SegmentFile(seg)
	if err != nil {
		return corrupt("invalid segment or session id: " + err.Error())
	}
	if !layout.Matches(seg.Path, seg.AccessSessionID, seg.ID) {
		return corrupt(fmt.Sprintf("recorded path %q is not the segment's location under recordings/ (%q)", seg.Path, path))
	}
	if ref != nil && ref.problem != "" {
		return corrupt(ref.problem)
	}
	switch seg.State {
	case "deleted":
		if p := svc.tombstoneProblem(ctx, seg, ref); p != "" {
			return corrupt(p)
		}
		r.Status, r.Problem = "skipped", "deleted by retention"
		return r
	case "failed":
		r.Status = "skipped"
		return r
	case "missing":
		r.Status = "missing"
		return r
	case "open":
		r.Status, r.Problem = "skipped", "segment is being written"
		return r
	}
	if ref == nil {
		return corrupt("no integrity-chain entry (removed)")
	}
	rep, err := hprec.Verify(path, svc.wrapper, expectations(seg)...)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.Status = "missing"
			return r
		}
		return corrupt(err.Error())
	}
	switch {
	case rep.Status == hprec.StatusCorrupt:
		return corrupt(errString(rep.Problem))
	case !bytes.Equal(rep.CiphertextSHA256[:], seg.CiphertextSha256):
		return corrupt("ciphertext hash differs from the recorded manifest")
	case seg.State == "finalized" && !rep.Final:
		return corrupt("final frame missing for a finalized segment")
	case !rep.Final:
		r.Status = "interrupted"
	default:
		r.Status = "ok"
	}
	return r
}

// tombstoneProblem checks that a deleted segment was deleted by retention: an authenticated tombstone that matches
// the segment, its chain entry and an audit event, and a deletion after the session's retention time (SR-17).
func (svc *Service) tombstoneProblem(ctx context.Context, seg db.RecordingSegment, ref *chainRef) string {
	ts, err := svc.s.R().GetTombstone(ctx, seg.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return "deleted without a retention tombstone"
	}
	if err != nil {
		return "read retention tombstone: " + err.Error()
	}
	switch {
	case !svc.kr.VerifyMAC(keyring.PurposeManifest, tombstoneData(ts), ts.Mac):
		return "retention tombstone does not authenticate (modified)"
	case ts.AccessSessionID != seg.AccessSessionID:
		return "retention tombstone belongs to another session"
	case ts.DeletedAt <= ts.DeleteAfter:
		return "retention tombstone records a deletion before the retention time"
	case chained(ts.PriorState) && (ref == nil || ref.seq != ts.ChainSeq):
		return "retention tombstone does not match the segment's integrity-chain entry"
	case !chained(ts.PriorState) && (ref != nil || ts.ChainSeq != 0):
		return "retention tombstone claims an unchained segment, but it is chained"
	}
	var n int
	if err := svc.s.ReadDB().QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE id = ? AND action = 'recording.deleted' AND target_id = ?`,
		ts.AuditEventID, seg.ID).Scan(&n); err != nil {
		return "read retention audit event: " + err.Error()
	}
	if n != 1 {
		return fmt.Sprintf("retention audit event %s is missing", ts.AuditEventID)
	}
	return ""
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ChainHead returns the latest integrity-chain hash for external anchoring (HP-CRY-008).
func (svc *Service) ChainHead(ctx context.Context) (int64, []byte, error) {
	h, err := svc.s.R().ChainHead(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	return h.Seq, h.Hash, err
}

// ErrChainBroken means the integrity chain's links or MACs do not verify, so its head cannot be adopted.
var ErrChainBroken = errors.New("integrity chain does not verify")

// AdoptChainHead writes the authenticated head record for the current last chain entry, after checking every hash
// link and MAC. It is an explicit operator decision (`hallpass verify --adopt-chain-head`, offline) for chains
// recorded before the head record existed, or after the operator has investigated a reported head mismatch and
// compared the chain with exported anchors. It is audited. It returns the adopted seq and hash.
func (svc *Service) AdoptChainHead(ctx context.Context, actor audit.Actor) (int64, []byte, error) {
	var seq int64
	var hash []byte
	err := svc.s.W().TxNamed(ctx, "recording.adopt_chain_head", func(tx *store.Tx) error {
		var err error
		seq, hash, err = svc.adoptChainHeadTx(ctx, tx, actor)
		return err
	})
	return seq, hash, err
}

func (svc *Service) adoptChainHeadTx(ctx context.Context, tx *store.Tx, actor audit.Actor) (int64, []byte, error) {
	prev := make([]byte, sha256.Size)
	var after int64
	for {
		rows, err := tx.Q.ChainFrom(ctx, db.ChainFromParams{Seq: after, Limit: 1000})
		if err != nil {
			return 0, nil, err
		}
		for _, e := range rows {
			if err := svc.checkLink(e, after, prev); err != nil {
				return 0, nil, fmt.Errorf("%w: %w", ErrChainBroken, err)
			}
			prev, after = e.Hash, e.Seq
		}
		if len(rows) < 1000 {
			break
		}
	}
	if after == 0 {
		return 0, nil, errors.New("the integrity chain is empty; nothing to adopt")
	}
	details := map[string]any{"seq": after, "hash": hex.EncodeToString(prev)}
	if old, err := tx.Q.GetChainHeadRecord(ctx); err == nil {
		details["previous_seq"], details["previous_hash"] = old.Seq, hex.EncodeToString(old.Hash)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, err
	}
	if err := svc.writeChainHeadTx(ctx, tx, after, prev); err != nil {
		return 0, nil, err
	}
	_, err := svc.opts.Audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "recording.chain_head_adopted",
		Target: audit.Target{Type: "integrity_chain", ID: fmt.Sprint(after)}, Details: details})
	return after, prev, err
}
