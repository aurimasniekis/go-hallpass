package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// ReconcileResult summarizes startup reconciliation of recordings (PLAN §13.6).
type ReconcileResult struct {
	Finalized   int // completed segments whose DB update was lost (crash between rename and commit)
	Interrupted int // partial segments recovered to their authentic prefix
	Missing     int
	Failed      int
	Orphans     int
}

// ReconcileStartup repairs segment state after a crash. Run before accepting connections.
func (svc *Service) ReconcileStartup(ctx context.Context) (*ReconcileResult, error) {
	res := &ReconcileResult{}
	open, err := svc.s.R().OpenSegments(ctx)
	if err != nil {
		return nil, err
	}
	for _, seg := range open {
		if err := svc.reconcileSegment(ctx, seg, res); err != nil {
			return res, fmt.Errorf("reconcile segment %s: %w", seg.ID, err)
		}
	}
	if err := svc.quarantineOrphans(ctx, res); err != nil {
		return res, err
	}
	for range res.Interrupted {
		svc.opts.Metrics.SegmentClosed(metrics.SegmentInterrupted)
	}
	for range res.Failed {
		svc.opts.Metrics.SegmentClosed(metrics.SegmentFailed)
	}
	return res, nil
}

func (svc *Service) reconcileSegment(ctx context.Context, seg db.RecordingSegment, res *ReconcileResult) error {
	partial := seg.Path + hprec.PartialSuffix
	opts := []hprec.Option{hprec.ExpectSegmentID(seg.ID), hprec.ExpectSessionID(seg.AccessSessionID), hprec.ExpectChannelID(seg.ChannelID)}
	switch {
	case exists(seg.Path):
		rep, err := hprec.Verify(seg.Path, svc.wrapper, opts...)
		if err != nil {
			return err
		}
		if rep.Status == hprec.StatusOK && rep.Final {
			res.Finalized++
			return svc.commitManifest(ctx, seg.ID, "finalized", manifestFromReport(seg, rep))
		}
		res.Interrupted++
		return svc.commitManifest(ctx, seg.ID, "interrupted", manifestFromReport(seg, rep))
	case exists(partial):
		q := filepath.Join(svc.qdir, seg.ID+".partial.orig")
		rr, err := hprec.Recover(partial, svc.wrapper, q, opts...)
		if err != nil {
			// Header or key slots unusable: nothing authentic to keep.
			res.Failed++
			svc.log.Error("recording unrecoverable", slog.String(obs.FieldSegmentID, seg.ID), obs.Err(err))
			dest := filepath.Join(svc.qdir, seg.ID+".unrecoverable")
			if mvErr := os.Rename(partial, dest); mvErr == nil {
				_ = svc.recordQuarantine(ctx, partial, dest, "unrecoverable: "+err.Error())
			}
			return svc.setState(ctx, seg.ID, "failed", "unrecoverable")
		}
		if rr.QuarantinePath != "" {
			_ = svc.recordQuarantine(ctx, partial, rr.QuarantinePath, "truncated partial frame")
		}
		state := "interrupted"
		if rr.Complete {
			state = "finalized"
			res.Finalized++
		} else {
			res.Interrupted++
		}
		return svc.commitManifest(ctx, seg.ID, state, rr.Manifest)
	default:
		res.Missing++
		svc.log.Error("recording file missing", slog.String(obs.FieldSegmentID, seg.ID), slog.String("path", seg.Path))
		return svc.setState(ctx, seg.ID, "missing", "file_missing_after_restart")
	}
}

func manifestFromReport(seg db.RecordingSegment, rep hprec.Report) hprec.Manifest {
	return hprec.Manifest{SegmentID: seg.ID, Path: seg.Path, HeaderSHA256: rep.HeaderSHA256, CiphertextSHA256: rep.CiphertextSHA256,
		Frames: rep.Frames, Bytes: rep.FileSize, Records: rep.Records, FirstSeq: rep.FirstSeq, LastSeq: rep.LastSeq, EndReason: rep.EndReason}
}

func (svc *Service) commitManifest(ctx context.Context, segID, state string, m hprec.Manifest) error {
	return svc.s.W().TxNamed(ctx, "recording.reconcile_commit", func(tx *store.Tx) error {
		return svc.finalizeRowTx(ctx, tx, segID, state, m)
	})
}

func (svc *Service) setState(ctx context.Context, segID, state, reason string) error {
	return svc.s.W().TxNamed(ctx, "recording.set_state", func(tx *store.Tx) error {
		_, err := tx.Q.SetSegmentState(ctx, db.SetSegmentStateParams{State: state, EndReason: sql.NullString{String: reason, Valid: true}, ID: segID, FromState: "open"})
		return err
	})
}

func (svc *Service) recordQuarantine(ctx context.Context, orig, q, reason string) error {
	return svc.s.W().TxNamed(ctx, "recording.quarantine", func(tx *store.Tx) error {
		return tx.Q.InsertQuarantine(ctx, db.InsertQuarantineParams{OriginalPath: orig, QuarantinePath: q, Reason: reason, At: tx.NowMicros()})
	})
}

// quarantineOrphans moves files under recordings/ that no segment row references (PLAN §13.6 step 3).
func (svc *Service) quarantineOrphans(ctx context.Context, res *ReconcileResult) error {
	rows, err := svc.s.R().AllSegmentPaths(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, r := range rows {
		known[r.Path] = true
		known[r.Path+hprec.PartialSuffix] = true
	}
	return filepath.WalkDir(svc.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || known[path] {
			return nil
		}
		rel, _ := filepath.Rel(svc.dir, path)
		dest := filepath.Join(svc.qdir, "orphan-"+strings.ReplaceAll(rel, string(filepath.Separator), "_"))
		// The recordings tree is gateway-owned (0700); rename moves the entry itself and never follows a final symlink.
		if err := os.Rename(path, dest); err != nil { //nolint:gosec // G122: see above

			return err
		}
		res.Orphans++
		svc.log.Warn("orphan recording file quarantined", slog.String("path", path), slog.String("quarantine", dest))
		return svc.recordQuarantine(ctx, path, dest, "orphan: no segment row")
	})
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

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

// Verify authenticates segment files against the database (header hash, ciphertext hash, final frame) and checks the
// integrity chain hashes and MACs. sessionID limits the check to one session ("" = all).
func (svc *Service) Verify(ctx context.Context, sessionID string) (*VerifyResult, error) {
	var segs []db.RecordingSegment
	var err error
	if sessionID != "" {
		segs, err = svc.s.R().SegmentsForSession(ctx, sessionID)
	} else {
		segs, err = svc.allSegments(ctx)
	}
	if err != nil {
		return nil, err
	}
	out := &VerifyResult{OK: true}
	now := svc.opts.Clock.Now()
	for _, seg := range segs {
		r := svc.verifySegment(seg)
		out.Segments = append(out.Segments, r)
		if r.Status == "corrupt" || r.Status == "missing" {
			out.OK = false
		}
		_ = svc.s.W().TxNamed(ctx, "recording.verified", func(tx *store.Tx) error {
			return tx.Q.RecordVerification(ctx, db.RecordVerificationParams{VerifiedAt: sql.NullInt64{Int64: now.UnixMicro(), Valid: true},
				VerifyResult: sql.NullString{String: r.Status, Valid: true}, ID: seg.ID})
		})
	}
	out.ChainLen, err = svc.verifyChain(ctx)
	out.ChainOK = err == nil
	if err != nil {
		out.Problem, out.OK = err.Error(), false
	}
	return out, nil
}

func (svc *Service) allSegments(ctx context.Context) ([]db.RecordingSegment, error) {
	var all []db.RecordingSegment
	for _, st := range []string{"finalized", "interrupted", "open", "failed", "missing"} {
		rows, err := svc.s.R().SegmentsByState(ctx, db.SegmentsByStateParams{State: st, Limit: 1_000_000})
		if err != nil {
			return nil, err
		}
		all = append(all, rows...)
	}
	return all, nil
}

func (svc *Service) verifySegment(seg db.RecordingSegment) SegmentReport {
	r := SegmentReport{SegmentID: seg.ID, SessionID: seg.AccessSessionID, State: seg.State}
	switch seg.State {
	case "deleted", "failed":
		r.Status = "skipped"
		return r
	case "missing":
		r.Status = "missing"
		return r
	case "open":
		r.Status = "skipped"
		r.Problem = "segment is being written"
		return r
	}
	opts := []hprec.Option{hprec.ExpectSegmentID(seg.ID), hprec.ExpectSessionID(seg.AccessSessionID), hprec.ExpectChannelID(seg.ChannelID)}
	if len(seg.HeaderSha256) == 32 {
		var h [32]byte
		copy(h[:], seg.HeaderSha256)
		opts = append(opts, hprec.ExpectHeaderSHA256(h))
	}
	rep, err := hprec.Verify(seg.Path, svc.wrapper, opts...)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.Status = "missing"
		} else {
			r.Status, r.Problem = "corrupt", err.Error()
		}
		return r
	}
	switch {
	case rep.Status == hprec.StatusCorrupt:
		r.Status, r.Problem = "corrupt", errString(rep.Problem)
	case !bytes.Equal(rep.CiphertextSHA256[:], seg.CiphertextSha256):
		r.Status, r.Problem = "corrupt", "ciphertext hash differs from the recorded manifest"
	case seg.State == "finalized" && !rep.Final:
		r.Status, r.Problem = "corrupt", "final frame missing for a finalized segment"
	case !rep.Final:
		r.Status = "interrupted"
	default:
		r.Status = "ok"
	}
	return r
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (svc *Service) verifyChain(ctx context.Context) (int64, error) {
	prev := make([]byte, sha256.Size)
	var after, n int64
	for {
		rows, err := svc.s.R().ChainFrom(ctx, db.ChainFromParams{Seq: after, Limit: 1000})
		if err != nil {
			return n, err
		}
		for _, e := range rows {
			if e.Seq != after+1 {
				return n, fmt.Errorf("integrity chain gap at %d", e.Seq)
			}
			if !bytes.Equal(e.PrevHash, prev) {
				return n, fmt.Errorf("integrity chain link broken at %d", e.Seq)
			}
			h := sha256.New()
			h.Write(prev)
			h.Write(e.ManifestSha256)
			want := h.Sum(nil)
			if !bytes.Equal(want, e.Hash) {
				return n, fmt.Errorf("integrity chain hash mismatch at %d", e.Seq)
			}
			if !svc.kr.VerifyMAC(keyring.PurposeManifest, e.Hash, e.Mac) {
				return n, fmt.Errorf("integrity chain MAC invalid at %d", e.Seq)
			}
			prev, after = e.Hash, e.Seq
			n++
		}
		if len(rows) < 1000 {
			return n, nil
		}
	}
}

// ChainHead returns the latest integrity-chain hash for external anchoring (HP-CRY-008).
func (svc *Service) ChainHead(ctx context.Context) (int64, []byte, error) {
	h, err := svc.s.R().ChainHead(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	return h.Seq, h.Hash, err
}

// ApplyRetention deletes recordings of closed sessions past their retention and keeps tombstones (HP-REC-013).
// Sessions without a deletion time get one: closed_at + retention.
func (svc *Service) ApplyRetention(ctx context.Context, retention time.Duration) (int, error) {
	pending, err := svc.s.R().ClosedSessionsWithoutRetention(ctx, 500)
	if err != nil {
		return 0, err
	}
	if len(pending) > 0 {
		err := svc.s.W().TxNamed(ctx, "recording.retention_schedule", func(tx *store.Tx) error {
			for _, p := range pending {
				closed := tx.NowMicros()
				if p.ClosedAt.Valid {
					closed = p.ClosedAt.Int64
				}
				if err := tx.Q.SetSessionDeleteAfter(ctx, db.SetSessionDeleteAfterParams{
					DeleteAfter: sql.NullInt64{Int64: time.UnixMicro(closed).Add(retention).UnixMicro(), Valid: true}, ID: p.ID}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	expired, err := svc.s.R().ExpiredSessions(ctx, db.ExpiredSessionsParams{DeleteAfter: sql.NullInt64{Int64: svc.opts.Clock.Now().UnixMicro(), Valid: true}, Limit: 100})
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, sid := range expired {
		segs, err := svc.s.R().SegmentsForSession(ctx, sid)
		if err != nil {
			return deleted, err
		}
		for _, seg := range segs {
			if seg.State == "deleted" {
				continue
			}
			for _, p := range []string{seg.Path, seg.Path + hprec.PartialSuffix} {
				if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return deleted, err
				}
			}
			_ = store.FsyncDir(filepath.Dir(seg.Path))
			if err := svc.s.W().TxNamed(ctx, "recording.retention_delete", func(tx *store.Tx) error {
				_, err := tx.Q.MarkSegmentDeleted(ctx, seg.ID)
				return err
			}); err != nil {
				return deleted, err
			}
			deleted++
		}
		if err := svc.s.W().TxNamed(ctx, "recording.retention_timeline", func(tx *store.Tx) error {
			return tx.Q.DeleteSessionTimelinePayloads(ctx, sql.NullString{String: sid, Valid: true})
		}); err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// ReadPage returns decrypted records of one segment for replay (≤ 256 KiB per page). Callers must authorize
// recording.play and audit the access (HP-REC-014).
func (svc *Service) ReadPage(ctx context.Context, segmentID string, fromSeq uint64, maxBytes int) (hprec.Page, error) {
	seg, err := svc.s.R().GetSegment(ctx, segmentID)
	if err != nil {
		return hprec.Page{}, err
	}
	path := seg.Path
	if seg.State == "open" {
		path += hprec.PartialSuffix
	}
	return hprec.ReadPage(path, svc.wrapper, fromSeq, maxBytes, hprec.ExpectSegmentID(seg.ID), hprec.ExpectSessionID(seg.AccessSessionID))
}
