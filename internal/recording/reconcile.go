package recording

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
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
	Failed      int // unrecoverable partial files and final files that do not verify (both quarantined)
	Orphans     int
	// SlotsRepaired counts segments whose key slots no longer unwrapped and were restored from the database copy
	// of the wrapped DEK (PLAN §13.4).
	SlotsRepaired int
	// SlotProblems counts segments whose slots could not be checked or repaired (logged; verify reports them).
	SlotProblems int
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
	if err := svc.repairSlots(ctx, res); err != nil {
		return res, err
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

// expectations are the header checks for a segment's file: IDs and the header hash registered at open.
func expectations(seg db.RecordingSegment) []hprec.Option {
	opts := []hprec.Option{hprec.ExpectSegmentID(seg.ID), hprec.ExpectSessionID(seg.AccessSessionID), hprec.ExpectChannelID(seg.ChannelID)}
	if len(seg.HeaderSha256) == 32 {
		var h [32]byte
		copy(h[:], seg.HeaderSha256)
		opts = append(opts, hprec.ExpectHeaderSHA256(h))
	}
	return opts
}

func (svc *Service) reconcileSegment(ctx context.Context, seg db.RecordingSegment, res *ReconcileResult) error {
	path, err := svc.SegmentFile(seg)
	if err != nil {
		// Only a tampered row has invalid IDs; leave it for verify to report.
		svc.log.Error("recording row has an invalid segment or session id", slog.String(obs.FieldSegmentID, seg.ID), obs.Err(err))
		return nil
	}
	if _, err := svc.s.R().ChainEntryForSegment(ctx, seg.ID); err == nil {
		// An open row is never chained; this one was relabeled after finalization. Leave it for verify to report.
		svc.log.Error("open recording segment already has an integrity-chain entry (metadata tampered)", slog.String(obs.FieldSegmentID, seg.ID))
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	partial := path + hprec.PartialSuffix
	opts := expectations(seg)
	switch {
	case exists(path):
		rep, err := hprec.Verify(path, svc.wrapper, opts...)
		if err != nil {
			return err
		}
		if rep.Status == hprec.StatusOK && rep.Final {
			res.Finalized++
			return svc.commitManifest(ctx, seg.ID, "finalized", manifestFromReport(seg, path, rep))
		}
		// A final name is given only after the final frame is fsynced (PLAN §13.5 step 4), so a final file without
		// a valid final frame was modified or damaged after the rename. Never chain it (SR-38).
		res.Failed++
		problem := "no final frame"
		if rep.Problem != nil {
			problem = rep.Problem.Error()
		}
		svc.log.Error("finalized recording file does not verify; quarantined", slog.String(obs.FieldSegmentID, seg.ID), slog.String("problem", problem))
		dest := filepath.Join(svc.qdir, seg.ID+".final.invalid")
		if err := os.Rename(path, dest); err != nil { //nolint:gosec // G122: canonical path inside the gateway-owned recordings tree
			return fmt.Errorf("quarantine %s: %w", path, err)
		}
		if err := svc.recordQuarantine(ctx, path, dest, "final segment file does not verify: "+problem); err != nil {
			return err
		}
		return svc.setState(ctx, seg.ID, "failed", "final_file_invalid")
	case exists(partial):
		q := filepath.Join(svc.qdir, seg.ID+".partial.orig")
		rr, err := hprec.Recover(partial, svc.wrapper, q, opts...)
		if err != nil {
			// Header or key slots unusable (or not this segment's header): nothing authentic to keep.
			res.Failed++
			svc.log.Error("recording unrecoverable", slog.String(obs.FieldSegmentID, seg.ID), obs.Err(err))
			dest := filepath.Join(svc.qdir, seg.ID+".unrecoverable")
			if mvErr := os.Rename(partial, dest); mvErr == nil { //nolint:gosec // G122: canonical path inside the recordings tree
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
		svc.log.Error("recording file missing", slog.String(obs.FieldSegmentID, seg.ID), slog.String("path", path))
		return svc.setState(ctx, seg.ID, "missing", "file_missing_after_restart")
	}
}

func manifestFromReport(seg db.RecordingSegment, path string, rep hprec.Report) hprec.Manifest {
	return hprec.Manifest{SegmentID: seg.ID, Path: path, HeaderSHA256: rep.HeaderSHA256, CiphertextSHA256: rep.CiphertextSHA256,
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

// repairSlots restores key slots that no longer unwrap from the database copy of the wrapped DEK (PLAN §13.4). The
// copy must unwrap under the segment's own AAD, so it cannot be forged without the recording key. Problems are
// logged and counted, never fatal: verify reports the affected segments.
func (svc *Service) repairSlots(ctx context.Context, res *ReconcileResult) error {
	const page = 500
	after := ""
	for {
		rows, err := svc.s.R().SegmentsWithFilesAfter(ctx, db.SegmentsWithFilesAfterParams{After: after, Lim: page})
		if err != nil {
			return err
		}
		for _, seg := range rows {
			after = seg.ID
			path, err := svc.SegmentFile(seg)
			if err != nil {
				continue
			}
			_, repaired, err := hprec.RepairSlotIfNeeded(path, svc.wrapper, seg.KeyID, seg.WrappedDek, expectations(seg)...)
			switch {
			case errors.Is(err, fs.ErrNotExist):
			case err != nil:
				res.SlotProblems++
				svc.log.Warn("recording key slots could not be checked or repaired", slog.String(obs.FieldSegmentID, seg.ID), obs.Err(err))
			case repaired:
				res.SlotsRepaired++
				svc.log.Warn("recording key slot repaired from the database copy", slog.String(obs.FieldSegmentID, seg.ID))
			}
		}
		if len(rows) < page {
			return nil
		}
	}
}

// quarantineOrphans moves files under recordings/ that are not the canonical file of any segment row to quarantine
// (PLAN §13.6 step 3).
func (svc *Service) quarantineOrphans(ctx context.Context, res *ReconcileResult) error {
	rows, err := svc.s.R().AllSegmentPaths(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, r := range rows {
		p := svc.segmentPath(r.AccessSessionID, r.ID)
		if p == "" {
			continue
		}
		known[p] = true
		known[p+hprec.PartialSuffix] = true
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

// ApplyRetention deletes recordings of closed sessions past their retention and keeps tombstones (HP-REC-013).
// Sessions without a deletion time get one: closed_at + retention(class), where class is the role's retention class.
// Each deletion is marked in one transaction with an audit event (recording.deleted) and an authenticated tombstone
// that verification requires for every deleted segment (SR-17). Files are removed only at their canonical location.
func (svc *Service) ApplyRetention(ctx context.Context, retention func(class string) time.Duration) (int, error) {
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
					DeleteAfter: sql.NullInt64{Int64: time.UnixMicro(closed).Add(retention(p.RetentionClass)).UnixMicro(), Valid: true}, ID: p.ID}); err != nil {
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
			ok, err := svc.deleteSegment(ctx, seg)
			if err != nil {
				return deleted, err
			}
			if ok {
				deleted++
			}
		}
		if err := svc.s.W().TxNamed(ctx, "recording.retention_timeline", func(tx *store.Tx) error {
			return tx.Q.DeleteSessionTimelinePayloads(ctx, sql.NullString{String: sid, Valid: true})
		}); err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// deleteSegment removes one segment's files and records the tombstone. A row whose IDs are invalid has no
// canonical location; it is skipped (and reported by verify) rather than trusting its stored path.
func (svc *Service) deleteSegment(ctx context.Context, seg db.RecordingSegment) (bool, error) {
	path, err := svc.SegmentFile(seg)
	if err != nil {
		svc.log.Error("retention skipped a segment with an invalid id", slog.String(obs.FieldSegmentID, seg.ID), obs.Err(err))
		return false, nil
	}
	for _, p := range []string{path, path + hprec.PartialSuffix} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	_ = store.FsyncDir(filepath.Dir(path))
	done := false
	err = svc.s.W().TxNamed(ctx, "recording.retention_delete", func(tx *store.Tx) error {
		var err error
		done, err = svc.markDeletedTx(ctx, tx, seg.ID)
		return err
	})
	return done, err
}

// markDeletedTx marks one segment deleted by retention, with its audit event and authenticated tombstone, if its
// session is closed and past delete_after. It reports whether the segment was marked.
func (svc *Service) markDeletedTx(ctx context.Context, tx *store.Tx, segID string) (bool, error) {
	cur, err := tx.Q.GetSegment(ctx, segID)
	if err != nil {
		return false, err
	}
	sess, err := tx.Q.GetSessionRetention(ctx, cur.AccessSessionID)
	if err != nil {
		return false, err
	}
	now := tx.NowMicros()
	if cur.State == "deleted" || sess.State != "closed" || !sess.DeleteAfter.Valid || sess.DeleteAfter.Int64 >= now {
		return false, nil
	}
	var chainSeq int64
	switch e, err := tx.Q.ChainEntryForSegment(ctx, cur.ID); {
	case err == nil:
		chainSeq = e.Seq
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	if n, err := tx.Q.MarkSegmentDeleted(ctx, cur.ID); err != nil || n == 0 {
		return false, err
	}
	auditID, err := svc.opts.Audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "recording.deleted",
		Target: audit.Target{Type: "recording_segment", ID: cur.ID},
		Details: map[string]any{"access_session_id": cur.AccessSessionID, "channel_id": cur.ChannelID, "prior_state": cur.State,
			"chain_seq": chainSeq, "delete_after": sess.DeleteAfter.Int64, "reason": "retention"}})
	if err != nil {
		return false, err
	}
	ts := db.RecordingTombstone{SegmentID: cur.ID, AccessSessionID: cur.AccessSessionID, PriorState: cur.State, ChainSeq: chainSeq,
		DeleteAfter: sess.DeleteAfter.Int64, DeletedAt: now, AuditEventID: auditID}
	if ts.Mac, err = svc.kr.MAC(keyring.PurposeManifest, tombstoneData(ts)); err != nil {
		return false, err
	}
	return true, tx.Q.InsertTombstone(ctx, db.InsertTombstoneParams(ts))
}

// ReadPage returns decrypted records of one segment for replay (≤ 256 KiB per page). Callers must authorize
// recording.play and audit the access (HP-REC-014). The file is opened at its canonical location only and must carry
// the header registered for the segment.
func (svc *Service) ReadPage(ctx context.Context, segmentID string, fromSeq uint64, maxBytes int) (hprec.Page, error) {
	seg, err := svc.s.R().GetSegment(ctx, segmentID)
	if err != nil {
		return hprec.Page{}, err
	}
	path, err := svc.SegmentFile(seg)
	if err != nil {
		return hprec.Page{}, err
	}
	if seg.State == "open" {
		path += hprec.PartialSuffix
	}
	return hprec.ReadPage(path, svc.wrapper, fromSeq, maxBytes, expectations(seg)...)
}
