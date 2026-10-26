package recording

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// finishedSegments records n finalized single-segment channels in the fixture's session and returns their rows in
// chain order.
func (f *fx) finishedSegments(svc *Service, n int) []db.RecordingSegment {
	f.t.Helper()
	var ids []string
	for i := range n {
		reg := f.channel(access.KindExec)
		rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
		must(f.t, err)
		must(f.t, rec.Output(sshproxy.StreamStdout, []byte(strings.Repeat("x", 100+i))))
		ids = append(ids, rec.SegmentID())
		must(f.t, rec.Finalize("exit_status"))
		must(f.t, f.access.CloseChannel(f.ctx, reg, access.CloseInfo{Reason: "exit_status"}))
	}
	out := make([]db.RecordingSegment, 0, n)
	for _, id := range ids {
		seg, err := f.s.R().GetSegment(f.ctx, id)
		must(f.t, err)
		out = append(out, seg)
	}
	return out
}

func (f *fx) exec(q string, args ...any) {
	f.t.Helper()
	must(f.t, f.s.W().Exec(f.ctx, q, args...))
}

func statusOf(vr *VerifyResult, segID string) (string, string) {
	for _, s := range vr.Segments {
		if s.SegmentID == segID {
			return s.Status, s.Problem
		}
	}
	return "", ""
}

// closeSession ends the fixture's grant, connection and session so retention applies to it.
func (f *fx) closeSession() {
	f.t.Helper()
	_, err := f.access.RevokeGrant(f.ctx, f.adminOp, f.grant.ID, "done")
	must(f.t, err)
	must(f.t, f.access.CloseConnection(f.ctx, f.conn, "client_closed"))
	_, err = f.access.CloseFinishedSessions(f.ctx)
	must(f.t, err)
}

// SR-02 (HP-CRY-005, G-9, T-15): a party without keys who can write the database and the segment files cannot hide,
// remove or truncate a finalized segment and still have `hallpass verify` pass. Each attack is the one from the
// security review's probe, plus removal of the newest chain entry and of a segment row.
func TestVerifyDetectsKeylessHiding(t *testing.T) {
	setup := func(t *testing.T) (*fx, *Service, []db.RecordingSegment) {
		f := newFx(t)
		svc := f.service(Options{})
		segs := f.finishedSegments(svc, 3)
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if !vr.OK {
			t.Fatalf("baseline: %+v", vr)
		}
		return f, svc, segs
	}
	t.Run("truncated and relabeled interrupted", func(t *testing.T) {
		f, svc, segs := setup(t)
		seg := segs[0]
		b, err := os.ReadFile(seg.Path)
		must(t, err)
		framesAt := 12 + int64(binary.BigEndian.Uint32(b[8:12])) + 2*hprec.SlotSize
		must(t, os.Truncate(seg.Path, framesAt))
		empty := sha256.Sum256(nil)
		f.exec(`UPDATE recording_segments SET state = 'interrupted', ciphertext_sha256 = ?, frames = 0, records = 0, first_seq = 0,
			last_seq = 0, bytes = ? WHERE id = ?`, empty[:], framesAt, seg.ID)
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if st, p := statusOf(vr, seg.ID); vr.OK || st != "corrupt" || !strings.Contains(p, "chain") {
			t.Fatalf("truncation hidden: status %q (%s) ok=%v", st, p, vr.OK)
		}
	})
	t.Run("removed and relabeled failed", func(t *testing.T) {
		f, svc, segs := setup(t)
		must(t, os.Remove(segs[1].Path))
		f.exec(`UPDATE recording_segments SET state = 'failed' WHERE id = ?`, segs[1].ID)
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if st, _ := statusOf(vr, segs[1].ID); vr.OK || st != "corrupt" {
			t.Fatalf("removal hidden: status %q ok=%v", st, vr.OK)
		}
	})
	t.Run("removed and relabeled deleted", func(t *testing.T) {
		f, svc, segs := setup(t)
		must(t, os.Remove(segs[2].Path))
		f.exec(`UPDATE recording_segments SET state = 'deleted' WHERE id = ?`, segs[2].ID)
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if st, p := statusOf(vr, segs[2].ID); vr.OK || st != "corrupt" || !strings.Contains(p, "tombstone") {
			t.Fatalf("deletion without retention hidden: status %q (%s) ok=%v", st, p, vr.OK)
		}
	})
	t.Run("newest chain entry removed", func(t *testing.T) {
		f, svc, segs := setup(t)
		last := segs[2]
		must(t, os.Remove(last.Path))
		f.exec(`DELETE FROM integrity_chain WHERE segment_id = ?`, last.ID)
		f.exec(`UPDATE recording_segments SET state = 'failed', ciphertext_sha256 = NULL, frames = NULL, records = NULL, bytes = NULL,
			first_seq = NULL, last_seq = NULL, finalized_at = NULL WHERE id = ?`, last.ID)
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if vr.OK || vr.ChainOK || !strings.Contains(vr.Problem, "head") {
			t.Fatalf("tail truncation hidden: %+v", vr)
		}
	})
	t.Run("segment row removed", func(t *testing.T) {
		f, svc, segs := setup(t)
		must(t, os.Remove(segs[1].Path))
		f.exec(`DELETE FROM recording_segments WHERE id = ?`, segs[1].ID)
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if st, p := statusOf(vr, segs[1].ID); vr.OK || st != "missing" || !strings.Contains(p, "chain") {
			t.Fatalf("row removal hidden: status %q (%s) ok=%v", st, p, vr.OK)
		}
	})
	t.Run("chained segment relabeled open", func(t *testing.T) {
		f, svc, segs := setup(t)
		f.exec(`UPDATE recording_segments SET state = 'open' WHERE id = ?`, segs[0].ID)
		// Startup reconciliation must not fail on (or re-chain) an open row that already has a chain entry.
		if _, err := svc.ReconcileStartup(f.ctx); err != nil {
			t.Fatal(err)
		}
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if st, _ := statusOf(vr, segs[0].ID); vr.OK || st != "corrupt" {
			t.Fatalf("relabel hidden: status %q ok=%v", st, vr.OK)
		}
	})
}

// SR-17 (HP-REC-013, PLAN §13.9): retention deletion writes an audit event and an authenticated tombstone in the
// same transaction, and verify accepts a deleted segment only with such a tombstone.
func TestRetentionAuditedTombstone(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	segs := f.finishedSegments(svc, 2)
	f.closeSession()
	f.clk.Advance(25 * time.Hour)
	n, err := svc.ApplyRetention(f.ctx, func(string) time.Duration { return 24 * time.Hour })
	must(t, err)
	if n != 2 {
		t.Fatalf("deleted %d", n)
	}
	var audited int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'recording.deleted' AND target_id IN (?, ?)`,
		segs[0].ID, segs[1].ID).Scan(&audited))
	if audited != 2 {
		t.Fatalf("retention deletions audited: %d", audited)
	}
	vr, err := svc.Verify(f.ctx, "")
	must(t, err)
	if !vr.OK {
		t.Fatalf("legitimate retention fails verification: %+v", vr)
	}
	if st, _ := statusOf(vr, segs[0].ID); st != "skipped" {
		t.Fatalf("deleted segment status %q", st)
	}
	// A tombstone edited without the manifest key no longer authenticates.
	f.exec(`UPDATE recording_tombstones SET delete_after = delete_after - 1 WHERE segment_id = ?`, segs[0].ID)
	vr, err = svc.Verify(f.ctx, "")
	must(t, err)
	if st, p := statusOf(vr, segs[0].ID); vr.OK || st != "corrupt" || !strings.Contains(p, "tombstone") {
		t.Fatalf("forged tombstone accepted: %q (%s)", st, p)
	}
	// Removing the tombstone is detected too.
	f.exec(`DELETE FROM recording_tombstones WHERE segment_id = ?`, segs[1].ID)
	vr, err = svc.Verify(f.ctx, "")
	must(t, err)
	if st, _ := statusOf(vr, segs[1].ID); st != "corrupt" {
		t.Fatalf("missing tombstone accepted: %q", st)
	}
}

// SR-16 (HP-REC-013, HP-OPS-004): segment paths stored in the database are never used for file I/O. Retention and
// replay act only on the canonical location derived from the validated IDs, and verify reports a stored path that is
// not that location.
func TestSegmentPathsConfined(t *testing.T) {
	setup := func(t *testing.T) (*fx, *Service, db.RecordingSegment, string) {
		f := newFx(t)
		svc := f.service(Options{})
		seg := f.finishedSegments(svc, 1)[0]
		victim := filepath.Join(t.TempDir(), "victim")
		must(t, os.WriteFile(victim, []byte("not a recording"), 0o600))
		f.exec(`UPDATE recording_segments SET path = ? WHERE id = ?`, victim, seg.ID)
		return f, svc, seg, victim
	}
	t.Run("retention", func(t *testing.T) {
		f, svc, seg, victim := setup(t)
		f.closeSession()
		f.clk.Advance(25 * time.Hour)
		if _, err := svc.ApplyRetention(f.ctx, func(string) time.Duration { return 24 * time.Hour }); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(victim); err != nil {
			t.Fatalf("retention deleted a file outside the recordings directory: %v", err)
		}
		if exists(svc.segmentPath(seg.AccessSessionID, seg.ID)) {
			t.Fatal("retention left the canonical segment file")
		}
	})
	t.Run("replay and verify", func(t *testing.T) {
		f, svc, seg, _ := setup(t)
		// Replay reads the canonical file, not the stored path.
		if recs := f.replay(svc, seg.ID); len(recs) != 1 {
			t.Fatalf("replay through tampered path: %+v", recs)
		}
		vr, err := svc.Verify(f.ctx, "")
		must(t, err)
		if st, p := statusOf(vr, seg.ID); vr.OK || st != "corrupt" || !strings.Contains(p, "path") {
			t.Fatalf("tampered path not reported: %q (%s)", st, p)
		}
	})
}

// SR-38 (PLAN §13.6 step 2b, HP-REC-009): a final .hprec file whose row is still open and that does not verify
// (tampered or damaged after the rename) is quarantined, its segment marked failed, and it is never chained.
func TestReconcileQuarantinesTamperedFinalFile(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{Durability: "strict"})
	reg := f.channel(access.KindExec)
	r, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	rec := r.(*channelRecorder)
	must(t, rec.Output(sshproxy.StreamStdout, []byte("line one\n")))
	halt(rec)
	_, err = rec.w.Finalize("exit_status") // crash after the rename, before the DB commit
	must(t, err)
	path := svc.segmentPath(reg.SessionID, rec.segID)
	b, err := os.ReadFile(path)
	must(t, err)
	b[len(b)-3] ^= 0x01
	must(t, os.WriteFile(path, b, 0o600))

	res, err := svc.ReconcileStartup(f.ctx)
	must(t, err)
	if res.Failed != 1 || res.Interrupted != 0 || res.Finalized != 0 {
		t.Fatalf("tampered final file reconciled as %+v", res)
	}
	seg, err := f.s.R().GetSegment(f.ctx, rec.segID)
	must(t, err)
	if seg.State != "failed" || exists(path) {
		t.Fatalf("segment %s, file still in place: %v", seg.State, exists(path))
	}
	var chained, quarantined int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM integrity_chain WHERE segment_id = ?`, rec.segID).Scan(&chained))
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM quarantine_files WHERE original_path = ?`, path).Scan(&quarantined))
	if chained != 0 || quarantined != 1 {
		t.Fatalf("chained=%d quarantined=%d", chained, quarantined)
	}
	q, _ := os.ReadDir(f.s.Path(store.QuarantineDir))
	if len(q) != 1 {
		t.Fatalf("quarantine dir: %v", q)
	}
}

// SR-39 (HP-CRY-002, PLAN §13.4): neither key slot unwraps but the database copy of the wrapped DEK does; startup
// repairs the slot so the segment is readable again.
func TestReconcileRepairsKeySlots(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	seg := f.finishedSegments(svc, 1)[0]
	b, err := os.ReadFile(seg.Path)
	must(t, err)
	slots := 12 + int(binary.BigEndian.Uint32(b[8:12]))
	for i := slots; i < slots+2*hprec.SlotSize; i++ {
		b[i] = 0xa5
	}
	must(t, os.WriteFile(seg.Path, b, 0o600))
	if _, err := svc.ReadPage(f.ctx, seg.ID, 0, 1<<16); err == nil {
		t.Fatal("damaged slots still unwrap")
	}
	res, err := svc.ReconcileStartup(f.ctx)
	must(t, err)
	if res.SlotsRepaired != 1 || res.SlotsFilled != 0 {
		t.Fatalf("damaged slots counted as %+v", res)
	}
	if recs := f.replay(svc, seg.ID); len(recs) != 1 {
		t.Fatalf("after repair: %+v", recs)
	}
}

// A healthy new segment's empty slot B is filled on the next start; that is counted as routine (SlotsFilled), not
// as a repair, so an upgrade does not warn about every recent recording.
func TestReconcileFillsEmptySlotsQuietly(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	f.finishedSegments(svc, 2)
	res, err := svc.ReconcileStartup(f.ctx)
	must(t, err)
	if res.SlotsFilled != 2 || res.SlotsRepaired != 0 || res.SlotProblems != 0 {
		t.Fatalf("first start: %+v", res)
	}
	if res, err = svc.ReconcileStartup(f.ctx); err != nil || res.SlotsFilled != 0 || res.SlotsRepaired != 0 {
		t.Fatalf("second start: %+v %v", res, err)
	}
}

// SR-02: once the head record is missing (or stale), new recordings do not silently re-create it; only an explicit,
// audited adoption after a full chain check does.
func TestChainHeadAdoption(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	f.finishedSegments(svc, 2)
	f.exec(`DELETE FROM recording_chain_head`)
	f.finishedSegments(svc, 1)
	vr, err := svc.Verify(f.ctx, "")
	must(t, err)
	if vr.OK || !strings.Contains(vr.Problem, "head record is missing") {
		t.Fatalf("missing head not reported: %+v", vr)
	}
	seq, hash, err := svc.AdoptChainHead(f.ctx, admin)
	must(t, err)
	if seq != 3 || len(hash) != 32 {
		t.Fatalf("adopted %d %x", seq, hash)
	}
	vr, err = svc.Verify(f.ctx, "")
	must(t, err)
	if !vr.OK {
		t.Fatalf("after adoption: %+v", vr)
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'recording.chain_head_adopted'`).Scan(&n))
	if n != 1 {
		t.Fatalf("adoption audited %d times", n)
	}
	// The head record moves with new entries again.
	f.finishedSegments(svc, 1)
	if vr, err = svc.Verify(f.ctx, ""); err != nil || !vr.OK {
		t.Fatalf("after another recording: %v %+v", err, vr)
	}
	// A modified head record is reported, and adoption refuses a broken chain.
	f.exec(`UPDATE recording_chain_head SET mac = zeroblob(32)`)
	if vr, _ = svc.Verify(f.ctx, ""); vr.OK || !strings.Contains(vr.Problem, "does not authenticate") {
		t.Fatalf("forged head accepted: %+v", vr)
	}
	f.exec(`UPDATE integrity_chain SET mac = zeroblob(32) WHERE seq = 1`)
	if _, _, err := svc.AdoptChainHead(f.ctx, admin); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("adopted a broken chain: %v", err)
	}
	f.exec(`DELETE FROM integrity_chain`)
	if _, _, err := svc.AdoptChainHead(f.ctx, admin); err == nil {
		t.Fatal("adopted an empty chain")
	}
}

// SR-39 (HP-CRY-002, PLAN §13.1/§13.4): after a recording-key rotation the background job rewraps every segment DEK
// (file slot and database copy), the old version can be retired, and a file whose slots only hold the retired key is
// repaired from the rewrapped database copy at startup.
func TestRewrapAfterRecordingKeyRotation(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	segs := f.finishedSegments(svc, 2)
	kept, gone := segs[0], segs[1]
	saved, err := os.ReadFile(gone.Path)
	must(t, err)
	must(t, os.Remove(gone.Path)) // no file: only the database copy can be rewrapped

	if n, err := svc.RewrapSegments(f.ctx, 10); err != nil || n != 0 {
		t.Fatalf("rewrap before rotation: %d %v", n, err)
	}
	_, err = f.kr.Rotate(f.ctx, f.s, keyring.PurposeRecording)
	must(t, err)
	n, err := svc.RewrapSegments(f.ctx, 1) // batch 1: pagination covers both
	must(t, err)
	if n != 2 {
		t.Fatalf("rewrapped %d segments", n)
	}
	var stale int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT count(*) FROM recording_segments WHERE key_id = 'recording:v1' AND state != 'deleted'`).Scan(&stale))
	if stale != 0 {
		t.Fatalf("%d segments still on recording v1", stale)
	}
	if n, err := svc.RewrapSegments(f.ctx, 10); err != nil || n != 0 {
		t.Fatalf("second run: %d %v", n, err)
	}
	must(t, f.kr.Retire(f.ctx, f.s, keyring.PurposeRecording, 1))
	if recs := f.replay(svc, kept.ID); len(recs) != 1 {
		t.Fatalf("replay after retirement: %+v", recs)
	}
	rep, err := hprec.Verify(kept.Path, svc.Wrapper())
	must(t, err)
	if rep.Status != hprec.StatusOK || rep.Slots[rep.ActiveSlot].KeyID != "recording:v2" {
		t.Fatalf("slots after rewrap: %+v", rep.Slots)
	}

	// The file comes back with only the retired key in its slots; startup repairs it from the database copy.
	must(t, os.WriteFile(gone.Path, saved, 0o600))
	if _, err := svc.ReadPage(f.ctx, gone.ID, 0, 1<<16); err == nil {
		t.Fatal("slot under a retired key still unwraps")
	}
	res, err := svc.ReconcileStartup(f.ctx)
	must(t, err)
	// Both: the returned file, and the stale retired-key slot of the other segment (refreshed from the copy).
	if res.SlotsRepaired != 2 || res.SlotProblems != 0 {
		t.Fatalf("%+v", res)
	}
	// The returned file's empty slot B was written first; its stale slot A is refreshed on the next start, after
	// which both slots of both files unwrap and nothing is written any more.
	if res, err = svc.ReconcileStartup(f.ctx); err != nil || res.SlotsRepaired != 1 {
		t.Fatalf("second start: %+v %v", res, err)
	}
	if res, err = svc.ReconcileStartup(f.ctx); err != nil || res.SlotsRepaired != 0 {
		t.Fatalf("repair does not converge: %+v %v", res, err)
	}
	if recs := f.replay(svc, gone.ID); len(recs) != 1 {
		t.Fatalf("replay after repair: %+v", recs)
	}
	if vr, err := svc.Verify(f.ctx, ""); err != nil || !vr.OK {
		t.Fatalf("verify: %v %+v", err, vr)
	}
}

// SR-17: every field of a retention tombstone is checked. Each case re-MACs the edited tombstone with the manifest
// key (as only a key holder could), so the consistency checks behind the MAC are exercised too.
func TestTombstoneConsistencyChecks(t *testing.T) {
	cases := []struct {
		name, want string
		edit       func(f *fx, ts *db.RecordingTombstone)
	}{
		{"other session", "another session", func(_ *fx, ts *db.RecordingTombstone) { ts.AccessSessionID = "ses_other" }},
		{"deleted early", "before the retention time", func(_ *fx, ts *db.RecordingTombstone) { ts.DeletedAt = ts.DeleteAfter }},
		{"wrong chain entry", "integrity-chain entry", func(_ *fx, ts *db.RecordingTombstone) { ts.ChainSeq++ }},
		{"claims unchained", "prior state", func(_ *fx, ts *db.RecordingTombstone) { ts.PriorState, ts.ChainSeq = "failed", 0 }},
		{"audit event missing", "audit event", func(f *fx, ts *db.RecordingTombstone) {
			f.exec(`UPDATE audit_events SET action = 'x' WHERE id = ?`, ts.AuditEventID)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFx(t)
			svc := f.service(Options{})
			seg := f.finishedSegments(svc, 1)[0]
			f.closeSession()
			f.clk.Advance(25 * time.Hour)
			_, err := svc.ApplyRetention(f.ctx, func(string) time.Duration { return 24 * time.Hour })
			must(t, err)
			if vr, err := svc.Verify(f.ctx, seg.AccessSessionID); err != nil || !vr.OK {
				t.Fatalf("baseline: %v %+v", err, vr)
			}
			ts, err := f.s.R().GetTombstone(f.ctx, seg.ID)
			must(t, err)
			c.edit(f, &ts)
			ts.Mac, err = f.kr.MAC(keyring.PurposeManifest, tombstoneData(ts))
			must(t, err)
			f.exec(`UPDATE recording_tombstones SET access_session_id = ?, prior_state = ?, chain_seq = ?, delete_after = ?, deleted_at = ?, mac = ?
				WHERE segment_id = ?`, ts.AccessSessionID, ts.PriorState, ts.ChainSeq, ts.DeleteAfter, ts.DeletedAt, ts.Mac, seg.ID)
			vr, err := svc.Verify(f.ctx, seg.AccessSessionID)
			must(t, err)
			if st, p := statusOf(vr, seg.ID); vr.OK || st != "corrupt" || !strings.Contains(p, c.want) {
				t.Fatalf("status %q (%s), want problem %q", st, p, c.want)
			}
		})
	}
}

// SR-39: a failed segment keeps its partial file; the rewrap job moves that file's key slot too, and open segments
// wait until they are finalized.
func TestRewrapFailedAndOpenSegments(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{Durability: "strict"})
	reg := f.channel(access.KindExec)
	rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	must(t, rec.Output(sshproxy.StreamStdout, []byte("before failure")))
	failedID := rec.SegmentID()
	rec.Abort(errors.New("injected"))
	open, err := svc.Open(f.ctx, f.channel(access.KindExec), access.KindExec, false)
	must(t, err)
	must(t, open.Output(sshproxy.StreamStdout, []byte("still writing")))

	_, err = f.kr.Rotate(f.ctx, f.s, keyring.PurposeRecording)
	must(t, err)
	n, err := svc.RewrapSegments(f.ctx, 0)
	must(t, err)
	if n != 1 {
		t.Fatalf("rewrapped %d, want only the failed segment", n)
	}
	seg, err := f.s.R().GetSegment(f.ctx, failedID)
	must(t, err)
	rep, err := hprec.Verify(svc.segmentPath(seg.AccessSessionID, seg.ID)+hprec.PartialSuffix, svc.Wrapper())
	must(t, err)
	if seg.State != "failed" || seg.KeyID != "recording:v2" || rep.ActiveSlot < 0 || rep.Slots[rep.ActiveSlot].KeyID != "recording:v2" {
		t.Fatalf("failed segment not rewrapped: %s %s %+v", seg.State, seg.KeyID, rep.Slots)
	}
	must(t, open.Finalize("exit_status"))
	if n, err := svc.RewrapSegments(f.ctx, 0); err != nil || n != 1 {
		t.Fatalf("after finalize: %d %v", n, err)
	}
}
