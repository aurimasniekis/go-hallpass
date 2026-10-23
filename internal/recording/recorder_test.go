package recording

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

func (f *fx) segments(sessionID string) []db.RecordingSegment {
	f.t.Helper()
	segs, err := f.s.R().SegmentsForSession(f.ctx, sessionID)
	must(f.t, err)
	return segs
}

func (f *fx) replay(svc *Service, segID string) []hprec.Record {
	f.t.Helper()
	var out []hprec.Record
	var from uint64
	for {
		p, err := svc.ReadPage(f.ctx, segID, from, 256<<10)
		must(f.t, err)
		out = append(out, p.Records...)
		if !p.More {
			return out
		}
		from = p.NextSeq
	}
}

// HP-REC-001/007/008: a channel recording round-trips, is finalized with a manifest and verifies.
func TestRecorderRoundTrip(t *testing.T) {
	for _, mode := range []string{"group", "strict"} {
		t.Run(mode, func(t *testing.T) {
			f := newFx(t)
			svc := f.service(Options{Durability: mode})
			reg := f.channel(access.KindExec)
			rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
			must(t, err)
			segs := f.segments(reg.SessionID)
			if len(segs) != 1 || segs[0].State != "open" || !exists(segs[0].Path+hprec.PartialSuffix) {
				t.Fatalf("segment not established before forwarding: %+v", segs)
			}
			must(t, rec.ExecRequested("uptime"))
			must(t, rec.Output(sshproxy.StreamStdout, []byte("up 3 days\n")))
			must(t, rec.Output(sshproxy.StreamStderr, []byte("warn\n")))
			must(t, rec.Input([]byte("secret")))
			status := 0
			must(t, rec.Exit(&status, ""))
			must(t, rec.Finalize("exit_status"))

			segs = f.segments(reg.SessionID)
			if segs[0].State != "finalized" || segs[0].Records.Int64 != 4 || len(segs[0].CiphertextSha256) != 32 {
				t.Fatalf("not finalized: %+v", segs[0])
			}
			recs := f.replay(svc, segs[0].ID)
			if len(recs) != 4 || string(recs[0].Payload) != "uptime" || string(recs[1].Payload) != "up 3 days\n" || recs[2].Stream != hprec.StreamStderr {
				t.Fatalf("replay mismatch: %+v", recs)
			}
			for i := 1; i < len(recs); i++ {
				if recs[i].Seq <= recs[i-1].Seq {
					t.Fatal("sequence not monotonic")
				}
			}
			vr, err := svc.Verify(f.ctx, "")
			must(t, err)
			if !vr.OK || !vr.ChainOK || vr.ChainLen != 1 || vr.Segments[0].Status != "ok" {
				t.Fatalf("verify: %+v", vr)
			}
		})
	}
}

// HP-REC-004: terminal input is not recorded unless the role enables it.
func TestRecorderInputOptIn(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	reg := f.channel(access.KindShell)
	reg.Role.RecordInput = true
	rec, err := svc.Open(f.ctx, reg, access.KindShell, true)
	must(t, err)
	must(t, rec.PTY(&sshproxy.PTYRequest{Term: "xterm", Cols: 80, Rows: 24}))
	must(t, rec.Input([]byte("ls\r")))
	must(t, rec.Output(sshproxy.StreamPTY, []byte("a b\r\n")))
	must(t, rec.Resize(100, 30))
	must(t, rec.Signal("INT"))
	must(t, rec.Notice("grant expired"))
	must(t, rec.Finalize("closed"))
	recs := f.replay(svc, f.segments(reg.SessionID)[0].ID)
	types := []hprec.RecordType{}
	for _, r := range recs {
		types = append(types, r.Type)
	}
	want := []hprec.RecordType{hprec.RecPTYRequested, hprec.RecTerminalInput, hprec.RecTerminalOutput, hprec.RecTerminalResized, hprec.RecSignal, hprec.RecGatewayNotice}
	if len(types) != len(want) {
		t.Fatalf("types %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("types %v want %v", types, want)
		}
	}
}

// HP-REC-005: segments roll over at the size bound and chain to their predecessor.
func TestRecorderRollover(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{SegmentMaxBytes: 8 << 10})
	reg := f.channel(access.KindExec)
	rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	chunk := bytes.Repeat([]byte("x"), 3000)
	for range 10 {
		must(t, rec.Output(sshproxy.StreamStdout, chunk))
	}
	must(t, rec.Finalize("exit_status"))
	segs := f.segments(reg.SessionID)
	if len(segs) < 3 {
		t.Fatalf("expected rollover, got %d segments", len(segs))
	}
	total := 0
	for i, s := range segs {
		if s.State != "finalized" || s.Ordinal != int64(i) {
			t.Fatalf("segment %d: %+v", i, s)
		}
		for _, r := range f.replay(svc, s.ID) {
			total += len(r.Payload)
		}
	}
	if total != 10*len(chunk) {
		t.Fatalf("payload bytes %d", total)
	}
	vr, err := svc.Verify(f.ctx, reg.SessionID)
	must(t, err)
	if !vr.OK || vr.ChainLen != int64(len(segs)) {
		t.Fatalf("verify %+v", vr)
	}
}

// Oversized writes are split, never truncated.
func TestRecorderSplitsLargeWrites(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	reg := f.channel(access.KindExec)
	rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	big := bytes.Repeat([]byte("y"), 3*hprec.MaxRecordPayload+17)
	must(t, rec.Output(sshproxy.StreamStdout, big))
	must(t, rec.Finalize("exit_status"))
	var got []byte
	for _, r := range f.replay(svc, f.segments(reg.SessionID)[0].ID) {
		got = append(got, r.Payload...)
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("got %d bytes", len(got))
	}
}

// HP-REC-010: a recording failure fails closed: further writes error and the segment is marked failed.
func TestRecorderFailureFailsClosed(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	reg := f.channel(access.KindExec)
	r, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	rec := r.(*channelRecorder)
	must(t, rec.Output(sshproxy.StreamStdout, []byte("before")))
	rec.Abort(errors.New("disk full"))
	if err := rec.Output(sshproxy.StreamStdout, []byte("after")); err == nil {
		t.Fatal("write after failure accepted")
	}
	if s := f.segments(reg.SessionID)[0]; s.State != "failed" {
		t.Fatalf("state %s", s.State)
	}
	if err := rec.Finalize("again"); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}

// HP-REC-011: a stalled writer blocks producers (backpressure) and then fails instead of dropping data.
func TestRecorderBackpressure(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{QueueBytes: 2048, QueueRecords: 2, BlockTimeout: 150 * time.Millisecond})
	reg := f.channel(access.KindExec)
	r, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	rec := r.(*channelRecorder)
	// Occupy every queue token, as a writer stuck on slow storage would.
	for range cap(rec.bytes) {
		rec.bytes <- struct{}{}
	}
	start := time.Now()
	err = rec.Output(sshproxy.StreamStdout, []byte("blocked"))
	if err == nil || !strings.Contains(err.Error(), "stalled") || time.Since(start) < 100*time.Millisecond {
		t.Fatalf("expected stall after blocking, got %v after %v", err, time.Since(start))
	}
	if err := rec.Output(sshproxy.StreamStdout, []byte("x")); err == nil {
		t.Fatal("recorder accepted data after a stall")
	}
	for range cap(rec.bytes) {
		<-rec.bytes
	}
	_ = rec.Finalize("failed")
	if s := f.segments(reg.SessionID)[0]; s.State != "failed" {
		t.Fatalf("state %s", s.State)
	}
}

// HP-CRY-005: tampering with a finalized segment or the integrity chain is detected.
func TestVerifyDetectsTampering(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	for range 2 {
		reg := f.channel(access.KindExec)
		rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
		must(t, err)
		must(t, rec.Output(sshproxy.StreamStdout, []byte("hello world")))
		must(t, rec.Finalize("exit_status"))
	}
	segs := f.segments(f.grant.SessionID)
	data, err := os.ReadFile(segs[0].Path)
	must(t, err)
	data[len(data)-5] ^= 0xff
	must(t, os.WriteFile(segs[0].Path, data, 0o600))
	vr, err := svc.Verify(f.ctx, "")
	must(t, err)
	if vr.OK {
		t.Fatal("tampered segment verified")
	}
	bad := 0
	for _, s := range vr.Segments {
		if s.Status == "corrupt" {
			bad++
		}
	}
	if bad != 1 || !vr.ChainOK {
		t.Fatalf("%+v", vr)
	}

	// Tamper with a chain MAC.
	must(t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(f.ctx, `UPDATE integrity_chain SET mac = zeroblob(32) WHERE seq = 2`)
		return err
	}))
	vr, err = svc.Verify(f.ctx, "")
	must(t, err)
	if vr.ChainOK || !strings.Contains(vr.Problem, "MAC") {
		t.Fatalf("chain tamper missed: %+v", vr)
	}
	// Deleting a chain entry breaks the sequence.
	must(t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(f.ctx, `DELETE FROM integrity_chain WHERE seq = 1`)
		return err
	}))
	vr, _ = svc.Verify(f.ctx, "")
	if vr.ChainOK {
		t.Fatal("chain deletion missed")
	}
	if seq, head, err := svc.ChainHead(f.ctx); err != nil || seq != 2 || len(head) != 32 {
		t.Fatalf("head %d %x %v", seq, head, err)
	}
}

// HP-REC-009, PLAN §13.6: crash reconciliation recovers partial segments, finalizes completed ones, flags missing
// files and quarantines orphans.
func TestReconcileStartup(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{Durability: "strict"})

	open := func() (*access.ChannelReg, *channelRecorder) {
		reg := f.channel(access.KindExec)
		r, err := svc.Open(f.ctx, reg, access.KindExec, false)
		must(t, err)
		rec := r.(*channelRecorder)
		must(t, rec.Output(sshproxy.StreamStdout, []byte("line one\n")))
		must(t, rec.Output(sshproxy.StreamStdout, []byte("line two\n")))
		return reg, rec
	}
	// crash simulates a process death: the writer stops without finalizing.
	crash := func(rec *channelRecorder) {
		rec.mu.Lock()
		rec.closed = true
		rec.mu.Unlock()
		_ = rec.w.Close()
	}

	// 1. interrupted: partial file with a valid prefix plus garbage.
	_, rec1 := open()
	crash(rec1)
	p1 := rec1.partialPath()
	fh, err := os.OpenFile(p1, os.O_APPEND|os.O_WRONLY, 0)
	must(t, err)
	_, _ = fh.Write([]byte("torn frame garbage"))
	must(t, fh.Close())

	// 2. finalized on disk, DB not updated.
	_, rec2 := open()
	_, err = rec2.w.Finalize("exit_status")
	must(t, err)

	// 3. missing file.
	_, rec3 := open()
	crash(rec3)
	must(t, os.Remove(rec3.partialPath()))

	// 4. orphan file.
	orphan := filepath.Join(f.s.Path(store.RecordingsDir), "zz", "stray.hprec")
	must(t, os.MkdirAll(filepath.Dir(orphan), 0o700))
	must(t, os.WriteFile(orphan, []byte("stray"), 0o600))

	res, err := svc.ReconcileStartup(f.ctx)
	must(t, err)
	if res.Interrupted != 1 || res.Finalized != 1 || res.Missing != 1 || res.Orphans != 1 {
		t.Fatalf("%+v", res)
	}
	states := map[string]string{}
	for _, s := range f.segments(f.grant.SessionID) {
		states[s.ID] = s.State
	}
	if states[rec1.segID] != "interrupted" || states[rec2.segID] != "finalized" || states[rec3.segID] != "missing" {
		t.Fatalf("%v", states)
	}
	recs := f.replay(svc, rec1.segID)
	if len(recs) != 2 || string(recs[1].Payload) != "line two\n" {
		t.Fatalf("recovered prefix: %+v", recs)
	}
	if exists(orphan) {
		t.Fatal("orphan not quarantined")
	}
	q, _ := os.ReadDir(f.s.Path(store.QuarantineDir))
	if len(q) != 2 { // the torn original and the orphan
		t.Fatalf("quarantine: %v", q)
	}
	vr, err := svc.Verify(f.ctx, "")
	must(t, err)
	if !vr.ChainOK || vr.ChainLen != 2 || vr.OK { // missing makes the run not OK
		t.Fatalf("%+v", vr)
	}
	// Idempotent.
	res, err = svc.ReconcileStartup(f.ctx)
	must(t, err)
	if *res != (ReconcileResult{}) {
		t.Fatalf("second run %+v", res)
	}
}

// HP-REC-013: retention deletes recordings of closed sessions and keeps tombstones.
func TestRetention(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	reg := f.channel(access.KindExec)
	rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	must(t, rec.Output(sshproxy.StreamStdout, []byte("x")))
	must(t, rec.Finalize("exit_status"))
	must(t, f.access.CloseChannel(f.ctx, reg, access.CloseInfo{Reason: "exit_status"}))

	n, err := svc.ApplyRetention(f.ctx, 24*time.Hour)
	must(t, err)
	if n != 0 {
		t.Fatal("deleted an active session's recording")
	}
	_, err = f.access.RevokeGrant(f.ctx, policy.OperatorInfo{ID: "opr_admin", Roles: []string{"administrator"}, Enabled: true}, f.grant.ID, "done")
	must(t, err)
	must(t, f.access.CloseConnection(f.ctx, f.conn, "client_closed"))
	_, err = f.access.CloseFinishedSessions(f.ctx)
	must(t, err)
	n, err = svc.ApplyRetention(f.ctx, 24*time.Hour)
	must(t, err)
	if n != 0 {
		t.Fatal("deleted before retention elapsed")
	}
	f.clk.Advance(25 * time.Hour)
	n, err = svc.ApplyRetention(f.ctx, 24*time.Hour)
	must(t, err)
	seg := f.segments(reg.SessionID)[0]
	if n != 1 || seg.State != "deleted" || exists(seg.Path) {
		t.Fatalf("n=%d %+v", n, seg)
	}
}

func (r *channelRecorder) partialPath() string {
	return r.svc.segmentPath(r.reg.SessionID, r.segID) + hprec.PartialSuffix
}

// HP-REC-014: an open segment can be replayed live (authentic prefix) and the segment rolls over by age.
func TestRecorderLiveReplayAndAgeRollover(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{Durability: "strict", SegmentMaxAge: time.Minute})
	if seq, head, err := svc.ChainHead(f.ctx); err != nil || seq != 0 || head != nil {
		t.Fatalf("empty chain head: %d %x %v", seq, head, err)
	}
	reg := f.channel(access.KindExec)
	rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	first := rec.SegmentID()
	must(t, rec.Output(sshproxy.StreamStdout, []byte("live")))
	must(t, rec.EOF(sshproxy.StreamStdout))
	p, err := svc.ReadPage(f.ctx, first, 0, 1<<16)
	must(t, err)
	if len(p.Records) != 2 || !p.Incomplete || string(p.Records[0].Payload) != "live" {
		t.Fatalf("live page %+v", p)
	}
	f.clk.Advance(2 * time.Minute)
	must(t, rec.Output(sshproxy.StreamStdout, []byte("later")))
	if rec.SegmentID() == first {
		t.Fatal("no age rollover")
	}
	must(t, rec.Finalize("exit_status"))
	if svc.Wrapper() == nil {
		t.Fatal("wrapper")
	}
}

// PLAN §13.6: a partial file whose header is unusable is quarantined and its segment marked failed; a finalized
// segment whose file disappeared verifies as missing.
func TestReconcileUnrecoverableAndVerifyMissing(t *testing.T) {
	f := newFx(t)
	svc := f.service(Options{})
	reg := f.channel(access.KindExec)
	r, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	rec := r.(*channelRecorder)
	rec.mu.Lock()
	rec.closed = true
	rec.mu.Unlock()
	_ = rec.w.Close()
	must(t, os.WriteFile(rec.partialPath(), []byte("not a segment"), 0o600))

	reg2 := f.channel(access.KindExec)
	r2, err := svc.Open(f.ctx, reg2, access.KindExec, false)
	must(t, err)
	must(t, r2.Output(sshproxy.StreamStdout, []byte("x")))
	must(t, r2.Finalize("exit_status"))

	res, err := svc.ReconcileStartup(f.ctx)
	must(t, err)
	if res.Failed != 1 || exists(rec.partialPath()) {
		t.Fatalf("%+v", res)
	}
	seg2, err := f.s.R().GetSegment(f.ctx, r2.SegmentID())
	must(t, err)
	must(t, os.Remove(seg2.Path))
	vr, err := svc.Verify(f.ctx, reg.SessionID)
	must(t, err)
	statuses := map[string]string{}
	for _, s := range vr.Segments {
		statuses[s.SegmentID] = s.Status
	}
	if vr.OK || statuses[rec.segID] != "skipped" || statuses[r2.SegmentID()] != "missing" {
		t.Fatalf("%+v", vr)
	}
}

// Regression: stdout, stderr and stdin are recorded from different goroutines; sequence numbers must still reach the
// file in order (an out-of-order append used to fail the recording and terminate mandatory-recording sessions).
func TestRecorderConcurrentProducers(t *testing.T) {
	for _, mode := range []string{"group", "strict"} {
		t.Run(mode, func(t *testing.T) {
			f := newFx(t)
			svc := f.service(Options{Durability: mode})
			reg := f.channel(access.KindExec)
			reg.Role.RecordInput = true
			rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
			must(t, err)
			var wg sync.WaitGroup
			for _, w := range []func([]byte) error{
				func(b []byte) error { return rec.Output(sshproxy.StreamStdout, b) },
				func(b []byte) error { return rec.Output(sshproxy.StreamStderr, b) },
				rec.Input,
			} {
				wg.Go(func() {
					for range 200 {
						if err := w([]byte("chunk")); err != nil {
							t.Error(err)
							return
						}
					}
				})
			}
			wg.Wait()
			must(t, rec.Finalize("exit_status"))
			if n := len(f.replay(svc, rec.SegmentID())); n != 600 {
				t.Fatalf("records %d", n)
			}
		})
	}
}
