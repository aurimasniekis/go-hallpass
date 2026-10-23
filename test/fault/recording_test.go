//go:build fault

package fault

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/obs/health"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// streamExec makes the destination write 4 KiB chunks to stdout until the write fails or limit bytes were written
// (0: unlimited); written counts the bytes the destination managed to send.
func streamExec(w *world, limit int64, written *atomic.Int64) {
	w.dest.Exec = func(_ string, _ io.Reader, stdout, _ io.Writer) uint32 {
		chunk := []byte(strings.Repeat("0123456789abcdef", 256))
		for limit == 0 || written.Load() < limit {
			n, err := stdout.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return 1
			}
		}
		return 0
	}
}

func segmentRows(t testing.TB, d *sql.DB) map[string]string {
	t.Helper()
	rows, err := d.QueryContext(context.Background(), `SELECT id, state FROM recording_segments`)
	must(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, st string
		must(t, rows.Scan(&id, &st))
		out[id] = st
	}
	must(t, rows.Err())
	return out
}

// FI-05 (ENOSPC on segment write) and FI-07 (EIO on fsync): mandatory recording failure terminates the channel with
// exit 80, marks the segment failed and records recording.failed (HP-REC-007, HP-DB-009, G-8). The failure is
// injected at the recorder boundary (the error a failing filesystem returns), on top of the real HPREC1 recorder.
func TestFI05FI07RecordingWriteFailureTerminates(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		durability string
	}{
		{"FI-05_ENOSPC", fmt.Errorf("write segment: %w", syscall.ENOSPC), "group"},
		{"FI-07_EIO_strict", fmt.Errorf("recording fsync: %w", syscall.EIO), "strict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			var ff *faultFactory
			g := w.start(t, withConfig(func(c *config.Config) { c.Recording.Durability = tc.durability }),
				withRecorders(func(in sshproxy.RecorderFactory) sshproxy.RecorderFactory {
					ff = &faultFactory{inner: in, failAfter: 256 << 10, failErr: tc.err}
					return ff
				}))
			var written atomic.Int64
			streamExec(w, 0, &written)
			le := startExec(t, g.addr, w, "exec web1 -- stream")
			err := le.wait(t, 10*time.Second)
			if code := exitCode(err); code != sshproxy.CodeInternal {
				t.Fatalf("exit %d (%v), want %d; stderr %q", code, err, sshproxy.CodeInternal, le.stderr.String())
			}
			d := g.a.Store.ReadDB()
			if !eventually(5*time.Second, func() bool {
				return queryInt(t, d, `SELECT count(*) FROM recording_segments WHERE state = 'failed'`) == 1
			}) {
				t.Fatalf("segment not marked failed: %v", segmentRows(t, d))
			}
			if n := queryInt(t, d, `SELECT count(*) FROM timeline_events WHERE type = 'recording.failed'`); n != 1 {
				t.Fatalf("recording.failed events %d", n)
			}
			// The failed segment keeps an authentic prefix (no corrupt frames).
			path := queryStr(t, d, `SELECT path FROM recording_segments WHERE state = 'failed'`)
			if _, err := os.Stat(path); err != nil {
				path += hprec.PartialSuffix
			}
			rep, err := hprec.Verify(path, g.a.Recording.Wrapper())
			must(t, err)
			if rep.Status == hprec.StatusCorrupt {
				t.Fatalf("failed segment is corrupt: %v", rep.Problem)
			}
			// G-8: nothing the recorder did not accept may reach the agent.
			fr := ff.last()
			got, rec := int64(le.stdout.Len()), fr.recorded.Load()
			t.Logf("destination wrote %d B, recorder accepted %d B, agent received %d B", written.Load(), rec, got)
			if got > rec {
				t.Errorf("FINDING: %d B of output the recorder rejected were forwarded to the agent after the recording failed "+
					"(G-8/HP-REC-007: mandatory recording failure must stop forwarding)", got-rec)
			}
		})
	}
}

// FI-05 (disk-level): free space below the storage reserve refuses new channels before any destination contact and
// degrades readiness (HP-DB-009, HP-OPS-006).
func TestFI05DiskReserveRefusesNewChannels(t *testing.T) {
	w := newWorld(t)
	w.setup(t, 0)
	logins := len(w.dest.Logins())
	g := w.start(t, withConfig(func(c *config.Config) { c.Storage.MinFreeBytes = 1 << 62 }))
	_, errOut, code := g.run("exec web1 -- id")
	if code == 0 {
		t.Fatal("channel opened below the storage reserve")
	}
	if n := len(w.dest.Logins()); n != logins {
		t.Fatalf("destination contacted (%d logins) while storage is below reserve", n-logins)
	}
	rep := g.a.Health.Refresh(context.Background())
	if rep.Status == health.StatusReady {
		t.Fatalf("readiness %s with free space below reserve", rep.Status)
	}
	t.Logf("exit %d, stderr %q, readiness %s", code, strings.TrimSpace(errOut), rep.Status)
}

// HP-REC-007, HP-DB-009: a read-only recordings directory means recordings cannot be established: channels are
// refused before the destination is dialed and readiness fails.
func TestReadOnlyRecordingsDirFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	w := newWorld(t)
	w.setup(t, 0)
	logins := len(w.dest.Logins())
	g := w.start(t)
	dir := g.a.Store.Path(store.RecordingsDir)
	chmodTree(t, dir, 0o500)
	t.Cleanup(func() { chmodTree(t, dir, 0o700) })
	_, errOut, code := g.run("exec web1 -- id")
	if code != sshproxy.CodeInternal {
		t.Fatalf("exit %d (%q), want %d", code, errOut, sshproxy.CodeInternal)
	}
	if n := len(w.dest.Logins()); n != logins {
		t.Fatal("destination dialed although the recording could not be created")
	}
	if rep := g.a.Health.Refresh(context.Background()); rep.Status == health.StatusReady {
		t.Fatalf("readiness %s with an unwritable recordings directory", rep.Status)
	}
	chmodTree(t, dir, 0o700)
	if _, _, code := g.run("exec web1 -- id"); code != 0 {
		t.Fatalf("no recovery after the directory became writable: exit %d", code)
	}
}

func chmodTree(t testing.TB, dir string, mode os.FileMode) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, mode)
		}
		return nil
	})
	_ = os.Chmod(dir, mode)
}

// FI-08 (slow disk): a slow recorder applies backpressure end to end: the destination is throttled by the SSH
// window, gateway memory stays bounded and no output is dropped (HP-REC-011, HP-SSH-014).
func TestFI08SlowRecorderBackpressure(t *testing.T) {
	w := newWorld(t)
	g := w.start(t, withRecorders(func(in sshproxy.RecorderFactory) sshproxy.RecorderFactory {
		return &faultFactory{inner: in, delay: 100 * time.Millisecond}
	}))
	var written atomic.Int64
	const total = 64 << 20
	streamExec(w, total, &written)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	le := startExec(t, g.addr, w, "exec web1 -- stream")
	time.Sleep(4 * time.Second)
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	sent, got := written.Load(), int64(le.stdout.Len())
	t.Logf("after 4 s: destination sent %d KiB, agent received %d KiB, heap %d → %d MiB", sent>>10, got>>10,
		before.HeapAlloc>>20, during.HeapAlloc>>20)
	// 100 ms per ≤32 KiB recorder call caps throughput near 320 KiB/s; allow the two SSH windows and pipe buffers.
	if sent > 12<<20 {
		t.Fatalf("destination not throttled: %d MiB sent while the recorder was slow", sent>>20)
	}
	if during.HeapAlloc > before.HeapAlloc+64<<20 {
		t.Fatalf("gateway heap grew by %d MiB under backpressure", (during.HeapAlloc-before.HeapAlloc)>>20)
	}
	_ = le.c.Close()
	_ = le.wait(t, 10*time.Second)
}

// FI-08 (storage stalled beyond recording.block_timeout): the database is write-locked by another connection while
// a channel streams, so the recorder cannot roll segments over; once its queue stays full for block_timeout the
// channel must be terminated (exit 80) instead of blocking indefinitely (HP-REC-011).
func TestFI08StalledStorageTerminatesAfterBlockTimeout(t *testing.T) {
	w := newWorld(t)
	g := w.start(t, withConfig(func(c *config.Config) {
		c.Recording.SegmentMaxBytes = 64 << 10
		c.Recording.QueueRecords = 4
		c.Recording.QueueBytes = 128 << 10 // must exceed the largest record (see TestQueueBytesBelowRecordSize)
		c.Recording.BlockTimeout = config.Duration(time.Second)
	}))
	var written atomic.Int64
	streamExec(w, 0, &written)
	le := startExec(t, g.addr, w, "exec web1 -- stream")
	if !eventually(5*time.Second, func() bool { return le.stdout.Len() > 8<<10 }) {
		t.Fatal("no output")
	}
	lock := holdWriteLock(t, g.a.Store.Path(store.DBFile))
	locked := time.Now()
	const hold = 20 * time.Second
	var err error
	select {
	case err = <-le.done:
	case <-time.After(hold):
	}
	elapsed := time.Since(locked)
	lock()
	if err == nil && elapsed >= hold {
		err = le.wait(t, 30*time.Second)
		elapsed = time.Since(locked)
	}
	t.Logf("channel ended after %s with exit %d (block_timeout 1s, DB lock held %s)", elapsed.Round(10*time.Millisecond), exitCode(err), hold)
	if code := exitCode(err); code != sshproxy.CodeInternal {
		t.Errorf("exit %d, want %d (recording stalled)", code, sshproxy.CodeInternal)
	}
	if elapsed > 7*time.Second {
		t.Errorf("FINDING: channel ended %s after storage stalled; recording.block_timeout is 1 s (HP-REC-011 bound exceeded)",
			elapsed.Round(time.Second))
	}
}

// holdWriteLock takes the database write lock from a separate connection (BEGIN IMMEDIATE) and returns its release.
func holdWriteLock(t testing.TB, path string) func() {
	t.Helper()
	d, err := sql.Open("sqlite", "file:"+path+"?_txlock=immediate&_pragma=busy_timeout(10000)")
	must(t, err)
	tx, err := d.BeginTx(context.Background(), nil)
	must(t, err)
	var once atomic.Bool
	release := func() {
		if once.CompareAndSwap(false, true) {
			_ = tx.Rollback()
			_ = d.Close()
		}
	}
	t.Cleanup(release)
	return release
}

// recordSessions runs n exec sessions that print 256 KiB each (several frames) and returns their finalized segments
// (id → path).
func recordSessions(t *testing.T, g *gw, n int) map[string]string {
	t.Helper()
	for i := range n {
		var written atomic.Int64
		streamExec(g.w, 256<<10, &written)
		if _, _, code := g.run(fmt.Sprintf("exec web1 -- echo %d", i)); code != 0 {
			t.Fatalf("exec %d: exit %d", i, code)
		}
	}
	d := g.a.Store.ReadDB()
	// Finalization commits after the agent saw the exit status.
	eventually(5*time.Second, func() bool {
		return queryInt(t, d, `SELECT count(*) FROM recording_segments WHERE state = 'finalized'`) >= n
	})
	rows, err := d.QueryContext(context.Background(), `SELECT id, path FROM recording_segments WHERE state = 'finalized' ORDER BY opened_at`)
	must(t, err)
	defer rows.Close()
	segs := map[string]string{}
	for rows.Next() {
		var id, p string
		must(t, rows.Scan(&id, &p))
		segs[id] = p
	}
	must(t, rows.Err())
	if len(segs) != n {
		t.Fatalf("finalized segments %d, want %d", len(segs), n)
	}
	return segs
}

func verifyStatus(t *testing.T, g *gw) map[string]string {
	t.Helper()
	vr, err := g.a.Recording.Verify(context.Background(), "")
	must(t, err)
	out := map[string]string{}
	for _, s := range vr.Segments {
		out[s.SegmentID] = s.Status
	}
	return out
}

// FI-11 (corrupted, truncated and swapped segments) and FI-12 (missing segment), checked live and again after a
// restart: verify reports corrupt/missing, never ok, and replay of a corrupted segment returns only authentic
// records (HP-CRY-004, HP-CRY-005, HP-DB-013). Frame reordering inside a segment is covered by
// internal/recording/hprec tamper tests.
func TestFI11FI12CorruptAndMissingSegments(t *testing.T) {
	w := newWorld(t)
	g := w.start(t)
	segs := recordSessions(t, g, 5)
	var ids []string
	for id := range segs {
		ids = append(ids, id)
	}
	flip, trunc, swapSrc, swapDst, missing := ids[0], ids[1], ids[2], ids[3], ids[4]

	b, err := os.ReadFile(segs[flip])
	must(t, err)
	b[len(b)-200] ^= 0x40 // inside the last frames: the authentic prefix stays readable
	must(t, os.WriteFile(segs[flip], b, 0o600))
	fi, err := os.Stat(segs[trunc])
	must(t, err)
	must(t, os.Truncate(segs[trunc], fi.Size()-7))
	src, err := os.ReadFile(segs[swapSrc])
	must(t, err)
	must(t, os.WriteFile(segs[swapDst], src, 0o600))
	must(t, os.Remove(segs[missing]))

	want := map[string]string{flip: "corrupt", trunc: "corrupt", swapDst: "corrupt", missing: "missing", swapSrc: "ok"}
	check := func(stage string) {
		got := verifyStatus(t, g)
		for id, st := range want {
			if got[id] != st {
				t.Errorf("%s: segment %s status %q, want %q", stage, id, got[id], st)
			}
		}
	}
	check("live")
	var recs int
	var from uint64
	for {
		page, err := g.a.Recording.ReadPage(context.Background(), flip, from, 256<<10)
		recs += len(page.Records)
		if err != nil || !page.More {
			if err == nil && page.Complete {
				t.Error("replay of a corrupted segment reported a complete, authentic segment")
			}
			t.Logf("replay of the corrupted segment stopped after %d authentic records: err=%v incomplete=%v", recs, err, page.Incomplete)
			break
		}
		from = page.NextSeq
	}
	if recs == 0 {
		t.Error("replay returned no authentic prefix for a segment corrupted near its end")
	}

	g.stop()
	g = w.start(t)
	check("after restart")
}

// FI-13: a stray file under recordings/ is quarantined at startup and recorded.
func TestFI13OrphanSegmentQuarantined(t *testing.T) {
	w := newWorld(t)
	g := w.start(t)
	recordSessions(t, g, 1)
	dir := g.a.Store.Path(store.RecordingsDir)
	g.stop()
	stray := filepath.Join(dir, "zz", "ses_stray", "seg_stray.hprec")
	must(t, os.MkdirAll(filepath.Dir(stray), 0o700))
	must(t, os.WriteFile(stray, []byte("not a recording"), 0o600))
	g = w.start(t)
	if _, err := os.Stat(stray); err == nil {
		t.Fatal("orphan still in the recordings tree")
	}
	d := g.a.Store.ReadDB()
	if n := queryInt(t, d, `SELECT count(*) FROM quarantine_files WHERE original_path = ? AND reason LIKE 'orphan%'`, stray); n != 1 {
		t.Fatalf("quarantine records %d", n)
	}
	q := queryStr(t, d, `SELECT quarantine_path FROM quarantine_files WHERE original_path = ?`, stray)
	if _, err := os.Stat(q); err != nil {
		t.Fatalf("quarantined file missing: %v", err)
	}
}

// Configuration edge of HP-REC-011: recording.queue_bytes smaller than one record (the proxy hands the recorder up to
// 32 KiB at a time) can never admit that record, so every channel with large output stalls for block_timeout and is
// killed. Either validation must reject such a value or recording must still work.
func TestQueueBytesBelowRecordSize(t *testing.T) {
	w := newWorld(t)
	tweak := func(c *config.Config) {
		c.Recording.QueueBytes = 16 << 10
		c.Recording.BlockTimeout = config.Duration(time.Second)
	}
	cfg := baseConfig("/var/lib/hallpass")
	cfg.Mode, cfg.PublicURL, cfg.KEK.File = config.ModeProduction, "https://hallpass.example", "/etc/hallpass/kek"
	cfg.HTTP.Listen = ":8080"
	tweak(cfg)
	if err := cfg.Validate(); err != nil {
		t.Logf("configuration rejected: %v", err)
		return
	}
	g := w.start(t, withConfig(tweak))
	var written atomic.Int64
	streamExec(w, 1<<20, &written)
	le := startExec(t, g.addr, w, "exec web1 -- stream")
	err := le.wait(t, 15*time.Second)
	if code := exitCode(err); code != 0 {
		t.Errorf("FINDING: recording.queue_bytes=16384 passes validation but every record larger than the queue stalls; "+
			"the channel ended with exit %d after %d B (HP-REC-011)", code, le.stdout.Len())
	}
}
