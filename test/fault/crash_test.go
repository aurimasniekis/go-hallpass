//go:build fault

package fault

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// FI-01: kill -9 during a storm of auto-approved requests (decision + grant + session in one transaction). After
// restart every request is either fully approved (exactly one decision, grant and session) or has none of them
// (HP-GRT-001).
func TestFI01CrashDuringDecisions(t *testing.T) {
	w := newWorld(t)
	const rounds, perRound = 4, 8
	w.setup(t, rounds*perRound)
	for r := range rounds {
		c := w.spawn(t, "")
		var wg sync.WaitGroup
		for i := range perRound {
			role := w.roles[r*perRound+i]
			wg.Go(func() {
				cl, err := dial(c.addr, w, w.agent)
				if err != nil {
					return
				}
				defer cl.Close()
				s, err := cl.NewSession()
				if err != nil {
					return
				}
				_ = s.Run("request web1 --role " + role + " --reason storm --no-wait --json")
			})
		}
		time.Sleep(time.Duration(20+40*r) * time.Millisecond)
		c.kill()
		wg.Wait()
	}
	g := w.start(t) // restart: reconciliation runs
	d := g.a.Store.ReadDB()
	checks := map[string]string{
		"approved request without exactly one decision": `SELECT count(*) FROM access_requests r WHERE r.state = 'approved'
			AND (SELECT count(*) FROM approval_decisions d WHERE d.request_id = r.id AND d.outcome = 'approved') != 1`,
		"approved request without exactly one grant": `SELECT count(*) FROM access_requests r WHERE r.state = 'approved'
			AND (SELECT count(*) FROM grants g WHERE g.request_id = r.id) != 1`,
		"grant without an access session": `SELECT count(*) FROM grants g WHERE NOT EXISTS (SELECT 1 FROM access_sessions s WHERE s.grant_id = g.id)`,
		"grant for a request that is not approved": `SELECT count(*) FROM grants g JOIN access_requests r ON r.id = g.request_id
			WHERE r.state != 'approved'`,
		"approval decision for a request that is not approved": `SELECT count(*) FROM approval_decisions d JOIN access_requests r ON r.id = d.request_id
			WHERE d.outcome = 'approved' AND r.state != 'approved'`,
	}
	for what, q := range checks {
		if n := queryInt(t, d, q); n != 0 {
			t.Errorf("%d × %s", n, what)
		}
	}
	t.Logf("after %d crashes: %d approved, %d other requests", rounds,
		queryInt(t, d, `SELECT count(*) FROM access_requests WHERE state = 'approved'`),
		queryInt(t, d, `SELECT count(*) FROM access_requests WHERE state != 'approved'`))
}

// FI-02: kill -9 after the channel is registered but before its recording exists. After restart the channel is
// interrupted/failed, no segment is left open and nothing reached the destination (HP-REC-007, HP-DB-013).
func TestFI02CrashBeforeSegmentCreated(t *testing.T) {
	w := newWorld(t)
	w.setup(t, 0)
	logins := len(w.dest.Logins())
	var ran atomic.Bool
	w.dest.Exec = func(string, io.Reader, io.Writer, io.Writer) uint32 { ran.Store(true); return 0 }
	c := w.spawn(t, "block-open")
	startExec(t, c.addr, w, "exec web1 -- id")
	ro := openRO(t, w.dir)
	if !eventually(10*time.Second, func() bool { return queryInt(t, ro, `SELECT count(*) FROM ssh_channels`) == 1 }) {
		t.Fatal("channel never registered")
	}
	c.kill()
	g := w.start(t)
	d := g.a.Store.ReadDB()
	if st := queryStr(t, d, `SELECT state FROM ssh_channels`); st != "interrupted" && st != "failed" {
		t.Fatalf("channel state %q after restart", st)
	}
	if n := queryInt(t, d, `SELECT count(*) FROM recording_segments WHERE state = 'open'`); n != 0 {
		t.Fatalf("%d segments left open", n)
	}
	if ran.Load() || len(w.dest.Logins()) != logins {
		t.Fatal("destination reached although the recording was never established")
	}
}

// FI-03: kill -9 while a channel streams output (group durability). After restart the segment is interrupted, its
// prefix authenticates, and the recorded output trails what the agent received by at most the 250 ms group-commit
// window (HP-REC-008, HP-REC-009).
func TestFI03CrashMidRecording(t *testing.T) {
	w := newWorld(t)
	w.setup(t, 0)
	const interval = 2 * time.Millisecond
	var mu sync.Mutex
	sentAt := map[int]time.Time{}
	pad := strings.Repeat("x", 1000)
	w.dest.Exec = func(_ string, _ io.Reader, stdout, _ io.Writer) uint32 {
		for i := 0; ; i++ {
			mu.Lock()
			sentAt[i] = time.Now()
			mu.Unlock()
			if _, err := fmt.Fprintf(stdout, "C%08d|%s\n", i, pad); err != nil {
				return 1
			}
			time.Sleep(interval)
		}
	}
	c := w.spawn(t, "")
	cl, err := dial(c.addr, w, w.agent)
	must(t, err)
	defer cl.Close()
	s, err := cl.NewSession()
	must(t, err)
	out, err := s.StdoutPipe()
	must(t, err)
	must(t, s.Start("exec web1 -- stream"))
	var agentLast atomic.Int64
	agentLast.Store(-1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if n, ok := counter(sc.Text()); ok {
				agentLast.Store(int64(n))
			}
		}
	}()
	time.Sleep(3 * time.Second)
	killedAt := agentLast.Load()
	c.kill()
	time.Sleep(100 * time.Millisecond)
	if last := agentLast.Load(); last > killedAt {
		killedAt = last
	}

	g := w.start(t)
	d := g.a.Store.ReadDB()
	segID := queryStr(t, d, `SELECT id FROM recording_segments`)
	if st := queryStr(t, d, `SELECT state FROM recording_segments WHERE id = ?`, segID); st != "interrupted" {
		t.Fatalf("segment state %q, want interrupted", st)
	}
	if st := verifyStatus(t, g)[segID]; st != "interrupted" {
		t.Fatalf("verify status %q, want interrupted (authentic prefix)", st)
	}
	var stdout bytes.Buffer
	var from uint64
	for {
		page, err := g.a.Recording.ReadPage(context.Background(), segID, from, 256<<10)
		must(t, err)
		for _, r := range page.Records {
			if r.Type == hprec.RecStdout {
				stdout.Write(r.Payload)
			}
		}
		if !page.More {
			break
		}
		from = page.NextSeq
	}
	recLast := -1
	for line := range strings.Lines(stdout.String()) {
		if n, ok := counter(strings.TrimSuffix(line, "\n")); ok && strings.HasSuffix(line, "\n") {
			recLast = n
		}
	}
	mu.Lock()
	lost := sentAt[int(killedAt)].Sub(sentAt[recLast])
	mu.Unlock()
	t.Logf("agent received line %d, recording recovered line %d: %s of output lost (group commit 250 ms)", killedAt, recLast,
		lost.Round(time.Millisecond))
	if recLast < 0 || lost > 300*time.Millisecond {
		t.Fatalf("recording lost %s of output (> 250 ms group-commit bound + 50 ms scheduling slack)", lost)
	}
}

func counter(line string) (int, bool) {
	if len(line) < 10 || line[0] != 'C' || line[9] != '|' {
		return 0, false
	}
	n, err := strconv.Atoi(line[1:9])
	return n, err == nil
}

// FI-04: kill -9 after the final frame was written and the segment renamed, but before the finalize transaction
// committed (held back by an external write lock). Reconciliation verifies the final frame, marks the segment
// finalized and appends its integrity-chain entry (HP-DB-013).
func TestFI04CrashBetweenRenameAndFinalize(t *testing.T) {
	w := newWorld(t)
	w.setup(t, 0)
	finish := make(chan struct{})
	started := make(chan struct{}, 1)
	w.dest.Exec = func(_ string, _ io.Reader, stdout, _ io.Writer) uint32 {
		started <- struct{}{}
		_, _ = io.WriteString(stdout, "hello\n")
		<-finish
		return 0
	}
	c := w.spawn(t, "")
	le := startExec(t, c.addr, w, "exec web1 -- hello")
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("exec never started")
	}
	ro := openRO(t, w.dir)
	var segID, path string
	if !eventually(5*time.Second, func() bool {
		return ro.QueryRowContext(context.Background(), `SELECT id, path FROM recording_segments WHERE state = 'open'`).Scan(&segID, &path) == nil
	}) {
		t.Fatal("no open segment")
	}
	release := holdWriteLock(t, w.dir+"/"+store.DBFile)
	close(finish)
	if !eventually(10*time.Second, func() bool { _, err := os.Stat(path); return err == nil }) {
		t.Fatal("segment never renamed to its final name")
	}
	_ = le.wait(t, 10*time.Second)
	c.kill()
	release()
	if st := queryStr(t, ro, `SELECT state FROM recording_segments WHERE id = ?`, segID); st != "open" {
		t.Fatalf("finalize committed before the crash (state %q); the fault window was missed", st)
	}

	g := w.start(t)
	d := g.a.Store.ReadDB()
	if st := queryStr(t, d, `SELECT state FROM recording_segments WHERE id = ?`, segID); st != "finalized" {
		t.Fatalf("segment state %q after reconciliation, want finalized", st)
	}
	if n := queryInt(t, d, `SELECT count(*) FROM integrity_chain WHERE segment_id = ?`, segID); n != 1 {
		t.Fatalf("integrity chain entries %d", n)
	}
	vr, err := g.a.Recording.Verify(context.Background(), "")
	must(t, err)
	if !vr.OK || !vr.ChainOK {
		t.Fatalf("verify after reconciliation: %+v", vr)
	}
}

// FI-23: the gateway restarts (SIGTERM) or crashes (SIGKILL) while an agent waits on a pending request. The agent is
// disconnected, the request stays pending, and status works after the restart (HP-SSH-021, HP-DB-013).
func TestFI23RestartDuringPendingWait(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		t.Run(sig.String(), func(t *testing.T) {
			w := newWorld(t)
			w.setup(t, 0, requestable(t))
			c := w.spawn(t, "")
			le := startExec(t, c.addr, w, "exec web1 --reason 'disk alert' --wait-timeout 10m -- id")
			ro := openRO(t, w.dir)
			if !eventually(10*time.Second, func() bool {
				return queryInt(t, ro, `SELECT count(*) FROM access_requests WHERE state = 'pending'`) == 1
			}) {
				t.Fatal("request never pending")
			}
			id := queryStr(t, ro, `SELECT id FROM access_requests`)
			must(t, c.cmd.Process.Signal(sig))
			_ = c.cmd.Wait()
			err := le.wait(t, 10*time.Second)
			t.Logf("waiting agent disconnected: %v (stderr %q)", err, strings.TrimSpace(le.stderr.String()))

			g := w.start(t)
			out, errOut, code := g.run("status " + id + " --json")
			if code != 0 {
				t.Fatalf("status after restart: exit %d %q", code, errOut)
			}
			var doc struct{ Request struct{ State string } }
			must(t, json.Unmarshal([]byte(out), &doc))
			if doc.Request.State != "pending" {
				t.Fatalf("request state %q after restart, want pending", doc.Request.State)
			}
		})
	}
}
