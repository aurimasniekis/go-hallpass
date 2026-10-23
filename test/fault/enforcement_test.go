//go:build fault

package fault

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
)

// offsetClock is the wall clock shifted by a settable offset: a wall-clock jump without restarting the process.
// Values carry no monotonic reading, so every comparison observes the jump (as persisted UTC times do).
type offsetClock struct{ off atomic.Int64 }

func (c *offsetClock) Now() time.Time { return time.Now().Round(0).Add(time.Duration(c.off.Load())) }

func (c *offsetClock) jump(d time.Duration) { c.off.Add(int64(d)) }

// revokeSilently ends a grant the way RevokeGrant persists it but without publishing the in-process event (a lost
// bus delivery): only the enforcer's database reconciliation can notice.
func revokeSilently(t testing.TB, g *gw, grantID string, now time.Time) {
	t.Helper()
	us := now.UnixMicro()
	must(t, g.a.Store.W().Exec(context.Background(), `UPDATE grants SET state = 'revoked', ended_at = ?, end_reason = ?, revoked_by = ?,
		updated_at = ? WHERE id = ? AND state = 'active'`, us, access.ReasonOperator, "operator:opr_admin", us, grantID))
}

// FI-20: wall-clock jumps. A backward jump never extends a grant (expiry unchanged on reuse); a forward jump past
// expiry terminates the channel within the enforcement bound and the next access needs a new grant (HP-GRT-003,
// HP-GRT-008).
func TestFI20ClockJumps(t *testing.T) {
	w := newWorld(t)
	oc := &offsetClock{}
	g := w.start(t, withApp(app.WithClock(oc)))
	started := blockingExec(w.dest)
	le := startExec(t, g.addr, w, "exec web1 --duration 30m -- sleep")
	waitStarted(t, started)
	gs := g.activeGrants()
	if len(gs) != 1 {
		t.Fatalf("grants %d", len(gs))
	}
	orig := gs[0]

	oc.jump(-time.Hour)
	started2 := blockingExec(w.dest)
	reuse := startExec(t, g.addr, w, "exec web1 -- true")
	waitStarted(t, started2)
	_ = reuse.stdin.Close()
	_ = reuse.wait(t, 10*time.Second)
	after, err := g.a.Access.GetGrant(context.Background(), orig.ID)
	must(t, err)
	if !after.ExpiresAt.Equal(orig.ExpiresAt) || after.State != access.GrantActive {
		t.Fatalf("backward jump changed the grant: expiry %s → %s, state %s", orig.ExpiresAt, after.ExpiresAt, after.State)
	}
	t.Logf("after a 1 h backward step, access used %d active grant(s); original expiry unchanged", len(g.activeGrants()))

	oc.jump(time.Hour + time.Until(orig.ExpiresAt) + 30*time.Second) // wall clock now 30 s past expiry
	jumped := time.Now()
	err = le.wait(t, access.EnforcementBound+2*time.Second)
	lat := time.Since(jumped)
	if code := exitCode(err); code != sshproxy.CodeAccessEnded {
		t.Fatalf("exit %d after the forward jump past expiry, want %d", code, sshproxy.CodeAccessEnded)
	}
	if lat > access.EnforcementBound {
		t.Fatalf("terminated %s after expiry passed (bound %s)", lat, access.EnforcementBound)
	}
	t.Logf("forward jump past expiry: channel terminated after %s", lat.Round(time.Millisecond))
	if !eventually(5*time.Second, func() bool {
		gr, err := g.a.Access.GetGrant(context.Background(), orig.ID)
		return err == nil && gr.State != access.GrantActive
	}) {
		t.Fatal("expired grant still active")
	}
	if _, _, code := g.run("exec web1 -- true"); code != 0 {
		t.Fatalf("new access after expiry: exit %d", code)
	}
	for _, gr := range g.activeGrants() {
		if gr.ID == orig.ID || !gr.ExpiresAt.After(oc.Now()) {
			t.Fatalf("access after expiry used a stale grant: %+v", gr)
		}
	}
}

// FI-20 (documented limitation probe): grant expiry is evaluated against the wall clock (persisted UTC times;
// THREAT_MODEL assumption 6 requires NTP). This measures what a backward step does to a channel whose grant is about
// to expire; it reports the observed behavior and does not fail.
func TestFI20BackwardJumpNearExpiry(t *testing.T) {
	w := newWorld(t)
	oc := &offsetClock{}
	g := w.start(t, withApp(app.WithClock(oc)))
	started := blockingExec(w.dest)
	le := startExec(t, g.addr, w, "exec web1 --duration 30m -- sleep")
	waitStarted(t, started)
	exp := g.activeGrants()[0].ExpiresAt
	oc.jump(time.Until(exp) - 3*time.Second) // 3 s before expiry
	oc.jump(-time.Hour)                      // then the wall clock steps back an hour
	select {
	case err := <-le.done:
		t.Logf("channel ended (exit %d) at the original expiry despite the backward step", exitCode(err))
	case <-time.After(3*time.Second + access.EnforcementBound):
		t.Logf("OBSERVATION: after a 1 h backward wall-clock step the channel outlived its grant's original expiry by more "+
			"than %s; expiry follows the wall clock (in-process deadlines are not monotonic for grant expiry)", access.EnforcementBound)
	}
}

// FI-21: a lost revocation event. The grant is revoked in the database without the in-process event; the
// enforcer's reconciliation terminates the channel within the 5 s bound (HP-GRT-008). The second case repeats it
// after a backward wall-clock step, where the reconciliation cursor (based on updated_at) must still see the change.
func TestFI21LostRevocationEvent(t *testing.T) {
	w := newWorld(t)
	oc := &offsetClock{}
	g := w.start(t, withApp(app.WithClock(oc)))
	started := blockingExec(w.dest)
	for _, tc := range []struct {
		name string
		step time.Duration
	}{{"no_clock_step", 0}, {"after_backward_step", -time.Hour}} {
		le := startExec(t, g.addr, w, "exec web1 -- sleep")
		waitStarted(t, started)
		gs := g.activeGrants()
		if len(gs) != 1 {
			t.Fatalf("%s: active grants %d", tc.name, len(gs))
		}
		oc.jump(tc.step)
		t0 := time.Now()
		revokeSilently(t, g, gs[0].ID, oc.Now())
		select {
		case err := <-le.done:
			lat := time.Since(t0)
			t.Logf("%s: terminated %s after the silent revocation (exit %d)", tc.name, lat.Round(time.Millisecond), exitCode(err))
			if lat > access.EnforcementBound {
				t.Errorf("%s: termination took %s (bound %s)", tc.name, lat, access.EnforcementBound)
			}
		case <-time.After(access.EnforcementBound + 2*time.Second):
			if tc.step == 0 {
				t.Fatalf("%s: channel survived a revoked grant (lost event) beyond %s", tc.name, access.EnforcementBound)
			}
			t.Errorf("FINDING: %s: with the in-process event lost, a grant revoked after a %s wall-clock step was not enforced "+
				"within %s: the enforcer's reconciliation cursor (max updated_at seen, minus 5 s) skips rows stamped "+
				"earlier than the cursor (HP-GRT-008)", tc.name, tc.step, access.EnforcementBound)
			_ = le.c.Close()
		}
		oc.off.Store(0)
	}
}

// Revocation storm: many live channels (one grant each) are revoked concurrently; then all of an agent's channels end
// on agent disable, and on lockdown. Every channel must end within the 5 s bound (HP-GRT-008, HP-GRT-011).
func TestRevocationStorm(t *testing.T) {
	const n = 16
	w := newWorld(t)
	g := w.start(t, withRoles(n))
	started := blockingExec(w.dest)
	open := func() []*longExec {
		les := make([]*longExec, n)
		for i := range n {
			les[i] = startExec(t, g.addr, w, fmt.Sprintf("exec web1 --role role%d -- sleep", i))
		}
		for range n {
			waitStarted(t, started)
		}
		return les
	}
	measure := func(name string, les []*longExec, t0 time.Time) {
		t.Helper()
		var lats []time.Duration
		for i, le := range les {
			select {
			case err := <-le.done:
				_ = err // the exit code is asserted by the per-scenario tests; only the timing matters here
				lats = append(lats, time.Unix(0, le.ended.Load()).Sub(t0))
				_ = le.c.Close() // stay under ssh.max_connections_per_agent for the next round
			case <-time.After(access.EnforcementBound + 2*time.Second - time.Since(t0)):
				t.Errorf("%s: channel %d still running after %s", name, i, time.Since(t0))
			}
		}
		slices.Sort(lats)
		if len(lats) > 0 {
			t.Logf("%s: %d channels ended; p50 %s, max %s", name, len(lats), lats[len(lats)/2].Round(time.Millisecond),
				lats[len(lats)-1].Round(time.Millisecond))
			if lats[len(lats)-1] > access.EnforcementBound {
				t.Errorf("%s: slowest termination %s exceeds %s", name, lats[len(lats)-1], access.EnforcementBound)
			}
		}
	}

	les := open()
	grants := g.activeGrants()
	if len(grants) != n {
		t.Fatalf("active grants %d, want %d", len(grants), n)
	}
	t0 := time.Now()
	var wg sync.WaitGroup
	for _, gr := range grants {
		wg.Go(func() {
			if _, err := g.a.Access.RevokeGrant(context.Background(), adminOp, gr.ID, "storm"); err != nil {
				t.Errorf("revoke: %v", err)
			}
		})
	}
	wg.Wait()
	measure("concurrent grant revocations", les, t0)

	les = open()
	t0 = time.Now()
	must(t, g.a.Access.SetLockdown(context.Background(), admin, true))
	measure("lockdown", les, t0)
	if _, _, code := g.run("exec web1 --role inspect -- true"); code == 0 {
		t.Error("new channel opened during lockdown")
	}
	must(t, g.a.Access.SetLockdown(context.Background(), admin, false))

	les = open()
	t0 = time.Now()
	_, err := g.a.Agents.SetEnabled(context.Background(), admin, w.agentID, false, "storm")
	must(t, err)
	measure("agent disabled", les, t0)
}
