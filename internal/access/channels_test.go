package access

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

func (f *fx) register(connID, grantID, kind string, pty bool) (*ChannelReg, error) {
	return f.svc.RegisterChannel(f.ctx, RegisterInput{ConnectionID: connID, AgentID: f.agent.ID, KeyID: f.keyID, GrantID: grantID, Kind: kind, PTY: pty})
}

// HP-SSH-025: every channel revalidates grant, key, policy, capability.
func TestRegisterChannelRevalidates(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	reg, err := f.register(conn, g.ID, KindShell, true)
	if err != nil || reg.SessionID != g.SessionID || reg.Role.ID != f.role.ID {
		t.Fatalf("%+v %v", reg, err)
	}
	must(t, f.svc.ActivateChannel(f.ctx, reg, "cred_x", map[string]any{"kind": "shell"}))
	exit := 0
	must(t, f.svc.CloseChannel(f.ctx, reg, CloseInfo{Reason: "exit_status", ExitStatus: &exit}))

	if _, err := f.svc.RegisterChannel(f.ctx, RegisterInput{ConnectionID: conn, AgentID: "agt_other", KeyID: f.keyID, GrantID: g.ID, Kind: KindExec}); !IsNotFoundOrForbidden(err) {
		t.Fatalf("foreign agent used grant: %v", err)
	}
	_, err = f.inv.UpdateRole(f.ctx, admin, f.role.ID, inventory.RoleInput{Version: f.role.Version, Capabilities: ptr([]string{inventory.CapExec})})
	must(t, err)
	if _, err := f.register(conn, g.ID, KindShell, false); !errors.Is(err, ErrCapability) {
		t.Fatalf("shell without capability: %v", err)
	}
	if _, err := f.register(conn, g.ID, KindExec, true); !errors.Is(err, ErrCapability) {
		t.Fatalf("pty without capability: %v", err)
	}
	if _, err := f.register(conn, g.ID, KindExec, false); err != nil {
		t.Fatalf("exec should be allowed: %v", err)
	}
	f.clk.Advance(time.Hour - time.Second)
	if _, err := f.register(conn, g.ID, KindExec, false); !errors.Is(err, ErrAccessEnded) {
		t.Fatalf("channel registered with < min remaining: %v", err)
	}
}

func TestRegisterAfterKeyRevokeAndLockdown(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	must(t, f.svc.SetLockdown(f.ctx, admin, true))
	if _, err := f.register(conn, g.ID, KindExec, false); err == nil {
		t.Fatal("channel during lockdown")
	}
	must(t, f.svc.SetLockdown(f.ctx, admin, false))
	g2 := f.grant(time.Hour)
	_, err := f.agents.AddKey(f.ctx, admin, f.agent.ID, newKeyLine(t))
	must(t, err)
	_, err = f.agents.RevokeKey(f.ctx, admin, f.agent.ID, f.keyID, "")
	must(t, err)
	if _, err := f.register(conn, g2.ID, KindExec, false); !errors.Is(err, ErrAccessEnded) {
		t.Fatalf("revoked key opened a channel: %v", err)
	}
}

// HP-GRT-006: concurrency limits are enforced atomically under contention.
func TestConcurrencyLimitsAtomic(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	var wg sync.WaitGroup
	var ok, limited atomic.Int32
	for range 12 {
		wg.Go(func() {
			_, err := f.register(conn, g.ID, KindExec, false)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrConcurrencyLimit):
				limited.Add(1)
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 2 || limited.Load() != 10 {
		t.Fatalf("per-agent limit 2: ok=%d limited=%d", ok.Load(), limited.Load())
	}
	n, _ := f.s.R().CountLiveChannelsForAgentRole(f.ctx, db.CountLiveChannelsForAgentRoleParams{AgentID: f.agent.ID, RoleID: f.role.ID})
	if n != 2 {
		t.Fatalf("live channels %d", n)
	}
}

func TestSessionTimelineAndClose(t *testing.T) {
	f := newFx(t)
	g := f.grant(15 * time.Minute)
	conn := f.conn()
	reg, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	must(t, f.svc.ActivateChannel(f.ctx, reg, "cred_1", map[string]any{"kind": "exec"}))
	must(t, f.svc.AppendSessionEvent(f.ctx, reg, EvExecRequested, "", map[string]any{"has_command": true}))
	f.clk.Advance(16 * time.Minute)
	_, _, err = f.svc.ExpireDue(f.ctx)
	must(t, err)
	if s, _ := f.s.R().GetSession(f.ctx, g.SessionID); s.State != "closing" {
		t.Fatalf("session with a live channel must stay closing, got %s", s.State)
	}
	st := 0
	must(t, f.svc.CloseChannel(f.ctx, reg, CloseInfo{Reason: ReasonExpired, ExitStatus: &st}))
	must(t, f.svc.CloseConnection(f.ctx, conn, "client_closed"))
	if n, err := f.svc.CloseFinishedSessions(f.ctx); err != nil || n != 1 {
		t.Fatalf("closed %d %v", n, err)
	}
	tl, _ := f.s.R().TimelineForSession(f.ctx, db.TimelineForSessionParams{AccessSessionID: nullStr(g.SessionID), Seq: nullInt(0), Limit: 100})
	var types []string
	var last int64
	for _, e := range tl {
		types = append(types, e.Type)
		if e.Seq.Valid {
			if e.Seq.Int64 <= last {
				t.Fatalf("sequence not increasing: %v", tl)
			}
			last = e.Seq.Int64
		}
	}
	want := []string{EvRequestApproved, EvGrantActivated, EvConnOpened, EvChannelOpened, EvExecRequested, EvGrantExpired, EvChannelExited, EvConnClosed, EvSessionClosed}
	if len(types) != len(want) {
		t.Fatalf("timeline %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("timeline %v, want %v", types, want)
		}
	}
}

type termRecorder struct {
	mu      sync.Mutex
	reasons map[string]string
	at      map[string]time.Time
}

func (r *termRecorder) live(f *fx, reg *ChannelReg, conn string, expires time.Time) *Live {
	return &Live{ChannelID: reg.ChannelID, ConnectionID: conn, AgentID: f.agent.ID, KeyID: f.keyID, GrantID: reg.Grant.ID, CredentialRef: "cred_1",
		ExpiresAt: expires, Terminate: func(reason string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.reasons[reg.ChannelID] = reason
			r.at[reg.ChannelID] = time.Now()
		}}
}

func (r *termRecorder) wait(t *testing.T, id string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		reason, ok := r.reasons[id]
		r.mu.Unlock()
		if ok {
			return reason
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("channel %s not terminated within %s", id, within)
	return ""
}

func newRecorder() *termRecorder {
	return &termRecorder{reasons: map[string]string{}, at: map[string]time.Time{}}
}

// HP-GRT-008: revocation terminates channels within the bound via events; registration after revocation fails.
func TestEnforcerRevocationBound(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	reg, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	e := NewEnforcer(f.svc, f.bus, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go e.Run(ctx)
	rec := newRecorder()
	must(t, e.Register(rec.live(f, reg, conn, g.ExpiresAt)))
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	_, err = f.svc.RevokeGrant(f.ctx, f.approver, g.ID, "")
	must(t, err)
	if reason := rec.wait(t, reg.ChannelID, EnforcementBound); reason != ReasonOperator {
		t.Fatalf("reason %q", reason)
	}
	if d := rec.at[reg.ChannelID].Sub(start); d > time.Second {
		t.Fatalf("event-path termination took %s", d)
	}
	if err := e.Register(rec.live(f, &ChannelReg{ChannelID: "chn_late", Grant: g}, conn, g.ExpiresAt)); !errors.Is(err, ErrAccessEnded) {
		t.Fatal("registration after revocation accepted")
	}
}

// Lost events: DB reconciliation still terminates within the bound (FI-21).
func TestEnforcerReconcilesWithoutEvents(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	reg, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	e := NewEnforcer(f.svc, nil, 50*time.Millisecond) // no bus: events are lost
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go e.Run(ctx)
	rec := newRecorder()
	must(t, e.Register(rec.live(f, reg, conn, g.ExpiresAt)))
	_, err = f.agents.SetEnabled(f.ctx, admin, f.agent.ID, false, "")
	must(t, err)
	if reason := rec.wait(t, reg.ChannelID, EnforcementBound); reason != ReasonAgentDisabled {
		t.Fatalf("reason %q", reason)
	}
}

func TestEnforcerExpiryAndKeyRevocation(t *testing.T) {
	f := newFx(t)
	g := f.grant(15 * time.Minute)
	conn := f.conn()
	r1, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	e := NewEnforcer(f.svc, f.bus, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go e.Run(ctx)
	rec := newRecorder()
	must(t, e.Register(rec.live(f, r1, conn, g.ExpiresAt)))
	f.clk.Advance(15 * time.Minute)
	if reason := rec.wait(t, r1.ChannelID, EnforcementBound); reason != ReasonExpired {
		t.Fatalf("reason %q", reason)
	}
	// Key revocation with another active key: only this key's connections end.
	f.clk.Advance(time.Minute)
	g2 := f.grant(time.Hour)
	r2, err := f.register(conn, g2.ID, KindExec, false)
	must(t, err)
	must(t, e.Register(rec.live(f, r2, conn, g2.ExpiresAt)))
	_, err = f.agents.AddKey(f.ctx, admin, f.agent.ID, newKeyLine(t))
	must(t, err)
	_, err = f.agents.RevokeKey(f.ctx, admin, f.agent.ID, f.keyID, "")
	must(t, err)
	if reason := rec.wait(t, r2.ChannelID, EnforcementBound); reason != ReasonKeyRevoked {
		t.Fatalf("reason %q", reason)
	}
	if gg, _ := f.svc.GetGrant(f.ctx, g2.ID); gg.State != GrantActive {
		t.Fatal("grant revoked although the agent still has an active key")
	}
}

// HP-DB-013: channels and connections from an earlier boot are marked interrupted.
func TestReconcileStartup(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	reg, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	must(t, f.svc.ActivateChannel(f.ctx, reg, "", nil))
	restarted := New(f.s, f.svc.kr, f.svc.audit, f.bus, f.svc.engine, Options{Clock: f.clk, BootID: ids.New(ids.Boot)})
	res, err := restarted.ReconcileStartup(f.ctx)
	if err != nil || res.Connections != 1 || res.Channels != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	ch, _ := f.s.R().GetChannel(f.ctx, reg.ChannelID)
	c, _ := f.s.R().GetConnection(f.ctx, conn)
	if ch.State != "interrupted" || c.State != "interrupted" {
		t.Fatalf("%s %s", ch.State, c.State)
	}
	if again, _ := restarted.ReconcileStartup(f.ctx); again.Channels != 0 {
		t.Fatal("reconciliation not idempotent")
	}
	if _, err := restarted.RegisterChannel(f.ctx, RegisterInput{ConnectionID: conn, AgentID: f.agent.ID, KeyID: f.keyID, GrantID: g.ID, Kind: KindExec}); err != nil {
		t.Fatalf("grant must survive restart: %v", err)
	}
}

func TestSanitizeReason(t *testing.T) {
	cases := map[string]string{
		"plain":                   "plain",
		"  a\tb\n\nc  ":           "a b c",
		"bidi\u202eevil\u2066x":   "bidievilx",
		"zero\u200bwidth":         "zerowidth",
		"ctrl\x00\x1b[31mred":     "ctrl[31mred",
		"emoji ✅ ok":              "emoji ✅ ok",
		string([]byte{0xff, 'a'}): "a",
	}
	for in, want := range cases {
		got, err := SanitizeReason(in)
		if err != nil || got != want {
			t.Errorf("%q → %q (%v), want %q", in, got, err, want)
		}
	}
	if _, err := SanitizeReason(stringsRepeat("a", 1001)); err == nil {
		t.Error("over-long reason accepted")
	}
	if _, err := SanitizeReason(stringsRepeat("é", 1000)); err != nil {
		t.Error("1000 runes must be accepted")
	}
	_ = apperr.CodeInvalid
}

func FuzzSanitizeReason(f *testing.F) {
	f.Add("investigate \u202e errors")
	f.Fuzz(func(t *testing.T, s string) {
		out, err := SanitizeReason(s)
		if err != nil {
			return
		}
		for _, r := range out {
			if r < 0x20 || (r >= 0x7f && r < 0xa0) || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
				t.Fatalf("control/format rune %U survived", r)
			}
		}
	})
}

func stringsRepeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
