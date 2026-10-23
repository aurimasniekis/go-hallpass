package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
)

func TestBackgroundLoopAppliesPolicyAndExpiry(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	p := f.request("pending", 15*time.Minute)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { f.svc.RunBackground(ctx, 20*time.Millisecond); close(done) }()
	rules, _ := f.pol.ListRules(f.ctx)
	must(t, f.pol.DeleteRule(f.ctx, admin, rules[0].ID))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		gg, _ := f.svc.GetGrant(f.ctx, g.ID)
		pr, _ := f.svc.GetRequest(f.ctx, p.Request.ID)
		if gg.State == GrantRevoked && pr.State == ReqCanceled {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background loop did not apply the policy change")
}

func TestServerDisableCascadeAndAgentViews(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	p := f.request("p", 15*time.Minute)
	grants, err := f.svc.ActiveGrantsForAgent(f.ctx, f.agent.ID)
	if err != nil || len(grants) != 1 || grants[0].SessionID == "" {
		t.Fatalf("%+v %v", grants, err)
	}
	if req, gr, err := f.svc.GetRequestForAgent(f.ctx, f.agent.ID, p.Request.ID); err != nil || req.ID != p.Request.ID || gr != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.GetRequestForAgent(f.ctx, f.agent.ID, "not-an-id"); !IsNotFoundOrForbidden(err) {
		t.Fatal(err)
	}
	_, err = f.inv.SetServerEnabled(f.ctx, admin, f.srv.ID, false)
	must(t, err)
	gg, _ := f.svc.GetGrant(f.ctx, g.ID)
	pr, _ := f.svc.GetRequest(f.ctx, p.Request.ID)
	if gg.State != GrantRevoked || pr.State != ReqCanceled || pr.StateReason != ReasonTargetDisabled {
		t.Fatalf("%+v %+v", gg, pr)
	}
	if _, err := f.svc.GetGrant(f.ctx, "grt_missing"); err == nil {
		t.Fatal("missing grant found")
	}
	if _, err := f.svc.GetRequest(f.ctx, "req_missing"); err == nil {
		t.Fatal("missing request found")
	}
	if r, err := f.svc.Reason(f.ctx, p.Request.ID); err != nil || r != "p" {
		t.Fatal(r, err)
	}
}

func TestEnforcerLockdownCredentialAndShutdown(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	e := NewEnforcer(f.svc, f.bus, time.Hour) // events only
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go e.Run(ctx)
	rec := newRecorder()
	r1, _ := f.register(conn, g.ID, KindExec, false)
	l1 := rec.live(f, r1, conn, g.ExpiresAt)
	l1.CredentialRef = "cred_A"
	must(t, e.Register(l1))
	// Credential revocation event for an unknown credential is ignored; a lockdown event ends everything.
	f.bus.Publish(eventbus.Event{Topic: eventbus.TopicCredentialChange, Key: "cred_unknown"})
	f.bus.Publish(eventbus.Event{Topic: eventbus.TopicLockdown, Payload: true})
	if reason := rec.wait(t, r1.ChannelID, time.Second); reason != ReasonLockdown {
		t.Fatalf("reason %q", reason)
	}
	must(t, f.svc.CloseChannel(f.ctx, r1, CloseInfo{Reason: ReasonLockdown}))
	r2, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	l2 := rec.live(f, r2, conn, g.ExpiresAt)
	must(t, e.Register(l2))
	if e.Count() != 1 {
		t.Fatalf("count %d", e.Count())
	}
	e.credentialRevoked("cred_1")
	if reason := rec.wait(t, r2.ChannelID, time.Second); reason != ReasonCredentialRevoked {
		t.Fatalf("reason %q", reason)
	}
	must(t, f.svc.CloseChannel(f.ctx, r2, CloseInfo{Reason: ReasonCredentialRevoked}))
	r3, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	l3 := rec.live(f, r3, conn, g.ExpiresAt)
	l3.CredentialRef = "cred_other"
	must(t, e.Register(l3))
	e.Unregister(r3.ChannelID)
	r4, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	{
		l4 := rec.live(f, r4, conn, g.ExpiresAt)
		l4.CredentialRef = "cred_other"
		must(t, e.Register(l4))
		e.TerminateAll(ReasonShutdown)
		if reason := rec.wait(t, r4.ChannelID, time.Second); reason != ReasonShutdown {
			t.Fatalf("reason %q", reason)
		}
	}
	if err := e.Register(rec.live(f, &ChannelReg{ChannelID: "chn_x", Grant: g}, conn, f.clk.Now().Add(-time.Second))); !errors.Is(err, ErrAccessEnded) {
		t.Fatal("expired live registered")
	}
	live, err := f.svc.LiveChannels(f.ctx)
	if err != nil || len(live) == 0 {
		t.Fatal(live, err)
	}
}

func TestCancelAndDecideEdgeCases(t *testing.T) {
	f := newFx(t)
	r := f.request("x", 0)
	if c, err := f.svc.CancelByAgent(f.ctx, f.agent.ID, r.Request.ID); err != nil || c.State != ReqCanceled {
		t.Fatal(err)
	}
	if c, err := f.svc.CancelByAgent(f.ctx, f.agent.ID, r.Request.ID); err != nil || c.State != ReqCanceled {
		t.Fatal("cancel must be idempotent", err)
	}
	if _, err := f.svc.CancelByAgent(f.ctx, "agt_other", r.Request.ID); !IsNotFoundOrForbidden(err) {
		t.Fatal(err)
	}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: "req_missing", Approve: true, Operator: f.approver, Channel: ChannelWeb}); err == nil {
		t.Fatal("decided a missing request")
	}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: f.approver, Channel: "email"}); err == nil {
		t.Fatal("unknown channel accepted")
	}
	r2 := f.request("y", 0)
	_, err := f.inv.UpdateRole(f.ctx, admin, f.role.ID, roleChannels(f, []string{"web"}))
	must(t, err)
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r2.Request.ID, Approve: true, Operator: f.approver, Channel: ChannelTelegram}); err == nil {
		t.Fatal("decision via a channel the role does not allow")
	}
	if _, err := f.svc.RevokeGrant(f.ctx, policy.OperatorInfo{ID: "opr_a", Roles: []string{"administrator"}, Enabled: true}, "grt_missing", ""); err == nil {
		t.Fatal("revoked a missing grant")
	}
}
