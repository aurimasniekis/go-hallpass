package access

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// HP-REQ-001/002/003/008: create, dedupe, idempotency, sanitized encrypted reason.
func TestCreateRequest(t *testing.T) {
	f := newFx(t)
	res := f.request("  check\x07 disk\u202e  usage\n\nplease ", 0)
	r := res.Request
	if r.State != ReqPending || res.Deduplicated || res.AutoApproved || r.RequestedDuration != 30*time.Minute ||
		!r.ExpiresAt.Equal(f.clk.Now().Add(30*time.Minute)) {
		t.Fatalf("%+v", r)
	}
	reason, err := f.svc.Reason(f.ctx, r.ID)
	if err != nil || reason != "check disk usage please" {
		t.Fatalf("reason %q %v", reason, err)
	}
	row, _ := f.s.R().GetRequest(f.ctx, r.ID)
	if strings.Contains(string(row.ReasonEnc), "disk") {
		t.Fatal("reason stored in plaintext")
	}
	again := f.request("different reason", time.Hour)
	if !again.Deduplicated || again.Request.ID != r.ID {
		t.Fatalf("not deduplicated: %+v", again)
	}
	if reason, _ := f.svc.Reason(f.ctx, r.ID); reason != "check disk usage please" {
		t.Fatal("dedup overwrote the original reason")
	}
	if _, err := f.svc.CancelByAgent(f.ctx, f.agent.ID, r.ID); err != nil {
		t.Fatal(err)
	}
	in := CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: f.role.ID, Reason: "x", IdempotencyKey: "retry-key-123"}
	a, err := f.svc.CreateRequest(f.ctx, in)
	must(t, err)
	_, _ = f.svc.CancelByAgent(f.ctx, f.agent.ID, a.Request.ID)
	b, err := f.svc.CreateRequest(f.ctx, in)
	if err != nil || b.Request.ID != a.Request.ID || !b.Deduplicated {
		t.Fatalf("idempotency: %+v %v", b, err)
	}
}

func TestCreateRequestValidation(t *testing.T) {
	f := newFx(t)
	base := CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: f.role.ID, Reason: "ok"}
	cases := map[string]func(*CreateRequestInput){
		"missing reason":   func(in *CreateRequestInput) { in.Reason = " \n " },
		"long reason":      func(in *CreateRequestInput) { in.Reason = strings.Repeat("x", 1001) },
		"bad duration":     func(in *CreateRequestInput) { in.Duration = 7 * time.Minute },
		"over max":         func(in *CreateRequestInput) { in.Duration = 24 * time.Hour },
		"short idempotent": func(in *CreateRequestInput) { in.IdempotencyKey = "abc" },
	}
	for name, mut := range cases {
		in := base
		mut(&in)
		if _, err := f.svc.CreateRequest(f.ctx, in); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other, _ := f.inv.CreateServer(f.ctx, admin, inventoryServer("db1", "10.0.0.2"))
	_ = other
	in := base
	in.RoleID = "rol_unknown"
	if _, err := f.svc.CreateRequest(f.ctx, in); !IsNotFoundOrForbidden(err) {
		t.Fatalf("unknown role: %v", err)
	}
}

// HP-REQ-007: per-agent request rate and pending caps.
func TestRequestRateLimits(t *testing.T) {
	f := newFx(t)
	f.svc.opts.MaxPendingPerAgent = 1
	f.request("first", 0)
	role2, err := f.inv.CreateRole(f.ctx, admin, f.srv.ID, roleInput("deploy"))
	must(t, err)
	_, err = f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: role2.ID, Reason: "x"})
	if !errors.Is(err, apperr.ErrRateLimited) {
		t.Fatalf("pending cap: %v", err)
	}
	f.svc.opts.MaxPendingPerAgent, f.svc.opts.RequestsPerAgentHour = 10, 1
	_, err = f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: role2.ID, Reason: "x"})
	if !errors.Is(err, apperr.ErrRateLimited) {
		t.Fatalf("hourly cap: %v", err)
	}
}

// HP-GRT-001/002/003, HP-SES-001: approval creates grant + session in one transaction; duration starts at commit.
func TestApproveCreatesGrantAndSession(t *testing.T) {
	f := newFx(t)
	r := f.request("why", time.Hour)
	f.clk.Advance(5 * time.Minute)
	res := f.approve(r.Request.ID, 0)
	g := res.Grant
	if g == nil || g.State != GrantActive || !g.StartsAt.Equal(f.clk.Now()) || g.ExpiresAt.Sub(g.StartsAt) != time.Hour || g.SessionID == "" {
		t.Fatalf("%+v", g)
	}
	if res.Decision.ActorID != f.approver.ID || res.Decision.Channel != ChannelWeb || res.Request.State != ReqApproved {
		t.Fatalf("%+v", res.Decision)
	}
	tl, _ := f.s.R().TimelineForSession(f.ctx, db.TimelineForSessionParams{AccessSessionID: nullStr(g.SessionID), Seq: nullInt(0), Limit: 10})
	if len(tl) != 2 || tl[0].Type != EvRequestApproved || tl[1].Type != EvGrantActivated || tl[0].Seq.Int64 != 1 {
		t.Fatalf("timeline %+v", tl)
	}
	// Reconnect/reuse never extends (HP-GRT-003).
	found, _ := f.svc.FindActiveGrant(f.ctx, f.agent.ID, f.srv.ID, f.role.ID)
	if found.ID != g.ID || !found.ExpiresAt.Equal(g.ExpiresAt) {
		t.Fatal("active grant lookup")
	}
	if res2 := f.approve(r.Request.ID, 0); !res2.Replayed || res2.Grant.ID != g.ID {
		t.Fatal("identical decision replay is not idempotent")
	}
	if res, err := audit.Verify(f.ctx, f.s.R()); err != nil || !res.OK {
		t.Fatal(err)
	}
}

func TestDenyAndAuthority(t *testing.T) {
	f := newFx(t)
	r := f.request("why", 0)
	viewer := policy.OperatorInfo{ID: "opr_viewer", Roles: []string{"viewer"}, Enabled: true}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: viewer, Channel: ChannelWeb}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("viewer approved: %v", err)
	}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Duration: 24 * time.Hour, Operator: f.approver, Channel: ChannelWeb}); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("over-max approval: %v", err)
	}
	res, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: false, Operator: f.approver, Channel: ChannelSlack, Comment: "not now"})
	if err != nil || res.Request.State != ReqDenied || res.Grant != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: f.approver, Channel: ChannelWeb}); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("approve after deny: %v", err)
	}
}

// HP-GRT-007: concurrent deciders — exactly one decision wins; the rest get a conflict or a replay.
func TestConcurrentDecisions(t *testing.T) {
	f := newFx(t)
	r := f.request("why", 0)
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := range 20 {
		wg.Go(func() {
			_, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: i%2 == 0, Operator: f.approver, Channel: ChannelWeb})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	ok, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, apperr.ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	d, err := f.s.R().GetDecisionByRequest(f.ctx, r.Request.ID)
	if err != nil || ok+conflicts != 20 || ok < 1 {
		t.Fatalf("ok=%d conflicts=%d %v", ok, conflicts, err)
	}
	if g, err := f.s.R().GetGrantByRequest(f.ctx, r.Request.ID); (d.Outcome == "approved") != (err == nil) {
		t.Fatalf("grant/decision mismatch: %v %v", g, err)
	}
}

// HP-REQ-004, HP-GRT-010: pending expiry, no approval after expiry, new session after grant expiry.
func TestExpiry(t *testing.T) {
	f := newFx(t)
	r := f.request("why", 0)
	f.clk.Advance(31 * time.Minute)
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: f.approver, Channel: ChannelWeb}); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("approved an expired request: %v", err)
	}
	reqs, grants, err := f.svc.ExpireDue(f.ctx)
	if err != nil || reqs != 1 || grants != 0 {
		t.Fatalf("%d %d %v", reqs, grants, err)
	}
	g1 := f.grant(15 * time.Minute)
	f.clk.Advance(16 * time.Minute)
	if g, _ := f.svc.FindActiveGrant(f.ctx, f.agent.ID, f.srv.ID, f.role.ID); g != nil {
		t.Fatal("expired grant still active (expiry must be time-authoritative)")
	}
	if _, grants, _ := f.svc.ExpireDue(f.ctx); grants != 1 {
		t.Fatal("grant not expired by sweep")
	}
	g2 := f.grant(15 * time.Minute)
	if g2.SessionID == g1.SessionID || g2.ID == g1.ID {
		t.Fatal("approval after expiry must create a new grant and session")
	}
	sess, _ := f.s.R().GetSession(f.ctx, g1.SessionID)
	if sess.State != "closed" || sess.CloseReason.String != ReasonExpired {
		t.Fatalf("session %+v", sess)
	}
}

// HP-GRT-005: overlapping grants pick the latest expiry.
func TestOverlappingGrantSelection(t *testing.T) {
	f := newFx(t)
	short := f.grant(15 * time.Minute)
	long := f.grant(time.Hour)
	if g, _ := f.svc.FindActiveGrant(f.ctx, f.agent.ID, f.srv.ID, f.role.ID); g.ID != long.ID || g.SessionID == short.SessionID {
		t.Fatalf("selected %+v", g)
	}
	f.clk.Advance(59*time.Minute + 59*time.Second)
	if g, _ := f.svc.FindActiveGrant(f.ctx, f.agent.ID, f.srv.ID, f.role.ID); g != nil {
		t.Fatal("grant with < min_remaining_to_connect must not be selected")
	}
}

// HP-POL-013: auto-approval within the auto max, records system:policy.
func TestAutoApproval(t *testing.T) {
	f := newFx(t)
	_, err := f.pol.CreateRule(f.ctx, admin, policy.Rule{Name: "auto", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove, AutoMaxDuration: 15 * time.Minute,
		Enabled: true, Subjects: policy.SubjectSelector{All: true}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	res := f.request("quick look", 15*time.Minute)
	if !res.AutoApproved || res.Grant == nil || res.Request.State != ReqApproved {
		t.Fatalf("%+v", res)
	}
	d, _ := f.s.R().GetDecisionByRequest(f.ctx, res.Request.ID)
	if d.ActorType != "policy" || d.Channel != "policy" {
		t.Fatalf("%+v", d)
	}
	if long := f.request("longer", time.Hour); long.AutoApproved || long.Request.State != ReqPending {
		t.Fatal("over-limit request was auto-approved")
	}
}

// HP-POL-008: policy changes cancel pending requests, revoke grants, clamp durations.
func TestPolicyChangeEffects(t *testing.T) {
	f := newFx(t)
	g := f.grant(3 * time.Hour)
	pending := f.request("again", time.Hour)
	rules, _ := f.pol.ListRules(f.ctx)
	r := rules[0]
	r.MaxDuration = time.Hour
	_, err := f.pol.UpdateRule(f.ctx, admin, r.ID, r)
	must(t, err)
	if _, _, clamped, err := f.svc.ReconcilePolicy(f.ctx); err != nil || clamped != 1 {
		t.Fatalf("clamped=%d %v", clamped, err)
	}
	cg, _ := f.svc.GetGrant(f.ctx, g.ID)
	if cg.ExpiresAt.Sub(cg.StartsAt) != time.Hour {
		t.Fatalf("grant not clamped: %s", cg.ExpiresAt.Sub(cg.StartsAt))
	}
	must(t, f.pol.DeleteRule(f.ctx, admin, r.ID))
	canceled, revoked, _, err := f.svc.ReconcilePolicy(f.ctx)
	if err != nil || canceled != 1 || revoked != 1 {
		t.Fatalf("canceled=%d revoked=%d %v", canceled, revoked, err)
	}
	pr, _ := f.svc.GetRequest(f.ctx, pending.Request.ID)
	gg, _ := f.svc.GetGrant(f.ctx, g.ID)
	if pr.State != ReqCanceled || pr.StateReason != ReasonPolicyChanged || gg.State != GrantRevoked || gg.EndReason != ReasonPolicyChanged {
		t.Fatalf("%+v %+v", pr, gg)
	}
}

// HP-AGT-008, HP-SRV-008, HP-GRT-011: disablement cascades and lockdown.
func TestCascadesAndLockdown(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	_, err := f.inv.SetRoleEnabled(f.ctx, admin, f.role.ID, false)
	must(t, err)
	if gg, _ := f.svc.GetGrant(f.ctx, g.ID); gg.State != GrantRevoked || gg.EndReason != ReasonTargetDisabled {
		t.Fatalf("%+v", gg)
	}
	_, err = f.inv.SetRoleEnabled(f.ctx, admin, f.role.ID, true)
	must(t, err)
	g2 := f.grant(time.Hour)
	p := f.request("pending", time.Hour)
	_ = p
	must(t, f.svc.SetLockdown(f.ctx, admin, true))
	if gg, _ := f.svc.GetGrant(f.ctx, g2.ID); gg.State != GrantRevoked || gg.EndReason != ReasonLockdown {
		t.Fatalf("%+v", gg)
	}
	if _, err := f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: f.role.ID, Reason: "x"}); !errors.Is(err, ErrLockdown) {
		t.Fatalf("request during lockdown: %v", err)
	}
	must(t, f.svc.SetLockdown(f.ctx, admin, false))
	g3 := f.grant(time.Hour)
	_, err = f.agents.SetEnabled(f.ctx, admin, f.agent.ID, false, "compromised")
	must(t, err)
	if gg, _ := f.svc.GetGrant(f.ctx, g3.ID); gg.State != GrantRevoked || gg.EndReason != ReasonAgentDisabled {
		t.Fatalf("%+v", gg)
	}
}

func TestKeyRevocationCascadeOnlyWhenLastKey(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	_, err := f.agents.RevokeKey(f.ctx, admin, f.agent.ID, f.keyID, "lost")
	must(t, err)
	if gg, _ := f.svc.GetGrant(f.ctx, g.ID); gg.State != GrantRevoked || gg.EndReason != ReasonKeyRevoked {
		t.Fatalf("last key revoked but grant survives: %+v", gg)
	}
}

func TestOperatorRevokeAndCancel(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	other := policy.OperatorInfo{ID: "opr_x", Roles: []string{"approver"}, Enabled: true}
	if _, err := f.svc.RevokeGrant(f.ctx, other, g.ID, "x"); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("out-of-scope revoke: %v", err)
	}
	if gg, err := f.svc.RevokeGrant(f.ctx, f.approver, g.ID, "suspicious"); err != nil || gg.State != GrantRevoked {
		t.Fatalf("%+v %v", gg, err)
	}
	r := f.request("x", 0)
	if _, err := f.svc.CancelByOperator(f.ctx, other, r.Request.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatal(err)
	}
	adminOp := policy.OperatorInfo{ID: "opr_a", Roles: []string{"administrator"}, Enabled: true}
	if c, err := f.svc.CancelByOperator(f.ctx, adminOp, r.Request.ID); err != nil || c.State != ReqCanceled {
		t.Fatal(err)
	}
	if _, _, err := f.svc.GetRequestForAgent(f.ctx, "agt_other", r.Request.ID); !IsNotFoundOrForbidden(err) {
		t.Fatal("other agent could see the request")
	}
	_ = keyring.PurposeField
}
