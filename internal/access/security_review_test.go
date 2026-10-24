package access

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// SR-12 (HP-POL-008): removing an agent from its only allowing group revokes its active grant through the
// policy.changed reconciliation, well inside the 5 s bound (before: only the 1-minute ticker caught it).
func TestGroupChangeRevokesGrantWithinBound(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	go f.svc.RunBackground(ctx, time.Hour)
	time.Sleep(20 * time.Millisecond) // let RunBackground subscribe
	a, err := f.agents.Get(f.ctx, f.agent.ID)
	must(t, err)
	_, err = f.agents.Update(f.ctx, admin, a.ID, agents.UpdateInput{Version: a.Version, Groups: ptr([]string{"other"})})
	must(t, err)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cur, err := f.svc.GetGrant(f.ctx, g.ID)
		must(t, err)
		if cur.State == GrantRevoked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("grant still active 3 s after the agent left its only allowing group")
}

// SR-13 (HP-GRT-008): more than one page of grant rows sharing one updated_at must not stall the enforcer's
// database safety net; a revocation whose event was lost is still enforced.
func TestEnforcerSafetyNetPagesPastSameTimestamp(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	conn := f.conn()
	reg, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	e := NewEnforcer(f.svc, nil, time.Hour) // no bus (lost events); reconcile driven manually
	rec := newRecorder()
	must(t, e.Register(rec.live(f, reg, conn, g.ExpiresAt)))

	// A mass revocation: grantPage+50 ended grants stamped with one timestamp, written in small transactions to keep
	// each within the HP-DB-004 budget (the fake clock does not move, so all rows share updated_at).
	now := f.clk.Now().UnixMicro()
	const batch = 10
	for b := 0; b < grantPage+50; b += batch {
		must(t, f.s.W().TxNamed(f.ctx, "test.bulk_grants", func(tx *store.Tx) error {
			for i := b; i < b+batch; i++ {
				rid, did, gid := ids.New(ids.Request), fmt.Sprintf("dec_bulk%05d", i), ids.New(ids.Grant)
				if _, err := tx.SQL.ExecContext(f.ctx, `INSERT INTO access_requests (id, agent_id, agent_key_id, server_id, role_id,
					requested_duration_s, state, policy_version, created_at, expires_at, updated_at) VALUES (?, ?, ?, ?, ?, 3600, 'approved', 1, ?, ?, ?)`,
					rid, f.agent.ID, f.keyID, f.srv.ID, f.role.ID, now, now+1, now); err != nil {
					return err
				}
				if _, err := tx.SQL.ExecContext(f.ctx, `INSERT INTO approval_decisions (id, request_id, outcome, actor_type, actor_id, channel,
					policy_version, decided_at) VALUES (?, ?, 'approved', 'policy', 'rule', 'policy', 1, ?)`, did, rid, now); err != nil {
					return err
				}
				if _, err := tx.SQL.ExecContext(f.ctx, `INSERT INTO grants (id, request_id, decision_id, agent_id, server_id, role_id, remote_user,
					capabilities_json, policy_version, starts_at, expires_at, state, ended_at, end_reason, updated_at)
					VALUES (?, ?, ?, ?, ?, ?, 'ro', '[]', 1, ?, ?, 'revoked', ?, 'lockdown', ?)`,
					gid, rid, did, f.agent.ID, f.srv.ID, f.role.ID, now-1, now+3600e6, now, now); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	f.clk.Advance(time.Second)
	// The live grant is revoked without an event.
	must(t, f.s.W().TxNamed(f.ctx, "test.silent_revoke", func(tx *store.Tx) error {
		_, err := tx.Q.EndGrant(f.ctx, db.EndGrantParams{State: GrantRevoked, Now: nullInt(tx.NowMicros()), EndReason: nullStr(ReasonOperator), ID: g.ID})
		return err
	}))
	for range 5 {
		must(t, e.reconcile(f.ctx))
		rec.mu.Lock()
		reason, done := rec.reasons[reg.ChannelID]
		rec.mu.Unlock()
		if done {
			if reason != ReasonOperator {
				t.Fatalf("reason %q", reason)
			}
			return
		}
		f.clk.Advance(time.Second)
	}
	t.Fatal("revoked grant's channel still live: safety net stalled on rows sharing one timestamp")
}

// SR-21 (HP-REC-011): a session served from a cached sequence block must not wait behind another session's block
// reservation stalled on the database write lock.
func TestSequencerCachedBlockIgnoresOtherSessionsStall(t *testing.T) {
	f := newFx(t)
	g1, g2 := f.grant(time.Hour), f.grant(time.Hour)
	_ = g1
	s1, err := f.s.R().GetSessionByGrant(f.ctx, g1.ID)
	must(t, err)
	s2, err := f.s.R().GetSessionByGrant(f.ctx, g2.ID)
	must(t, err)
	seq := f.svc.Sequencer()
	_, err = seq.Next(f.ctx, s2.ID, 1) // s2 now has a cached block
	must(t, err)

	d, err := sql.Open("sqlite", "file:"+f.s.Path(store.DBFile)+"?_txlock=immediate&_pragma=busy_timeout(10000)")
	must(t, err)
	tx, err := d.BeginTx(context.Background(), nil) // hold the write lock
	must(t, err)
	t.Cleanup(func() { _ = tx.Rollback(); _ = d.Close() })

	stalled := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		_, err := seq.Next(ctx, s1.ID, 1) // needs a reservation: blocks on the write lock
		stalled <- err
	}()
	time.Sleep(100 * time.Millisecond) // let the reservation start
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if _, err := seq.Next(ctx, s2.ID, 1); err != nil {
		t.Fatalf("cached allocation failed: %v", err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("cached allocation waited %s behind another session's stalled reservation", d)
	}
	if err := <-stalled; err == nil {
		t.Fatal("reservation succeeded while the write lock was held")
	}
}

// SR-21: a waiter for the same session's in-flight reservation honours its own deadline.
func TestSequencerWaiterHonoursDeadline(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	sess, err := f.s.R().GetSessionByGrant(f.ctx, g.ID)
	must(t, err)
	seq := f.svc.Sequencer()
	d, err := sql.Open("sqlite", "file:"+f.s.Path(store.DBFile)+"?_txlock=immediate&_pragma=busy_timeout(10000)")
	must(t, err)
	tx, err := d.BeginTx(context.Background(), nil)
	must(t, err)
	t.Cleanup(func() { _ = tx.Rollback(); _ = d.Close() })
	stalled := make(chan struct{})
	go func() {
		defer close(stalled)
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		_, _ = seq.Next(ctx, sess.ID, 1)
	}()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := seq.Next(ctx, sess.ID, 1); err == nil {
		t.Fatal("expected a deadline error while storage is stalled")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("waiter ignored its deadline: %s", d)
	}
	<-stalled
}

// SR-15 (HP-AGT-005, T-02): a connection authenticated with a key that has since been revoked cannot file requests
// (and so cannot receive auto-approved, agent-wide grants), even when the agent has another active key.
func TestCreateRequestRefusesRevokedKey(t *testing.T) {
	f := newFx(t)
	_, err := f.pol.CreateRule(f.ctx, admin, policy.Rule{Name: "auto", Effect: policy.EffectAllow, Level: policy.LevelAutoApprove,
		AutoMaxDuration: time.Hour, Enabled: true, Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}},
		Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	_, err = f.agents.AddKey(f.ctx, admin, f.agent.ID, newKeyLine(t))
	must(t, err)
	_, err = f.agents.RevokeKey(f.ctx, admin, f.agent.ID, f.keyID, "")
	must(t, err)
	_, err = f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: f.role.ID,
		Reason: "debug", Duration: 15 * time.Minute})
	if !errors.Is(err, ErrAccessEnded) {
		t.Fatalf("request with a revoked key: %v", err)
	}
	if n, _ := f.s.R().CountPendingAll(f.ctx); n != 0 {
		t.Fatal("request created")
	}
	_, err = f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: "agk_unknown", ServerID: f.srv.ID, RoleID: f.role.ID,
		Reason: "debug", Duration: 15 * time.Minute})
	if !errors.Is(err, ErrAccessEnded) {
		t.Fatalf("request with an unknown key: %v", err)
	}
}

// SR-32 (HP-GRT-009, HP-REQ-006) with SR-14: an owner-approver cannot approve its own agent's request but can deny
// it, and can cancel requests and revoke grants of that agent.
func TestOwnerApproverMayDenyCancelRevoke(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour) // approved before ownership is recorded
	must(t, f.pol.SetAgentOwners(f.ctx, admin, f.agent.ID, []string{f.approver.ID}))
	r := f.request("debug", 15*time.Minute)
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: f.approver, Channel: ChannelWeb}); err == nil {
		t.Fatal("owner approved own agent's request")
	}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: false, Operator: f.approver, Channel: ChannelWeb}); err != nil {
		t.Fatalf("owner cannot deny: %v", err)
	}
	r2 := f.request("debug again", 15*time.Minute)
	if _, err := f.svc.CancelByOperator(f.ctx, f.approver, r2.Request.ID); err != nil {
		t.Fatalf("owner cannot cancel: %v", err)
	}
	if _, err := f.svc.RevokeGrant(f.ctx, f.approver, g.ID, ""); err != nil {
		t.Fatalf("owner cannot revoke: %v", err)
	}
}

// SR-23 (G-5, HP-NTF-008): Decide re-reads the operator inside the transaction: a nonexistent or disabled operator,
// or roles the caller claims but no longer holds, never decide.
func TestDecideRereadsOperator(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	r := f.request("debug", 15*time.Minute)
	ghost := policy.OperatorInfo{ID: ids.New(ids.Operator), Roles: []string{"administrator"}, Enabled: true}
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: ghost, Channel: ChannelWeb}); !errors.Is(err, ErrOperatorUnavailable) {
		t.Fatalf("nonexistent operator decided: %v", err)
	}
	viewer := insertOperator(t, f.s, "viewer")
	_, err := f.pol.CreateApproverRule(f.ctx, admin, policy.ApproverRule{Name: "viewer-rule", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{viewer}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	claimed := policy.OperatorInfo{ID: viewer, Roles: []string{"approver"}, Enabled: true} // stale or forged roles
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: claimed, Channel: ChannelWeb}); err == nil {
		t.Fatal("operator decided with a role it does not hold")
	}
	must(t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(f.ctx, `UPDATE operators SET enabled = 0 WHERE id = ?`, f.approver.ID)
		return err
	}))
	if _, err := f.svc.Decide(f.ctx, DecideInput{RequestID: r.Request.ID, Approve: true, Operator: f.approver, Channel: ChannelWeb}); !errors.Is(err, ErrOperatorUnavailable) {
		t.Fatalf("disabled operator decided: %v", err)
	}
	if _, err := f.svc.CancelByOperator(f.ctx, f.approver, r.Request.ID); !errors.Is(err, ErrOperatorUnavailable) {
		t.Fatalf("disabled operator canceled: %v", err)
	}
	if _, err := f.svc.RevokeGrant(f.ctx, f.approver, g.ID, ""); !errors.Is(err, ErrOperatorUnavailable) {
		t.Fatalf("disabled operator revoked: %v", err)
	}
	if r2, _ := f.svc.GetRequest(f.ctx, r.Request.ID); r2.State != ReqPending {
		t.Fatalf("state %s", r2.State)
	}
}
