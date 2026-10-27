package access

import (
	"testing"
	"time"
)

// Grants belong to the agent session that asked: another session of the same agent neither sees nor uses them,
// files its own request, and cannot open a channel under them. "" is the shared default session.
func TestAgentSessionsAreSeparate(t *testing.T) {
	f := newFx(t)
	req := func(session string) *CreateResult {
		t.Helper()
		res, err := f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID, RoleID: f.role.ID,
			Reason: "check disks", Duration: 30 * time.Minute, AgentSession: session})
		must(t, err)
		return res
	}
	a := req("claude-a")
	if a.Request.AgentSession != "claude-a" {
		t.Fatalf("request session %q", a.Request.AgentSession)
	}
	b := req("claude-b")
	if b.Deduplicated || b.Request.ID == a.Request.ID {
		t.Fatal("another session's pending request was reused")
	}
	if again := req("claude-a"); !again.Deduplicated || again.Request.ID != a.Request.ID {
		t.Fatal("the same session's pending request was not reused")
	}
	g := f.approve(a.Request.ID, 0).Grant
	if g.AgentSession != "claude-a" {
		t.Fatalf("grant session %q", g.AgentSession)
	}
	if got, err := f.svc.FindActiveGrant(f.ctx, f.agent.ID, "claude-b", f.srv.ID, f.role.ID); err != nil || got != nil {
		t.Fatalf("session b found session a's grant: %v %v", got, err)
	}
	if got, err := f.svc.FindActiveGrant(f.ctx, f.agent.ID, "", f.srv.ID, f.role.ID); err != nil || got != nil {
		t.Fatalf("the default session found session a's grant: %v %v", got, err)
	}
	if got, err := f.svc.FindActiveGrant(f.ctx, f.agent.ID, "claude-a", f.srv.ID, f.role.ID); err != nil || got == nil || got.ID != g.ID {
		t.Fatalf("session a lost its grant: %v %v", got, err)
	}
	if gs, _ := f.svc.ActiveGrantsForAgent(f.ctx, f.agent.ID, "claude-b"); len(gs) != 0 {
		t.Fatalf("session b lists %d grants", len(gs))
	}
	conn := f.conn()
	if _, err := f.svc.RegisterChannel(f.ctx, RegisterInput{ConnectionID: conn, AgentID: f.agent.ID, KeyID: f.keyID, GrantID: g.ID,
		Kind: KindExec, AgentSession: "claude-b"}); !IsNotFoundOrForbidden(err) {
		t.Fatalf("session b opened a channel under session a's grant: %v", err)
	}
	if _, err := f.svc.RegisterChannel(f.ctx, RegisterInput{ConnectionID: conn, AgentID: f.agent.ID, KeyID: f.keyID, GrantID: g.ID,
		Kind: KindExec, AgentSession: "claude-a"}); err != nil {
		t.Fatalf("session a: %v", err)
	}
	if _, err := f.svc.CreateRequest(f.ctx, CreateRequestInput{AgentID: f.agent.ID, KeyID: f.keyID, ServerID: f.srv.ID,
		RoleID: f.role.ID, Reason: "x", AgentSession: "bad session"}); err == nil {
		t.Fatal("an invalid session name was accepted")
	}
}
