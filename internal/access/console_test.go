package access

import (
	"errors"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

func (f *fx) consoleConn(opID string) string {
	f.t.Helper()
	id, err := f.svc.OpenConnection(f.ctx, ConnectionInfo{AgentID: ConsoleAgentID, KeyID: ConsoleKeyID, OperatorID: opID, ClientUser: "admin@example.com",
		ClientVersion: "hallpass-web-terminal", SourceIP: "198.51.100.7"})
	must(f.t, err)
	return id
}

func (f *fx) consoleRegister(conn, grantID, opID string) (*ChannelReg, error) {
	return f.svc.RegisterChannel(f.ctx, RegisterInput{ConnectionID: conn, AgentID: ConsoleAgentID, KeyID: ConsoleKeyID, GrantID: grantID, Kind: KindShell,
		PTY: true, OperatorID: opID})
}

func setRoles(t *testing.T, s *store.Store, opID string, roles ...string) {
	t.Helper()
	must(t, s.W().Tx(t.Context(), func(tx *store.Tx) error {
		if _, err := tx.SQL.ExecContext(t.Context(), `DELETE FROM operator_roles WHERE operator_id = ?`, opID); err != nil {
			return err
		}
		for _, r := range roles {
			if _, err := tx.SQL.ExecContext(t.Context(), `INSERT INTO operator_roles (operator_id, role, source) VALUES (?, ?, 'manual')`, opID, r); err != nil {
				return err
			}
		}
		return nil
	}))
}

// ADR-0055: an administrator's web terminal is a self-approved grant for the built-in agent, independent of agent
// policy, revalidated on every channel open, and ended by lockdown, disabled targets and loss of the role.
func TestConsoleTerminal(t *testing.T) {
	f := newFx(t)
	adminID := insertOperator(t, f.s, "administrator")
	viewerID := insertOperator(t, f.s, "viewer")
	// An agent deny rule covering everything does not affect web terminals.
	_, err := f.pol.CreateRule(f.ctx, admin, policy.Rule{Name: "deny-all", Effect: policy.EffectDeny, Enabled: true,
		Subjects: policy.SubjectSelector{All: true}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	open := func(op string, dur time.Duration) (*Grant, error) {
		return f.svc.OpenConsole(f.ctx, OpenConsoleInput{Operator: policy.OperatorInfo{ID: op}, ServerID: f.srv.ID, RoleID: f.role.ID, Duration: dur})
	}
	if _, err := open(viewerID, time.Hour); !errors.Is(err, ErrConsoleOperator) {
		t.Fatalf("viewer opened a terminal: %v", err)
	}
	if _, err := open(adminID, 2*time.Hour); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("duration outside the presets: %v", err)
	}
	g, err := open(adminID, time.Hour)
	must(t, err)
	if g.AgentID != ConsoleAgentID || g.OperatorID != adminID || !g.Console() || g.SessionID == "" || g.ExpiresAt.Sub(g.StartsAt) != time.Hour {
		t.Fatalf("grant %+v", g)
	}
	req, err := f.svc.GetRequest(f.ctx, g.RequestID)
	must(t, err)
	if req.State != ReqApproved || req.OperatorID != adminID {
		t.Fatalf("request %+v", req)
	}
	dec, err := f.s.R().GetDecisionByRequest(f.ctx, g.RequestID)
	must(t, err)
	if dec.Channel != ChannelConsole || dec.ActorID != adminID {
		t.Fatalf("decision %+v", dec)
	}

	conn := f.consoleConn(adminID)
	reg, err := f.consoleRegister(conn, g.ID, adminID)
	must(t, err)
	must(t, f.svc.CloseChannel(f.ctx, reg, CloseInfo{Reason: "exit_status"}))
	if _, err := f.consoleRegister(conn, g.ID, viewerID); !IsNotFoundOrForbidden(err) {
		t.Fatalf("another operator used the terminal: %v", err)
	}
	if _, err := f.svc.RegisterChannel(f.ctx, RegisterInput{ConnectionID: conn, AgentID: ConsoleAgentID, KeyID: ConsoleKeyID, GrantID: g.ID, Kind: KindShell}); !IsNotFoundOrForbidden(err) {
		t.Fatalf("agent-style use of a terminal grant: %v", err)
	}
	// Policy reconciliation leaves the terminal alone although no agent rule allows it.
	_, revoked, _, err := f.svc.ReconcilePolicy(f.ctx)
	must(t, err)
	if g2, _ := f.svc.GetGrant(f.ctx, g.ID); g2.State != GrantActive {
		t.Fatalf("reconciliation revoked the terminal (%d revoked): %+v", revoked, g2)
	}

	// Losing the administrator role ends it.
	setRoles(t, f.s, adminID, "viewer")
	if _, err := f.consoleRegister(conn, g.ID, adminID); !errors.Is(err, ErrAccessEnded) {
		t.Fatalf("channel for a former administrator: %v", err)
	}
	n, err := f.svc.RevokeIneligibleConsoleGrants(f.ctx)
	must(t, err)
	if g2, _ := f.svc.GetGrant(f.ctx, g.ID); n != 1 || g2.State != GrantRevoked || g2.EndReason != ReasonOperatorIneligible {
		t.Fatalf("after role loss: %d %+v", n, g2)
	}
	setRoles(t, f.s, adminID, "administrator")

	// Closing the browser ends the grant.
	g3, err := open(adminID, 0)
	must(t, err)
	must(t, f.svc.CloseConsole(f.ctx, g3.ID, viewerID)) // not theirs: no effect
	if g4, _ := f.svc.GetGrant(f.ctx, g3.ID); g4.State != GrantActive {
		t.Fatalf("another operator closed the terminal: %+v", g4)
	}
	must(t, f.svc.CloseConsole(f.ctx, g3.ID, adminID))
	if g4, _ := f.svc.GetGrant(f.ctx, g3.ID); g4.State != GrantRevoked || g4.EndReason != ReasonTerminalClosed {
		t.Fatalf("after close: %+v", g4)
	}

	// Disabling the role revokes open terminals and refuses new ones.
	g5, err := open(adminID, time.Hour)
	must(t, err)
	_, err = f.inv.SetRoleEnabled(f.ctx, admin, f.role.ID, false)
	must(t, err)
	if g6, _ := f.svc.GetGrant(f.ctx, g5.ID); g6.State != GrantRevoked {
		t.Fatalf("disabled role kept the terminal: %+v", g6)
	}
	if _, err := open(adminID, time.Hour); !IsNotFoundOrForbidden(err) {
		t.Fatalf("terminal on a disabled role: %v", err)
	}
	_, err = f.inv.SetRoleEnabled(f.ctx, admin, f.role.ID, true)
	must(t, err)

	// Lockdown refuses terminals.
	must(t, f.svc.SetLockdown(f.ctx, admin, true))
	if _, err := open(adminID, time.Hour); !errors.Is(err, ErrLockdown) {
		t.Fatalf("terminal during lockdown: %v", err)
	}
	must(t, f.svc.SetLockdown(f.ctx, admin, false))

	// A role without pty cannot host a terminal.
	role, err := f.inv.CreateRole(f.ctx, admin, f.srv.ID, inventory.RoleInput{Alias: ptr("batch"), RemoteUser: ptr("batch"),
		Capabilities: ptr([]string{inventory.CapExec})})
	must(t, err)
	if _, err := f.svc.OpenConsole(f.ctx, OpenConsoleInput{Operator: policy.OperatorInfo{ID: adminID}, ServerID: f.srv.ID, RoleID: role.ID}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("terminal on an exec-only role: %v", err)
	}

	// The built-in agent is never listed.
	list, err := f.agents.List(f.ctx)
	must(t, err)
	for _, a := range list {
		if a.ID == ConsoleAgentID {
			t.Fatal("web terminal agent listed")
		}
	}
}
