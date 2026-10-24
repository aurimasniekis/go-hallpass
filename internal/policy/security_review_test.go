package policy

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// insertOperator creates a minimal operator row (owners must reference existing operators).
func insertOperator(t *testing.T, s *store.Store) string {
	t.Helper()
	id := ids.New(ids.Operator)
	if err := s.W().Tx(context.Background(), func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(context.Background(), `INSERT INTO operators (id, email, display_name, enabled, provisioned_via, created_at,
			created_by, updated_at) VALUES (?, ?, 'op', 1, 'admin', ?, 'test', ?)`, id, id+"@example.com", tx.NowMicros(), tx.NowMicros())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// SR-14 (HP-POL-012): owners are settable and readable through the service, validated against existing
// operators, and enforced by CanApprove.
func TestAgentOwnersManagement(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	owner, other := insertOperator(t, f.s), insertOperator(t, f.s)
	if err := f.svc.SetAgentOwners(ctx, admin, f.agent.ID, []string{ids.New(ids.Operator)}); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("unknown operator accepted as owner: %v", err)
	}
	if err := f.svc.SetAgentOwners(ctx, admin, "agt_missing", []string{owner}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
	if err := f.svc.SetAgentOwners(ctx, admin, f.agent.ID, []string{owner, other, owner}); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.AgentOwners(ctx, f.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{owner, other}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("owners %v, want %v", got, want)
	}
	if on, err := f.svc.ProhibitSelfApproval(ctx); err != nil || !on {
		t.Fatalf("self-approval prohibition default: %v %v", on, err)
	}
	_, err = f.svc.CreateApproverRule(ctx, admin, ApproverRule{Name: "all", Enabled: true, Operators: OperatorSelector{All: true},
		Targets: TargetSelector{All: true}, Roles: RoleSelector{All: true}})
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := f.svc.Engine().Current(ctx)
	op := OperatorInfo{ID: owner, Roles: []string{"approver"}, Enabled: true}
	if snap.CanApprove(op, f.agent.ID, f.srv.ID, f.role.ID, time.Hour).Allowed {
		t.Fatal("owner may approve own agent's request")
	}
	// SR-32 (HP-GRT-009, HP-REQ-006): the prohibition restricts approving only; owners may still deny, cancel and
	// revoke their agent's access.
	if !snap.CanAct(op, f.agent.ID, f.srv.ID, f.role.ID, 0).Allowed {
		t.Fatal("owner cannot deny, cancel or revoke own agent's access")
	}
	if err := f.svc.SetAgentOwners(ctx, admin, f.agent.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.svc.AgentOwners(ctx, f.agent.ID); len(got) != 0 {
		t.Fatalf("owners not cleared: %v", got)
	}
}
