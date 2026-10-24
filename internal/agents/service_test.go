package agents

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func newSvc(t *testing.T) (*Service, *store.Store, *eventbus.Bus) {
	t.Helper()
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	bus := eventbus.New()
	return New(s, kr, audit.NewWriter(kr), bus, nil), s, bus
}

func policyVersion(t *testing.T, s *store.Store) int64 {
	ps, err := s.R().GetPolicyState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ps.Version
}

func TestCreateGetList(t *testing.T) {
	svc, s, _ := newSvc(t)
	ctx := context.Background()
	k := sshkeys.Ed25519(t)
	v0 := policyVersion(t, s)
	a, err := svc.Create(ctx, admin, CreateInput{
		Name: "ci-bot", Description: "CI runner", SourceCIDRs: []string{"10.1.2.3/16"},
		Groups: []string{"sre-bots", "ci"}, Labels: map[string]string{"team": "sre"}, PublicKeys: []string{k.AuthorizedLine("ci")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Enabled || a.SourceCIDRs[0] != "10.1.0.0/16" || len(a.Groups) != 2 || a.Groups[0] != "ci" || a.Labels["team"] != "sre" {
		t.Fatalf("%+v", a)
	}
	if policyVersion(t, s) <= v0 {
		t.Fatal("policy version not bumped (HP-POL-007)")
	}
	keys, _ := svc.Keys(ctx, a.ID)
	if len(keys) != 1 || keys[0].Fingerprint != k.Fingerprint() || keys[0].Comment != "ci" {
		t.Fatalf("%+v", keys)
	}
	if _, err := svc.Create(ctx, admin, CreateInput{Name: "ci-bot"}); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	list, _ := svc.List(ctx)
	if len(list) != 1 || list[0].Groups[1] != "sre-bots" {
		t.Fatalf("%+v", list)
	}
	if _, err := svc.Get(ctx, "agt_missing"); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestValidation(t *testing.T) {
	svc, _, _ := newSvc(t)
	_, err := svc.Create(context.Background(), admin, CreateInput{
		Name: "Bad Name", SourceCIDRs: []string{"nope"}, Groups: []string{"UPPER"}, Labels: map[string]string{"bad key": "v"},
		PublicKeys: []string{"garbage"},
	})
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Code != apperr.CodeInvalid || len(ae.Fields) < 5 {
		t.Fatalf("%v", err)
	}
}

// HP-AGT-003: a key can never belong to two agents, even after revocation.
func TestKeyUniquenessAcrossAgents(t *testing.T) {
	svc, _, _ := newSvc(t)
	ctx := context.Background()
	k := sshkeys.Ed25519(t)
	a, _ := svc.Create(ctx, admin, CreateInput{Name: "a", PublicKeys: []string{k.AuthorizedLine("")}})
	b, _ := svc.Create(ctx, admin, CreateInput{Name: "b"})
	if _, err := svc.AddKey(ctx, admin, b.ID, k.AuthorizedLine("")); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatalf("shared key accepted: %v", err)
	}
	keys, _ := svc.Keys(ctx, a.ID)
	if _, err := svc.RevokeKey(ctx, admin, a.ID, keys[0].ID, "rotated"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddKey(ctx, admin, b.ID, k.AuthorizedLine("")); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatalf("revoked (tombstoned) key reassigned: %v", err)
	}
	if _, err := svc.AddKey(ctx, admin, a.ID, k.AuthorizedLine("")); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatalf("revoked key re-added: %v", err)
	}
}

// HP-SSH-002/003, HP-AGT-005/007/008: identity from key; unknown, revoked, disabled and source-denied all fail.
func TestAuthenticate(t *testing.T) {
	svc, _, _ := newSvc(t)
	ctx := context.Background()
	k1, k2, unknown := sshkeys.Ed25519(t), sshkeys.ECDSA256(t), sshkeys.Ed25519(t)
	a, _ := svc.Create(ctx, admin, CreateInput{Name: "bot", SourceCIDRs: []string{"192.0.2.0/24"},
		PublicKeys: []string{k1.AuthorizedLine(""), k2.AuthorizedLine("")}})
	in, out := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.1")
	id, err := svc.Authenticate(ctx, k1.Public, in)
	if err != nil || id.AgentID != a.ID || id.Fingerprint != k1.Fingerprint() {
		t.Fatalf("%+v %v", id, err)
	}
	if _, err := svc.Authenticate(ctx, k1.Public, netip.MustParseAddr("::ffff:192.0.2.11")); err != nil {
		t.Fatalf("IPv4-mapped source rejected: %v", err)
	}
	reason := func(_ *Identity, err error) string {
		var ae *AuthError
		if !errors.As(err, &ae) || !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("not an AuthError: %v", err)
		}
		return ae.Reason
	}
	if r := reason(svc.Authenticate(ctx, unknown.Public, in)); r != FailUnknownKey {
		t.Fatal(r)
	}
	if r := reason(svc.Authenticate(ctx, k1.Public, out)); r != FailSourceDenied {
		t.Fatal(r)
	}
	if r := reason(svc.Authenticate(ctx, sshkeys.RSA(t, 2048).Public, in)); r != FailKeyPolicy {
		t.Fatal(r)
	}
	keys, _ := svc.Keys(ctx, a.ID)
	if _, err := svc.RevokeKey(ctx, admin, a.ID, keys[0].ID, ""); err != nil {
		t.Fatal(err)
	}
	if r := reason(svc.Authenticate(ctx, k1.Public, in)); r != FailRevokedKey {
		t.Fatal(r)
	}
	if _, err := svc.Authenticate(ctx, k2.Public, in); err != nil {
		t.Fatalf("other key should still work: %v", err)
	}
	if _, err := svc.SetEnabled(ctx, admin, a.ID, false, "compromised"); err != nil {
		t.Fatal(err)
	}
	if r := reason(svc.Authenticate(ctx, k2.Public, in)); r != FailAgentDisabled {
		t.Fatal(r)
	}
}

func TestHooksRunInsideTransaction(t *testing.T) {
	svc, _, bus := newSvc(t)
	ctx := context.Background()
	sub := bus.Subscribe(10)
	var calls []string
	svc.OnDisable(func(_ context.Context, tx *store.Tx, agentID, keyID, reason string) error {
		calls = append(calls, "disable:"+agentID+":"+reason)
		return nil
	})
	fail := errors.New("hook failure")
	svc.OnKeyRevoke(func(_ context.Context, tx *store.Tx, agentID, keyID, reason string) error {
		calls = append(calls, "revoke:"+keyID)
		return fail
	})
	k := sshkeys.Ed25519(t)
	a, _ := svc.Create(ctx, admin, CreateInput{Name: "bot", PublicKeys: []string{k.AuthorizedLine("")}})
	keys, _ := svc.Keys(ctx, a.ID)
	if _, err := svc.RevokeKey(ctx, admin, a.ID, keys[0].ID, ""); !errors.Is(err, fail) {
		t.Fatalf("hook error not propagated: %v", err)
	}
	if keys, _ = svc.Keys(ctx, a.ID); keys[0].State != "active" {
		t.Fatal("revocation committed despite hook failure")
	}
	if _, err := svc.SetEnabled(ctx, admin, a.ID, false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetEnabled(ctx, admin, a.ID, false, ""); err != nil {
		t.Fatal("idempotent disable failed")
	}
	if len(calls) != 2 || !strings.HasPrefix(calls[1], "disable:"+a.ID) {
		t.Fatalf("calls %v", calls)
	}
	var topics []string
	for len(sub.C) > 0 {
		topics = append(topics, (<-sub.C).Topic)
	}
	if topics[len(topics)-1] != eventbus.TopicAgentDisabled {
		t.Fatalf("topics %v", topics)
	}
}

func TestUpdateOptimisticConcurrency(t *testing.T) {
	svc, _, _ := newSvc(t)
	ctx := context.Background()
	a, _ := svc.Create(ctx, admin, CreateInput{Name: "bot", Groups: []string{"g1"}})
	desc := "new"
	g := []string{"g2"}
	b, err := svc.Update(ctx, admin, a.ID, UpdateInput{Version: a.Version, Description: &desc, Groups: &g})
	if err != nil || b.Description != "new" || b.Groups[0] != "g2" || b.Version != a.Version+1 {
		t.Fatalf("%+v %v", b, err)
	}
	if _, err := svc.Update(ctx, admin, a.ID, UpdateInput{Version: a.Version, Description: &desc}); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("stale update accepted: %v", err)
	}
}

func TestAuditTrail(t *testing.T) {
	svc, s, _ := newSvc(t)
	ctx := context.Background()
	a, _ := svc.Create(ctx, audit.Actor{Type: audit.ActorOperator, ID: "opr_1"}, CreateInput{Name: "bot", PublicKeys: []string{sshkeys.Ed25519(t).AuthorizedLine("")}})
	keys, _ := svc.Keys(ctx, a.ID)
	_, _ = svc.RevokeKey(ctx, admin, a.ID, keys[0].ID, "lost laptop")
	res, err := audit.Verify(ctx, s.R())
	if err != nil || !res.OK || res.Events != 3 {
		t.Fatalf("%+v %v", res, err)
	}
}

// Deleting an agent ends its access through the disable hooks, revokes its keys for good, hides it, refuses further
// changes and frees the name; history still reads it by ID under its former name.
func TestDelete(t *testing.T) {
	svc, _, _ := newSvc(t)
	ctx := context.Background()
	var disabled []string
	svc.OnDisable(func(_ context.Context, _ *store.Tx, agentID, _, reason string) error {
		disabled = append(disabled, agentID+":"+reason)
		return nil
	})
	k := sshkeys.Ed25519(t)
	a, err := svc.Create(ctx, admin, CreateInput{Name: "ci-bot", PublicKeys: []string{k.AuthorizedLine("ci")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, admin, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, admin, a.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if len(disabled) != 1 || disabled[0] != a.ID+":agent_disabled" {
		t.Fatalf("disable hooks: %v", disabled)
	}
	got, err := svc.Get(ctx, a.ID)
	if err != nil || !got.Deleted() || got.Name != "ci-bot" || got.Enabled {
		t.Fatalf("deleted agent: %+v %v", got, err)
	}
	if keys, _ := svc.Keys(ctx, a.ID); len(keys) != 1 || keys[0].State != "revoked" {
		t.Fatalf("keys: %+v", keys)
	}
	if list, _ := svc.List(ctx); len(list) != 0 {
		t.Fatalf("deleted agent listed: %+v", list)
	}
	if all, _ := svc.ListWithDeleted(ctx); len(all) != 1 || all[0].Name != "ci-bot" {
		t.Fatalf("with deleted: %+v", all)
	}
	if _, err := svc.Update(ctx, admin, a.ID, UpdateInput{Version: got.Version, Description: ptrTo("x")}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update of a deleted agent: %v", err)
	}
	if _, err := svc.SetEnabled(ctx, admin, a.ID, true, ""); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("enabling a deleted agent: %v", err)
	}
	if _, err := svc.AddKey(ctx, admin, a.ID, sshkeys.Ed25519(t).AuthorizedLine("")); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("key for a deleted agent: %v", err)
	}
	// The name is free again; the revoked key stays unusable (HP-AGT-003).
	if _, err := svc.Create(ctx, admin, CreateInput{Name: "ci-bot", PublicKeys: []string{k.AuthorizedLine("ci")}}); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatalf("revoked key accepted again: %v", err)
	}
	if _, err := svc.Create(ctx, admin, CreateInput{Name: "ci-bot"}); err != nil {
		t.Fatalf("name not reusable: %v", err)
	}
}
