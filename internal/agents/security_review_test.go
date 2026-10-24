package agents

import (
	"context"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
)

func ptrTo[T any](v T) *T { return &v }

// SR-12 (HP-POL-008): every agent change that bumps policy_version also publishes policy.changed, the topic the
// access service reconciles on; agent.changed alone has no reconciling subscriber.
func TestPolicyChangedOnAgentChanges(t *testing.T) {
	svc, _, bus := newSvc(t)
	ctx := context.Background()
	sub := bus.Subscribe(16, eventbus.TopicPolicyChanged)
	defer sub.Close()
	expect := func(what string) {
		t.Helper()
		select {
		case <-sub.C:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: policy.changed not published", what)
		}
	}
	a, err := svc.Create(ctx, admin, CreateInput{Name: "bot", Groups: []string{"sre"}})
	if err != nil {
		t.Fatal(err)
	}
	expect("create")
	if a, err = svc.Update(ctx, admin, a.ID, UpdateInput{Version: a.Version, Groups: ptrTo([]string{"other"})}); err != nil {
		t.Fatal(err)
	}
	expect("group change")
	if _, err = svc.Update(ctx, admin, a.ID, UpdateInput{Version: a.Version, Labels: ptrTo(map[string]string{"team": "x"})}); err != nil {
		t.Fatal(err)
	}
	expect("label change")
	if _, err := svc.SetEnabled(ctx, admin, a.ID, false, ""); err != nil {
		t.Fatal(err)
	}
	expect("disable")
}
