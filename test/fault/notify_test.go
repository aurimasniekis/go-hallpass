//go:build fault

package fault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/outbox"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// failingProvider fails every delivery like a chat API under outage: 5xx, timeout, then 429.
type failingProvider struct{ calls atomic.Int64 }

func (p *failingProvider) Deliver(context.Context, outbox.Delivery) (outbox.Result, error) {
	switch p.calls.Add(1) {
	case 1:
		return outbox.Result{HTTPStatus: 502}, errors.New("chat api: 502 bad gateway")
	case 2:
		return outbox.Result{}, fmt.Errorf("chat api: %w", context.DeadlineExceeded)
	default:
		return outbox.Result{HTTPStatus: 429}, errors.New("chat api: 429 rate limited")
	}
}

// FI-18 (outbox layer): a chat provider that keeps failing (5xx, timeout, 429) is retried with backoff until the
// message is dead; every attempt is recorded, and the pending request is never approved by the failure
// (HP-NTF-001, HP-NTF-010). The Slack and Telegram clients' own classification of API errors is unit-tested in
// internal/notify/slack and internal/notify/telegram.
func TestFI18ChatProviderOutage(t *testing.T) {
	w := newWorld(t)
	w.setup(t, 0, requestable(t))
	g := w.start(t)
	out, errOut, code := g.run("request web1 --role inspect --reason 'disk alert' --no-wait --json")
	if code != 0 {
		t.Fatalf("request: %d %q", code, errOut)
	}
	var doc struct{ Request struct{ ID string } }
	must(t, json.Unmarshal([]byte(out), &doc))
	p := &failingProvider{}
	g.a.Outbox.RegisterProvider("fault", p)
	ctx := context.Background()
	var msgID string
	must(t, g.a.Store.W().Tx(ctx, func(tx *store.Tx) error {
		var err error
		msgID, err = g.a.Outbox.Enqueue(ctx, tx, outbox.Message{Provider: "fault", Destination: "C0123", Kind: "request.pending",
			SubjectType: "request", SubjectID: doc.Request.ID, Body: []byte(`{"text":"approve?"}`), MaxAttempts: 3})
		return err
	}))
	d := g.a.Store.ReadDB()
	start := time.Now()
	if !eventually(60*time.Second, func() bool {
		return queryStr(t, d, `SELECT state FROM outbox_messages WHERE id = ?`, msgID) == "dead"
	}) {
		t.Fatalf("message not dead-lettered: state %q after %d calls", queryStr(t, d, `SELECT state FROM outbox_messages WHERE id = ?`, msgID), p.calls.Load())
	}
	t.Logf("dead-lettered after %s and %d attempts (backoff between attempts)", time.Since(start).Round(100*time.Millisecond), p.calls.Load())
	rows, err := d.QueryContext(ctx, `SELECT outcome, coalesce(http_status, 0) FROM delivery_attempts WHERE outbox_id = ? ORDER BY id`, msgID)
	must(t, err)
	defer rows.Close()
	var attempts []string
	for rows.Next() {
		var o string
		var s int
		must(t, rows.Scan(&o, &s))
		attempts = append(attempts, fmt.Sprintf("%s/%d", o, s))
	}
	must(t, rows.Err())
	if got := strings.Join(attempts, ","); got != "retry/502,retry/0,failed/429" {
		t.Fatalf("delivery history %q", got)
	}
	if st := queryStr(t, d, `SELECT state FROM access_requests WHERE id = ?`, doc.Request.ID); st != "pending" {
		t.Fatalf("request state %q after notification failure, want pending", st)
	}
}
