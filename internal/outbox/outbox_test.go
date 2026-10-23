package outbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

type fakeProvider struct {
	calls atomic.Int32
	fn    func(n int32, d Delivery) (Result, error)
	last  atomic.Value
}

func (f *fakeProvider) Deliver(_ context.Context, d Delivery) (Result, error) {
	n := f.calls.Add(1)
	f.last.Store(d)
	return f.fn(n, d)
}

func setup(t *testing.T) (*store.Store, *Outbox, context.Context) {
	t.Helper()
	s := storetest.Open(t)
	o := New(s, keyringtest.Load(t, s), Options{PollInterval: 10 * time.Millisecond, BaseBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return s, o, ctx
}

func enqueue(t *testing.T, s *store.Store, o *Outbox, m Message) string {
	t.Helper()
	var id string
	if err := s.W().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		id, err = o.Enqueue(context.Background(), tx, m)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func waitState(t *testing.T, s *store.Store, id, state string) db.OutboxMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m, err := s.R().GetOutboxMessage(context.Background(), id)
		if err == nil && m.State == state {
			return m
		}
		time.Sleep(5 * time.Millisecond)
	}
	m, _ := s.R().GetOutboxMessage(context.Background(), id)
	t.Fatalf("message %s did not reach %s: %+v", id, state, m)
	return m
}

func msg() Message {
	return Message{Provider: "fake", Destination: "C123", Kind: "request.pending", SubjectType: "request", SubjectID: "req_1", Body: []byte("approve me please")}
}

func TestDeliversAndRecordsAttempt(t *testing.T) {
	s, o, ctx := setup(t)
	p := &fakeProvider{fn: func(int32, Delivery) (Result, error) { return Result{ProviderRef: "ts-1", HTTPStatus: 200}, nil }}
	o.RegisterProvider("fake", p)
	go o.Run(ctx, 2)
	id := enqueue(t, s, o, msg())
	m := waitState(t, s, id, "delivered")
	if m.ProviderRef.String != "ts-1" || m.Attempts != 1 {
		t.Fatalf("%+v", m)
	}
	d := p.last.Load().(Delivery)
	if string(d.Body) != "approve me please" || d.SubjectID != "req_1" {
		t.Fatalf("delivery %+v", d)
	}
	atts, _ := s.R().ListDeliveryAttempts(context.Background(), id)
	if len(atts) != 1 || atts[0].Outcome != "delivered" || atts[0].HttpStatus.Int64 != 200 {
		t.Fatalf("attempts %+v", atts)
	}
}

// HP-NTF-001: bodies are encrypted at rest.
func TestBodyEncryptedAtRest(t *testing.T) {
	s, o, _ := setup(t)
	id := enqueue(t, s, o, msg())
	m, err := s.R().GetOutboxMessage(context.Background(), id)
	if err != nil || bytes.Contains(m.BodyEnc, []byte("approve me")) {
		t.Fatalf("plaintext body stored: %v", err)
	}
}

// HP-NTF-001, HP-NTF-010: bounded retries end in dead-letter with full attempt history.
func TestRetriesThenDead(t *testing.T) {
	s, o, ctx := setup(t)
	p := &fakeProvider{fn: func(int32, Delivery) (Result, error) { return Result{HTTPStatus: 503}, errors.New("unavailable") }}
	o.RegisterProvider("fake", p)
	go o.Run(ctx, 1)
	m := msg()
	m.MaxAttempts = 4
	id := enqueue(t, s, o, m)
	got := waitState(t, s, id, "dead")
	atts, _ := s.R().ListDeliveryAttempts(context.Background(), id)
	if got.Attempts != 4 || len(atts) != 4 || atts[3].Outcome != "failed" || atts[0].Outcome != "retry" {
		t.Fatalf("msg %+v attempts %+v", got, atts)
	}
}

func TestPermanentAndMissingProvider(t *testing.T) {
	s, o, ctx := setup(t)
	o.RegisterProvider("fake", &fakeProvider{fn: func(int32, Delivery) (Result, error) {
		return Result{HTTPStatus: 400}, fmt.Errorf("%w: channel not found", ErrPermanent)
	}})
	go o.Run(ctx, 1)
	if m := waitState(t, s, enqueue(t, s, o, msg()), "dead"); m.Attempts != 1 {
		t.Fatalf("permanent retried: %+v", m)
	}
	m := msg()
	m.Provider = "nobody"
	if got := waitState(t, s, enqueue(t, s, o, m), "dead"); got.LastError.String == "" {
		t.Fatal("missing provider error not recorded")
	}
}

func TestRetryThenDeliver(t *testing.T) {
	s, o, ctx := setup(t)
	o.RegisterProvider("fake", &fakeProvider{fn: func(n int32, _ Delivery) (Result, error) {
		if n < 3 {
			return Result{}, context.DeadlineExceeded
		}
		return Result{HTTPStatus: 200}, nil
	}})
	go o.Run(ctx, 1)
	id := enqueue(t, s, o, msg())
	waitState(t, s, id, "delivered")
	atts, _ := s.R().ListDeliveryAttempts(context.Background(), id)
	if len(atts) != 3 || atts[0].ErrorCode.String != "timeout" {
		t.Fatalf("%+v", atts)
	}
}

// A message left in 'sending' by a crashed process is reclaimed after its lease.
func TestCrashedSendReclaimed(t *testing.T) {
	s, o, ctx := setup(t)
	o.RegisterProvider("fake", &fakeProvider{fn: func(int32, Delivery) (Result, error) { return Result{}, nil }})
	id := enqueue(t, s, o, msg())
	if err := s.W().Exec(context.Background(), "UPDATE outbox_messages SET state='sending', attempts=1, lease_until=? WHERE id=?",
		time.Now().Add(-time.Second).UnixMicro(), id); err != nil {
		t.Fatal(err)
	}
	go o.Run(ctx, 1)
	if m := waitState(t, s, id, "delivered"); m.Attempts != 2 {
		t.Fatalf("%+v", m)
	}
}

func TestEnqueueValidation(t *testing.T) {
	s, o, _ := setup(t)
	err := s.W().Tx(context.Background(), func(tx *store.Tx) error {
		_, err := o.Enqueue(context.Background(), tx, Message{Provider: "x"})
		return err
	})
	if err == nil {
		t.Fatal("invalid message accepted")
	}
}
