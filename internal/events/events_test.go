package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-pulse/pkg/pulse"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/events"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

type published struct {
	subject, typ string
	data         json.RawMessage
}

type fakePub struct {
	mu    sync.Mutex
	fails int // remaining failures; -1 fails forever
	got   []published
}

func (f *fakePub) Publish(_ context.Context, subject, typ string, data any, opts ...pulse.PublishOption) (*pulse.PubAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails != 0 {
		if f.fails > 0 {
			f.fails--
		}
		return nil, errors.New("nats: no responders available for request")
	}
	f.got = append(f.got, published{subject: subject, typ: typ, data: data.(json.RawMessage)})
	return &pulse.PubAck{}, nil
}

type env struct {
	s     *store.Store
	clock *clock.Fake
	aw    *audit.Writer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	c := clock.NewFake(time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	s := storetest.Open(t, storetest.WithClock(c))
	e := &env{s: s, clock: c, aw: audit.NewWriter(keyringtest.Load(t, s))}
	e.aw.SetEvents(events.NewRecorder(true))
	return e
}

// auditN appends n audit events, each in its own transaction.
func (e *env) auditN(t *testing.T, n int) {
	t.Helper()
	for range n {
		if err := e.s.W().Tx(context.Background(), func(tx *store.Tx) error {
			_, err := e.aw.Append(context.Background(), tx, audit.Event{Actor: audit.System, Action: "server.updated",
				Target: audit.Target{Type: "server", ID: "srv_1"}, Details: map[string]any{"changed": []string{"name"}},
				Sensitive: map[string]any{"note": "sealed-note-text"}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *env) backlog(t *testing.T) (pending, dead int64) {
	t.Helper()
	c, err := e.s.R().CountEventOutbox(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c.Pending, c.Dead
}

func (e *env) relay(pub events.Publisher) *events.Relay {
	return &events.Relay{Store: e.s, Pub: pub, Clock: e.clock, Log: slog.New(slog.DiscardHandler)}
}

func TestSubjectAndType(t *testing.T) {
	for _, c := range []struct{ name, subject, typ string }{
		{"request.created", "evt.hallpass.request.created", "hallpass.request.created.v1"},
		{"session.channel.opened", "evt.hallpass.session.channel.opened", "hallpass.session.channel.opened.v1"},
		{"lockdown", "evt.hallpass.lockdown.recorded", "hallpass.lockdown.recorded.v1"},
		{"Odd Name..x>*", "evt.hallpass.odd_name._.x__", "hallpass.odd_name._.x__.v1"},
	} {
		if s, ty := events.Subject(c.name), events.Type(c.name); s != c.subject || ty != c.typ {
			t.Errorf("%q: got %s %s", c.name, s, ty)
		}
	}
}

func TestDisabledRecordsNothing(t *testing.T) {
	e := newEnv(t)
	e.aw.SetEvents(events.NewRecorder(false))
	e.auditN(t, 2)
	if p, d := e.backlog(t); p != 0 || d != 0 {
		t.Fatalf("pending %d dead %d", p, d)
	}
}

// An audit event is published with its audit ID, subject, type and the audit record as payload, never the sealed
// sensitive details.
func TestAuditEventPayload(t *testing.T) {
	e := newEnv(t)
	e.auditN(t, 1)
	pub := &fakePub{}
	if n, failed, err := e.relay(pub).Once(context.Background()); err != nil || n != 1 || failed != 0 {
		t.Fatalf("published %d failed %d err %v", n, failed, err)
	}
	got := pub.got[0]
	if got.subject != "evt.hallpass.server.updated" || got.typ != "hallpass.server.updated.v1" {
		t.Fatalf("published %+v", got)
	}
	var rec audit.Record
	if err := json.Unmarshal(got.data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Action != "server.updated" || rec.Seq != 1 || rec.TargetID != "srv_1" || rec.ActorType != audit.ActorSystem || rec.Details["changed"] == nil ||
		!rec.HasSensitive {
		t.Fatalf("record %+v", rec)
	}
	if strings.Contains(string(got.data), "sealed-note-text") {
		t.Fatalf("sensitive details published: %s", got.data)
	}
	if p, _ := e.backlog(t); p != 0 {
		t.Fatalf("pending %d after publishing", p)
	}
}

// Pulse being down never loses events: they retry with backoff and publish once Pulse is back.
func TestRelayRetriesThenPublishes(t *testing.T) {
	e := newEnv(t)
	e.auditN(t, 3)
	pub := &fakePub{fails: 2}
	r := e.relay(pub)
	ctx := context.Background()
	if n, failed, err := r.Once(ctx); err != nil || n != 0 || failed != 1 {
		t.Fatalf("first round %d %d %v", n, failed, err)
	}
	for range 10 {
		e.clock.Advance(10 * time.Second)
		if _, _, err := r.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if p, d := e.backlog(t); p != 0 || d != 0 || len(pub.got) != 3 {
		t.Fatalf("pending %d dead %d published %d of 3", p, d, len(pub.got))
	}
}

func TestRelayDeadLetters(t *testing.T) {
	e := newEnv(t)
	e.auditN(t, 2)
	r := e.relay(&fakePub{fails: -1})
	ctx := context.Background()
	if _, _, err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(events.MaxAge + time.Minute)
	for range 3 {
		if _, _, err := r.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if p, d := e.backlog(t); p != 0 || d != 2 {
		t.Fatalf("pending %d dead %d", p, d)
	}
}

func TestPurge(t *testing.T) {
	e := newEnv(t)
	e.auditN(t, 2)
	e.clock.Advance(events.Retention + time.Hour)
	e.auditN(t, 1)
	n, err := events.Purge(context.Background(), e.s, e.clock.Now().Add(-events.Retention))
	if err != nil || n != 2 {
		t.Fatalf("purged %d %v", n, err)
	}
	if p, _ := e.backlog(t); p != 1 {
		t.Fatalf("pending %d", p)
	}
}

// Against a real NATS JetStream server through the Pulse SDK: events keep their ID (Nats-Msg-Id), CloudEvents type
// and source, and a re-publish of the same event is deduplicated by JetStream.
func TestRelayJetStream(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats not ready")
	}
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	ctx := context.Background()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: pulse.DefaultStream, Subjects: []string{"evt.>"}, Duplicates: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	pc, err := pulse.New(nc, "hallpass")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.auditN(t, 2)
	if n, failed, err := e.relay(pc).Once(ctx); err != nil || failed != 0 || n != 2 {
		t.Fatalf("published %d failed %d err %v", n, failed, err)
	}
	cons, err := js.OrderedConsumer(ctx, pulse.DefaultStream, jetstream.OrderedConsumerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var first nats.Header
	for i := range 2 {
		m, err := cons.Next(jetstream.FetchMaxWait(5 * time.Second))
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		h := m.Headers()
		if m.Subject() != "evt.hallpass.server.updated" || h.Get("ce-source") != "hallpass" || h.Get("ce-type") != "hallpass.server.updated.v1" ||
			len(h.Get("Nats-Msg-Id")) < 4 || h.Get("Nats-Msg-Id")[:4] != "aud_" {
			t.Fatalf("message %s %v", m.Subject(), h)
		}
		if first == nil {
			first = h
		}
	}
	// A crash between publishing and marking publishes again with the same ID: JetStream drops the duplicate.
	ack, err := pc.Publish(ctx, "evt.hallpass.server.updated", first.Get("ce-type"), map[string]any{}, pulse.WithID(first.Get("Nats-Msg-Id")))
	if err != nil || !ack.Duplicate {
		t.Fatalf("duplicate not detected: %+v %v", ack, err)
	}
}
