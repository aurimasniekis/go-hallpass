package eventbus

import "testing"

func TestPublishSubscribe(t *testing.T) {
	b := New()
	all := b.Subscribe(10)
	grants := b.Subscribe(10, "grant.revoked")
	b.Publish(Event{Topic: "request.created", Key: "req_1"})
	b.Publish(Event{Topic: "grant.revoked", Key: "grt_1"})
	if len(all.C) != 2 || len(grants.C) != 1 {
		t.Fatalf("all=%d grants=%d", len(all.C), len(grants.C))
	}
	if ev := <-grants.C; ev.Key != "grt_1" {
		t.Fatal(ev)
	}
	grants.Close()
	grants.Close() // idempotent
	b.Publish(Event{Topic: "grant.revoked"})
	if _, ok := <-grants.C; ok {
		t.Fatal("closed subscription received")
	}
}

func TestFullQueueDrops(t *testing.T) {
	b := New()
	s := b.Subscribe(1)
	for range 5 {
		b.Publish(Event{Topic: "x"})
	}
	if s.Dropped() != 4 || len(s.C) != 1 {
		t.Fatalf("dropped=%d len=%d", s.Dropped(), len(s.C))
	}
}
