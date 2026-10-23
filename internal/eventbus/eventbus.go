// Package eventbus is an in-process publish/subscribe bus with bounded subscriber queues.
//
// The bus only reduces latency (e.g. waking a waiting SSH request or the enforcer). It is never the durability
// mechanism: every consumer that matters for security also reconciles from the database, because a slow subscriber's
// full queue drops events (counted in Dropped).
package eventbus

import (
	"slices"
	"sync"
	"sync/atomic"
)

// Event is a published message. Payloads must not contain secrets.
type Event struct {
	Topic   string
	Key     string // primary subject ID (request, grant, …)
	Payload any
}

// Bus fans events out to subscribers.
type Bus struct {
	mu   sync.RWMutex
	subs map[*Subscription]struct{}
}

// New returns an empty bus.
func New() *Bus { return &Bus{subs: map[*Subscription]struct{}{}} }

// Subscription receives events for its topics on C.
type Subscription struct {
	C       <-chan Event
	c       chan Event
	topics  []string
	bus     *Bus
	dropped atomic.Uint64
	once    sync.Once
}

// Subscribe registers for topics (an empty list means all topics) with a queue of size buffer (≥ 1).
func (b *Bus) Subscribe(buffer int, topics ...string) *Subscription {
	if buffer < 1 {
		buffer = 1
	}
	c := make(chan Event, buffer)
	s := &Subscription{C: c, c: c, topics: topics, bus: b}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// Close unsubscribes and closes C.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.bus.mu.Lock()
		delete(s.bus.subs, s)
		s.bus.mu.Unlock()
		close(s.c)
	})
}

// Dropped returns how many events were dropped because the queue was full.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

func (s *Subscription) wants(topic string) bool {
	return len(s.topics) == 0 || slices.Contains(s.topics, topic)
}

// Publish delivers ev to matching subscribers without blocking; full queues drop the event.
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if !s.wants(ev.Topic) {
			continue
		}
		select {
		case s.c <- ev:
		default:
			s.dropped.Add(1)
		}
	}
}
