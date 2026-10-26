// Package events publishes HallPass events to Pulse (NATS JetStream, ADR-0057).
//
// While events.pulse is enabled, every audit event and the lifecycle events of agent sessions are written to an outbox
// in the transaction of the change they describe. A relay publishes them after commit with the source event's ID as
// the CloudEvents ID and Nats-Msg-Id, so consumers can deduplicate retries. Pulse being down never blocks HallPass:
// events wait in the outbox, retry with capped exponential backoff and are dead-lettered after MaxAttempts attempts or
// MaxAge.
package events

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// SubjectPrefix starts every subject HallPass publishes (the Pulse grant is publish:evt.hallpass.>).
const SubjectPrefix = "evt.hallpass."

// Retention is how long outbox rows are kept, published or not.
const Retention = 7 * 24 * time.Hour

// Event is one event to publish.
type Event struct {
	// ID is the stable event ID (the audit or timeline event ID).
	ID string
	// Name is the dotted event name, e.g. "request.created" (see Subject).
	Name    string
	Payload any
}

// Recorder writes events to the outbox. A nil Recorder records nothing (publishing disabled).
type Recorder struct{}

// NewRecorder returns a Recorder, or nil when publishing is disabled.
func NewRecorder(enabled bool) *Recorder {
	if !enabled {
		return nil
	}
	return &Recorder{}
}

// Record stores ev inside tx; it is published once tx commits.
func (r *Recorder) Record(ctx context.Context, tx *store.Tx, ev Event) error {
	if r == nil {
		return nil
	}
	b, err := json.Marshal(ev.Payload)
	if err != nil {
		return err
	}
	subject, typ := Subject(ev.Name), Type(ev.Name)
	now := tx.NowMicros()
	return tx.Q.InsertEventOutbox(ctx, db.InsertEventOutboxParams{ID: ev.ID, Subject: subject, Type: typ, PayloadJson: string(b),
		CreatedAt: now, NextAttemptAt: now})
}

// Subject returns the subject of a dotted event name: "request.created" → evt.hallpass.request.created. Every token
// is reduced to [a-z0-9_-], and a one-token name gets ".recorded" so the subject has the four tokens Pulse requires.
func Subject(name string) string { return SubjectPrefix + tokens(name) }

// Type returns the CloudEvents type of a dotted event name: "request.created" → hallpass.request.created.v1.
func Type(name string) string { return "hallpass." + tokens(name) + ".v1" }

func tokens(name string) string {
	parts := strings.Split(strings.ToLower(name), ".")
	for i, p := range parts {
		p = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
				return r
			}
			return '_'
		}, p)
		if p == "" {
			p = "_"
		}
		parts[i] = p
	}
	if len(parts) == 1 {
		parts = append(parts, "recorded")
	}
	return strings.Join(parts, ".")
}

// Purge deletes outbox rows created before cutoff and returns how many.
func Purge(ctx context.Context, s *store.Store, cutoff time.Time) (int64, error) {
	var n int64
	err := s.W().TxNamed(ctx, "events.purge", func(tx *store.Tx) error {
		var err error
		n, err = tx.Q.PurgeEventOutbox(ctx, cutoff.UnixMicro())
		return err
	})
	return n, err
}
