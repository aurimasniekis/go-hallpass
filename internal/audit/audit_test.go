package audit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

func setup(t *testing.T) (*store.Store, *Writer) {
	s := storetest.Open(t)
	return s, NewWriter(keyringtest.Load(t, s))
}

func appendN(t *testing.T, s *store.Store, w *Writer, n int) {
	t.Helper()
	ctx := context.Background()
	for i := range n {
		err := s.W().Tx(ctx, func(tx *store.Tx) error {
			_, err := w.Append(ctx, tx, Event{
				Actor: Actor{Type: ActorOperator, ID: "opr_x"}, Action: "agent.created",
				Target: Target{Type: "agent", ID: "agt_x"}, Details: map[string]any{"i": i, "name": "bot"},
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifies(t *testing.T) {
	s, w := setup(t)
	appendN(t, s, w, 25)
	res, err := Verify(context.Background(), s.R())
	if err != nil || !res.OK || res.Events != 25 || len(res.HeadHash) != 32 {
		t.Fatalf("%+v %v", res, err)
	}
}

// HP-OBS-005: modification, deletion and reordering are detected.
func TestTamperDetected(t *testing.T) {
	ctx := context.Background()
	cases := map[string]string{
		"modified details": "UPDATE audit_events SET details_json = '{\"i\":99}' WHERE seq = 5",
		"modified outcome": "UPDATE audit_events SET outcome = 'failure' WHERE seq = 3",
		"deleted event":    "DELETE FROM audit_events WHERE seq = 4",
		"reordered":        "UPDATE audit_events SET seq = seq + 100 WHERE seq = 2",
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			s, w := setup(t)
			appendN(t, s, w, 8)
			if err := s.W().Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
			res, err := Verify(ctx, s.R())
			if err != nil || res.OK {
				t.Fatalf("tampering not detected: %+v %v", res, err)
			}
		})
	}
}

func TestSensitiveDetailsSealed(t *testing.T) {
	s, w := setup(t)
	ctx := context.Background()
	var id string
	err := s.W().Tx(ctx, func(tx *store.Tx) error {
		var err error
		id, err = w.Append(ctx, tx, Event{Actor: System, Action: "grant.revoked", Outcome: OutcomeSuccess,
			Sensitive: map[string]any{"reason": "suspicious-activity-xyz"}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.R().AuditEventsFrom(ctx, db.AuditEventsFromParams{Seq: 0, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatal(err)
	}
	if bytes.Contains(rows[0].DetailsEnc, []byte("suspicious")) || strings.Contains(rows[0].DetailsJson, "suspicious") {
		t.Fatal("sensitive detail stored in plaintext")
	}
	m, err := w.OpenSensitive(rows[0])
	if err != nil || m["reason"] != "suspicious-activity-xyz" {
		t.Fatalf("%v %v", m, err)
	}
	if rec := DecodeRecord(rows[0]); !rec.HasSensitive || rec.Action != "grant.revoked" {
		t.Fatalf("%+v", rec)
	}
}

type memSink struct{ recs []Record }

func (m *memSink) Write(r Record) error { m.recs = append(m.recs, r); return nil }

func TestSinkOnlyAfterCommit(t *testing.T) {
	s, w := setup(t)
	sink := &memSink{}
	w.SetSink(sink)
	ctx := context.Background()
	boom := errors.New("rollback")
	_ = s.W().Tx(ctx, func(tx *store.Tx) error {
		if _, err := w.Append(ctx, tx, Event{Actor: System, Action: "x"}); err != nil {
			return err
		}
		return boom
	})
	if len(sink.recs) != 0 {
		t.Fatal("sink received a rolled-back event")
	}
	appendN(t, s, w, 2)
	if len(sink.recs) != 2 || sink.recs[1].Seq != 2 {
		t.Fatalf("sink got %+v", sink.recs)
	}
	var buf bytes.Buffer
	js := NewJSONSink(&buf)
	if err := js.Write(sink.recs[0]); err != nil || !strings.Contains(buf.String(), `"action":"agent.created"`) {
		t.Fatalf("json sink: %s %v", buf.String(), err)
	}
}

func TestValidation(t *testing.T) {
	s := storetest.Open(t)
	w := NewWriter(nil)
	ctx := context.Background()
	err := s.W().Tx(ctx, func(tx *store.Tx) error {
		_, err := w.Append(ctx, tx, Event{Actor: System})
		return err
	})
	if err == nil {
		t.Fatal("missing action accepted")
	}
	err = s.W().Tx(ctx, func(tx *store.Tx) error {
		_, err := w.Append(ctx, tx, Event{Actor: System, Action: "a", Sensitive: map[string]any{"x": 1}})
		return err
	})
	if err == nil {
		t.Fatal("sensitive details without keyring accepted")
	}
}
