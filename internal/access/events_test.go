package access

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/events"
)

type outboxRow struct {
	subject, typ string
	payload      SessionEvent
}

func (f *fx) eventOutbox() []outboxRow {
	f.t.Helper()
	rows, err := f.s.ReadDB().QueryContext(f.ctx, `SELECT subject, type, payload_json FROM event_outbox ORDER BY created_at, subject`)
	must(f.t, err)
	defer func() { _ = rows.Close() }()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		var payload string
		must(f.t, rows.Scan(&r.subject, &r.typ, &payload))
		must(f.t, json.Unmarshal([]byte(payload), &r.payload))
		out = append(out, r)
	}
	must(f.t, rows.Err())
	return out
}

// ADR-0057: session lifecycle events are recorded for Pulse with the grant's agent, server and role; request and
// grant timeline events are left to the audit log.
func TestSessionEventsRecordedForPulse(t *testing.T) {
	f := newFxWith(t, func(o *Options) { o.Events = events.NewRecorder(true) })
	g := f.grant(time.Hour)
	conn := f.conn()
	reg, err := f.register(conn, g.ID, KindExec, false)
	must(t, err)
	must(t, f.svc.ActivateChannel(f.ctx, reg, "cred_x", map[string]any{"kind": "exec"}))
	must(t, f.svc.AppendSessionEvent(f.ctx, reg, EvExecRequested, "seg_1", map[string]any{"has_command": true, "bytes": 7}))
	exit := 3
	must(t, f.svc.CloseChannel(f.ctx, reg, CloseInfo{Reason: "exit_status", ExitStatus: &exit}))
	must(t, f.svc.CloseConnection(f.ctx, conn, "client_closed"))

	rows := f.eventOutbox()
	var subjects []string
	for _, r := range rows {
		subjects = append(subjects, r.subject)
		p := r.payload
		if p.SessionID != g.SessionID || p.GrantID != g.ID || p.AgentID != f.agent.ID || p.ServerID != f.srv.ID || p.RoleID != f.role.ID || p.ID == "" {
			t.Errorf("%s: payload %+v", r.subject, p)
		}
		if r.typ != "hallpass."+r.subject[len(events.SubjectPrefix):]+".v1" {
			t.Errorf("%s: type %s", r.subject, r.typ)
		}
	}
	slices.Sort(subjects)
	want := []string{"evt.hallpass.session.channel.exited", "evt.hallpass.session.channel.opened", "evt.hallpass.session.connection.closed",
		"evt.hallpass.session.connection.opened", "evt.hallpass.session.exec.requested"}
	if !slices.Equal(subjects, want) {
		t.Fatalf("subjects %v, want %v", subjects, want)
	}
	for _, r := range rows {
		if r.subject == "evt.hallpass.session.channel.exited" && (r.payload.ChannelID != reg.ChannelID || r.payload.Data["exit_status"] != float64(3)) {
			t.Fatalf("channel.exited payload %+v", r.payload)
		}
	}
}

func TestSessionEventsOffByDefault(t *testing.T) {
	f := newFx(t)
	g := f.grant(time.Hour)
	reg, err := f.register(f.conn(), g.ID, KindShell, false)
	must(t, err)
	must(t, f.svc.ActivateChannel(f.ctx, reg, "cred_x", nil))
	if rows := f.eventOutbox(); len(rows) != 0 {
		t.Fatalf("recorded %d events with publishing disabled", len(rows))
	}
}
