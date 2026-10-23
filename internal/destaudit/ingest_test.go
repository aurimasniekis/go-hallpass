package destaudit

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

func certLogin(a activity, user string) wire.Login {
	return wire.Login{Ref: "1761220000.000:1/" + a.connID, User: user, CertKeyID: a.keyID()}
}

func rejection(res *IngestResult, id string) string {
	for _, r := range res.Rejections {
		if r.RecordID == id {
			return r.Reason
		}
	}
	return ""
}

// HP-REC-012: a correlated record is attached as destination.exec with provenance labels; exec details are sealed.
func TestIngestCertificateRecordOnTimeline(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	before := len(f.timeline(a.grant.SessionID))
	rec := f.record(certLogin(a, "ro"), f.clk.Now().Add(-10*time.Second))
	res := f.ingest(rec)
	if res.Accepted != 1 || res.Rejected != 0 || res.Duplicates != 0 || res.Records != 1 {
		t.Fatalf("result %+v", res)
	}
	evs := f.timeline(a.grant.SessionID)
	if len(evs) != before+1 {
		t.Fatalf("timeline grew by %d", len(evs)-before)
	}
	execs := destExecEvents(evs)
	if len(execs) != 1 {
		t.Fatalf("destination.exec events: %d", len(execs))
	}
	e := execs[0]
	if !e.Seq.Valid || e.Seq.Int64 <= evs[len(evs)-2].Seq.Int64 || e.SchemaVersion != 1 || e.ConnectionID.String != a.connID {
		t.Fatalf("event %+v", e)
	}
	var data map[string]any
	must(t, json.Unmarshal([]byte(e.DataJson), &data))
	if data["provenance"] != Provenance || data["verified"] != false || data["confidence"] != ConfidenceHigh ||
		data["correlation"] != CorrelationCertKeyID || data["after_session_end"] != false || data["collector_id"] != f.collector.ID ||
		data["argc"] != float64(2) || data["source"] != wire.SourceAuditd {
		t.Fatalf("data %v", data)
	}
	// The command line never appears in plaintext timeline data.
	if strings.Contains(e.DataJson, "secret-config") || strings.Contains(e.DataJson, "/usr/bin/cat") {
		t.Fatalf("exec details leaked into timeline: %s", e.DataJson)
	}
	recs, err := f.svc.SessionRecords(f.ctx, a.grant.SessionID, 0)
	must(t, err)
	if len(recs) != 1 || recs[0].TimelineEventID != e.ID || recs[0].Verified || recs[0].Argv != nil {
		t.Fatalf("records %+v", recs)
	}
	d, err := f.svc.RecordDetails(f.ctx, recs[0].ID)
	must(t, err)
	if d.Exe != "/usr/bin/cat" || len(d.Argv) != 2 || d.Argv[1] != "/etc/secret-config" || d.CWD != "/home/ro" || d.Provenance != Provenance {
		t.Fatalf("details %+v", d)
	}
	raw, err := f.s.R().GetDestauditRecord(f.ctx, recs[0].ID)
	must(t, err)
	if strings.Contains(string(raw.DetailsEnc), "secret-config") {
		t.Fatal("details stored in plaintext")
	}
	// The batch is audited and its signature retained.
	b, err := f.s.R().GetDestauditBatch(f.ctx, db.GetDestauditBatchParams{CollectorID: f.collector.ID, Seq: 1})
	must(t, err)
	if b.Accepted != 1 || len(b.Signature) != ed25519.SignatureSize {
		t.Fatalf("batch %+v", b)
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'destaudit.batch.ingested' AND actor_type = 'provider'`).Scan(&n))
	if n != 1 {
		t.Fatalf("audit events %d", n)
	}
	c, err := f.svc.GetCollector(f.ctx, f.collector.ID)
	must(t, err)
	if c.LastSeq != 1 || c.LastSeenAt == nil {
		t.Fatalf("collector %+v", c)
	}
}

func TestIngestAuthenticationFailures(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	env := f.envelope(f.record(certLogin(a, "ro"), f.clk.Now()))

	// Tampered payload.
	bad := *env
	bad.Payload = append([]byte(nil), env.Payload...)
	bad.Payload[len(bad.Payload)-3] ^= 1
	if _, err := f.svc.Ingest(f.ctx, f.collector.ID, body(t, &bad)); !errors.Is(err, errUnauthorized) {
		t.Fatalf("tampered: %v", err)
	}
	// Signed by a different key.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	var b wire.Batch
	must(t, json.Unmarshal(env.Payload, &b))
	forged, err := wire.Sign(other, &b)
	must(t, err)
	if _, err := f.svc.Ingest(f.ctx, f.collector.ID, body(t, forged)); !errors.Is(err, errUnauthorized) {
		t.Fatalf("forged: %v", err)
	}
	// Unknown and malformed collector IDs.
	if _, err := f.svc.Ingest(f.ctx, "dac_00000000000000000000000000", body(t, env)); !errors.Is(err, errUnauthorized) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := f.svc.Ingest(f.ctx, "../../etc", body(t, env)); !errors.Is(err, errUnauthorized) {
		t.Fatalf("malformed id: %v", err)
	}
	// A valid signature for a batch naming another collector.
	other2, priv2 := f.register(f.srv.ID, "second")
	b2 := b
	b2.CollectorID = f.collector.ID
	env2, err := wire.Sign(priv2, &b2)
	must(t, err)
	if _, err := f.svc.Ingest(f.ctx, other2.ID, body(t, env2)); apperr.CodeOf(err) != apperr.CodeInvalid {
		t.Fatalf("collector mismatch: %v", err)
	}
	// Revoked collector.
	_, err = f.svc.RevokeCollector(f.ctx, admin, f.collector.ID, "decommissioned")
	must(t, err)
	if _, err := f.svc.Ingest(f.ctx, f.collector.ID, body(t, env)); !errors.Is(err, errUnauthorized) {
		t.Fatalf("revoked: %v", err)
	}
	if got := destExecEvents(f.timeline(a.grant.SessionID)); len(got) != 0 {
		t.Fatalf("events written: %d", len(got))
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM destaudit_batches`).Scan(&n))
	if n != 0 {
		t.Fatalf("batches written: %d", n)
	}
}

func TestIngestReplayProtection(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	env := f.envelope(f.record(certLogin(a, "ro"), f.clk.Now()))
	first, err := f.svc.Ingest(f.ctx, f.collector.ID, body(t, env))
	must(t, err)
	// Exact resend (lost response): same result, nothing duplicated.
	again, err := f.svc.Ingest(f.ctx, f.collector.ID, body(t, env))
	must(t, err)
	if !again.DuplicateBatch || again.Accepted != first.Accepted {
		t.Fatalf("resend %+v", again)
	}
	if n := len(destExecEvents(f.timeline(a.grant.SessionID))); n != 1 {
		t.Fatalf("events %d", n)
	}
	// Same sequence, different content.
	f.nextSeq = 0
	diff := f.envelope(f.record(certLogin(a, "ro"), f.clk.Now()))
	_, err = f.svc.Ingest(f.ctx, f.collector.ID, body(t, diff))
	var re *ReplayError
	if !errors.As(err, &re) || re.LastSeq != 1 {
		t.Fatalf("same seq: %v", err)
	}
	// Advance, then replay an older sequence.
	f.nextSeq = 10
	f.ingest(f.record(certLogin(a, "ro"), f.clk.Now()))
	f.nextSeq = 4
	_, err = f.svc.Ingest(f.ctx, f.collector.ID, body(t, f.envelope(f.record(certLogin(a, "ro"), f.clk.Now()))))
	if !errors.As(err, &re) || re.LastSeq != 11 {
		t.Fatalf("old seq: %v", err)
	}
	// Records already stored count as duplicates in a new batch.
	var b wire.Batch
	must(t, json.Unmarshal(env.Payload, &b))
	f.nextSeq = 20
	res := f.ingest(b.Records...)
	if res.Duplicates != 1 || res.Accepted != 0 {
		t.Fatalf("dup records %+v", res)
	}
}

func TestIngestClockSkewAndLimits(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	rec := f.record(certLogin(a, "ro"), f.clk.Now())

	f.nextSeq++
	env, err := wire.Sign(f.priv, &wire.Batch{V: wire.Version, CollectorID: f.collector.ID, Seq: f.nextSeq, SentAt: f.clk.Now().Add(-10 * time.Minute),
		Records: []wire.Record{rec}})
	must(t, err)
	if _, err := f.svc.Ingest(f.ctx, f.collector.ID, body(t, env)); apperr.CodeOf(err) != apperr.CodeInvalid {
		t.Fatalf("skew: %v", err)
	}
	// Too many records.
	many := make([]wire.Record, wire.MaxRecords+1)
	for i := range many {
		many[i] = rec
	}
	if _, err := f.svc.Ingest(f.ctx, f.collector.ID, body(t, f.envelope(many...))); apperr.CodeOf(err) != apperr.CodeInvalid {
		t.Fatalf("too many: %v", err)
	}
	// Oversized body.
	if _, err := f.svc.Ingest(f.ctx, f.collector.ID, make([]byte, wire.MaxEnvelopeBytes+1)); apperr.CodeOf(err) != apperr.CodeInvalid {
		t.Fatalf("oversized: %v", err)
	}
	// Per-record limits and timestamps are record-level rejections.
	big := f.record(certLogin(a, "ro"), f.clk.Now())
	big.Argv = []string{strings.Repeat("A", wire.MaxArgvBytes+1)}
	future := f.record(certLogin(a, "ro"), f.clk.Now().Add(10*time.Minute))
	old := f.record(certLogin(a, "ro"), f.clk.Now().Add(-48*time.Hour))
	noID := f.record(certLogin(a, "ro"), f.clk.Now())
	noID.ID = "has space"
	dup := f.record(certLogin(a, "ro"), f.clk.Now())
	res := f.ingest(big, future, old, noID, dup, dup)
	if res.Accepted != 1 || res.Rejected != 5 {
		t.Fatalf("result %+v", res)
	}
	for id, want := range map[string]string{big.ID: "too_large", future.ID: RejectFuture, old.ID: RejectTooOld, "has space": "invalid_id", dup.ID: RejectDuplicateInBatch} {
		if got := rejection(res, id); got != want {
			t.Errorf("%s: got %q want %q", id, got, want)
		}
	}
}

// Correlation never trusts destination claims that disagree with Hallpass state.
func TestCertificateCorrelationRefusals(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	b := f.activity(f.a2, "ca:ca_test")
	now := f.clk.Now()

	otherSrv, err := f.inv.CreateServer(f.ctx, admin, inventory.ServerInput{Alias: ptr("db1"), Address: ptr("10.0.0.2")})
	must(t, err)
	otherRole, err := f.inv.CreateRole(f.ctx, admin, otherSrv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro")})
	must(t, err)

	cases := map[string]struct {
		login wire.Login
		at    time.Time
		want  string
	}{
		"wrong user":          {certLogin(a, "root"), now, RejectUserMismatch},
		"role swapped":        {wire.Login{Ref: "r1", User: "ro", CertKeyID: "hallpass:" + otherRole.ID + ":" + a.grant.ID + ":" + a.connID}, now, RejectRoleMismatch},
		"connection of other": {wire.Login{Ref: "r2", User: "ro", CertKeyID: "hallpass:" + a.grant.RoleID + ":" + a.grant.ID + ":" + b.connID}, now, RejectConnectionMismatch},
		"unknown grant":       {wire.Login{Ref: "r3", User: "ro", CertKeyID: "hallpass:" + a.grant.RoleID + ":grt_00000000000000000000000000:" + a.connID}, now, RejectUnknownSession},
		"session id as grant": {wire.Login{Ref: "r4", User: "ro", CertKeyID: "hallpass:" + a.grant.RoleID + ":" + a.grant.SessionID + ":" + a.connID}, now, RejectInvalidKeyID},
		"garbage key id":      {wire.Login{Ref: "r5", User: "ro", CertKeyID: "hallpass:x"}, now, RejectInvalidKeyID},
		"no identity":         {wire.Login{Ref: "r6", User: "ro"}, now, RejectNoIdentity},
		"before grant":        {certLogin(a, "ro"), now.Add(-20 * time.Minute), RejectOutsideWindow},
		"login before grant":  {wire.Login{Ref: "r7", User: "ro", CertKeyID: a.keyID(), Time: now.Add(-20 * time.Minute)}, now, RejectOutsideWindow},
		"unknown fingerprint": {wire.Login{Ref: "r8", User: "ro", KeyFingerprint: "SHA256:AAAA"}, now, RejectUnknownKey},
		"control (accepted)":  {wire.Login{Ref: "r9", User: "ro", CertKeyID: a.keyID()}, now, ""},
	}
	var recs []wire.Record
	want := map[string]string{}
	names := map[string]string{}
	for name, c := range cases {
		r := f.record(c.login, c.at)
		recs = append(recs, r)
		want[r.ID] = c.want
		names[r.ID] = name
	}
	res := f.ingest(recs...)
	for _, r := range recs {
		if got := rejection(res, r.ID); got != want[r.ID] {
			t.Errorf("%s: got %q want %q", names[r.ID], got, want[r.ID])
		}
	}
	if res.Accepted != 1 {
		t.Fatalf("accepted %d", res.Accepted)
	}

	// A collector enrolled for another server cannot attach records to this server's sessions.
	c2, priv2 := f.register(otherSrv.ID, "db1-auditd")
	env, err := wire.Sign(priv2, &wire.Batch{V: 1, CollectorID: c2.ID, Seq: 1, SentAt: now, Records: []wire.Record{f.record(certLogin(a, "ro"), now)}})
	must(t, err)
	res2, err := f.svc.Ingest(f.ctx, c2.ID, body(t, env))
	must(t, err)
	if res2.Accepted != 0 || res2.Rejections[0].Reason != RejectServerMismatch {
		t.Fatalf("cross-server %+v", res2)
	}
}

// HP-SES-004: processes outliving the session keep their audit session; records are attached but flagged, within a bound.
func TestRecordsAfterSessionEnd(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	_, err := f.acc.RevokeGrant(f.ctx, f.approver, a.grant.ID, "done")
	must(t, err)
	f.clk.Advance(time.Hour)
	in := f.record(certLogin(a, "ro"), f.clk.Now().Add(-59*time.Minute)) // within skew of the end
	late := f.record(certLogin(a, "ro"), f.clk.Now().Add(-5*time.Minute))
	res := f.ingest(in, late)
	if res.Accepted != 2 {
		t.Fatalf("%+v", res)
	}
	recs, err := f.svc.SessionRecords(f.ctx, a.grant.SessionID, 10)
	must(t, err)
	flags := map[string]bool{}
	for _, r := range recs {
		flags[r.RecordRef] = r.AfterSessionEnd
	}
	if flags[in.ID] || !flags[late.ID] {
		t.Fatalf("flags %v", flags)
	}
	// Beyond PostSessionWindow (and MaxRecordAge is larger here) records are refused.
	f.svc.opts.MaxRecordAge = 72 * time.Hour
	f.clk.Advance(30 * time.Hour)
	tooLate := f.record(certLogin(a, "ro"), f.clk.Now().Add(-time.Minute))
	res = f.ingest(tooLate)
	if rejection(res, tooLate.ID) != RejectOutsideWindow {
		t.Fatalf("%+v", res)
	}
}

func TestFingerprintCorrelation(t *testing.T) {
	f := newFx(t)
	credID, fp := f.loginCredential(f.role.ID)
	a := f.activity(f.a1, credID)
	now := f.clk.Now()
	login := wire.Login{Ref: "1761220000.000:7/12", User: "ro", KeyFingerprint: fp, Time: now.Add(-5 * time.Second)}
	res := f.ingest(f.record(login, now))
	if res.Accepted != 1 {
		t.Fatalf("%+v", res)
	}
	recs, err := f.svc.SessionRecords(f.ctx, a.grant.SessionID, 10)
	must(t, err)
	if len(recs) != 1 || recs[0].Confidence != ConfidenceMedium || recs[0].Correlation != CorrelationKeyWindow {
		t.Fatalf("%+v", recs)
	}

	// A second concurrent session on the same role and key makes new logins ambiguous: refused, not guessed.
	f.activity(f.a2, credID)
	newLogin := wire.Login{Ref: "1761220000.000:8/13", User: "ro", KeyFingerprint: fp, Time: f.clk.Now()}
	r := f.record(newLogin, f.clk.Now())
	res = f.ingest(r)
	if rejection(res, r.ID) != RejectAmbiguous {
		t.Fatalf("%+v", res)
	}
	// The first login stays bound to its session even now.
	f.clk.Advance(30 * time.Second)
	res = f.ingest(f.record(login, f.clk.Now()))
	if res.Accepted != 1 {
		t.Fatalf("%+v", res)
	}
	recs, err = f.svc.SessionRecords(f.ctx, a.grant.SessionID, 10)
	must(t, err)
	if len(recs) != 2 || recs[1].Correlation != CorrelationLoginBinded {
		t.Fatalf("%+v", recs)
	}
	// Wrong account or a key of another server is refused.
	r1 := f.record(wire.Login{Ref: "x1", User: "admin", KeyFingerprint: fp}, f.clk.Now())
	res = f.ingest(r1)
	if rejection(res, r1.ID) != RejectUserMismatch {
		t.Fatalf("%+v", res)
	}
	otherSrv, err := f.inv.CreateServer(f.ctx, admin, inventory.ServerInput{Alias: ptr("db1"), Address: ptr("10.0.0.2")})
	must(t, err)
	otherRole, err := f.inv.CreateRole(f.ctx, admin, otherSrv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro")})
	must(t, err)
	_, fp2 := f.loginCredential(otherRole.ID)
	r2 := f.record(wire.Login{Ref: "x2", User: "ro", KeyFingerprint: fp2}, f.clk.Now())
	res = f.ingest(r2)
	if rejection(res, r2.ID) != RejectServerMismatch {
		t.Fatalf("%+v", res)
	}
	// No session at that time.
	r3 := f.record(wire.Login{Ref: "x3", User: "ro", KeyFingerprint: fp, Time: now.Add(-3 * time.Hour)}, f.clk.Now())
	res = f.ingest(r3)
	if rejection(res, r3.ID) != RejectNoSession {
		t.Fatalf("%+v", res)
	}
}

// A destination login is bound to one access session; a later claim pointing it elsewhere is refused.
func TestLoginBindingConflict(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	b := f.activity(f.a2, "ca:ca_test")
	ref := "1761220000.000:9/44"
	res := f.ingest(f.record(wire.Login{Ref: ref, User: "ro", CertKeyID: a.keyID()}, f.clk.Now()))
	if res.Accepted != 1 {
		t.Fatalf("%+v", res)
	}
	r := f.record(wire.Login{Ref: ref, User: "ro", CertKeyID: b.keyID()}, f.clk.Now())
	res = f.ingest(r)
	if rejection(res, r.ID) != RejectLoginConflict || res.Accepted != 0 {
		t.Fatalf("%+v", res)
	}
	if n := len(destExecEvents(f.timeline(b.grant.SessionID))); n != 0 {
		t.Fatalf("events on wrong session: %d", n)
	}
}

// HP-REC-013: retention clears timeline payloads; the trigger purges the sealed exec details with them.
func TestRetentionPurgesDetails(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	f.ingest(f.record(certLogin(a, "ro"), f.clk.Now()))
	must(t, f.s.W().Tx(f.ctx, func(tx *store.Tx) error {
		return tx.Q.DeleteSessionTimelinePayloads(f.ctx, sql.NullString{String: a.grant.SessionID, Valid: true})
	}))
	recs, err := f.svc.SessionRecords(f.ctx, a.grant.SessionID, 10)
	must(t, err)
	if len(recs) != 1 || !recs[0].Purged {
		t.Fatalf("%+v", recs)
	}
	d, err := f.svc.RecordDetails(f.ctx, recs[0].ID)
	must(t, err)
	if !d.Purged || d.Argv != nil {
		t.Fatalf("%+v", d)
	}
}

func TestSequencesAreOrderedPerSession(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	b := f.activity(f.a2, "ca:ca_test")
	var recs []wire.Record
	for range 3 {
		recs = append(recs, f.record(certLogin(a, "ro"), f.clk.Now()))
		recs = append(recs, f.record(wire.Login{Ref: "b/" + b.connID, User: "ro", CertKeyID: b.keyID()}, f.clk.Now()))
	}
	res := f.ingest(recs...)
	if res.Accepted != 6 {
		t.Fatalf("%+v", res)
	}
	for _, sid := range []string{a.grant.SessionID, b.grant.SessionID} {
		evs := f.timeline(sid)
		seen := map[int64]bool{}
		for _, e := range evs {
			if seen[e.Seq.Int64] {
				t.Fatalf("duplicate seq %d", e.Seq.Int64)
			}
			seen[e.Seq.Int64] = true
		}
		if len(destExecEvents(evs)) != 3 {
			t.Fatalf("session %s: %d", sid, len(destExecEvents(evs)))
		}
	}
}
