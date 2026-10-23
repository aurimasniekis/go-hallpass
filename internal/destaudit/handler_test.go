package destaudit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

func (f *fx) post(mux http.Handler, id string, ctype string, b []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(f.ctx, http.MethodPost, "/hooks/destaudit/"+id, bytes.NewReader(b))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestHandler(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	mux := http.NewServeMux()
	mux.Handle("/hooks/destaudit/{collector_id}", f.svc.Handler())

	env := f.envelope(f.record(certLogin(a, "ro"), f.clk.Now()))
	rec := f.post(mux, f.collector.ID, "application/json; charset=utf-8", body(t, env))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var res IngestResult
	must(t, json.Unmarshal(rec.Body.Bytes(), &res))
	if res.Accepted != 1 || res.Seq != 1 {
		t.Fatalf("%+v", res)
	}

	// Replay of an older sequence → 409 with last_seq so the collector can resynchronize.
	f.nextSeq = 0
	rec = f.post(mux, f.collector.ID, "application/json", body(t, f.envelope(f.record(certLogin(a, "ro"), f.clk.Now()))))
	var p problem
	must(t, json.Unmarshal(rec.Body.Bytes(), &p))
	if rec.Code != http.StatusConflict || p.Code != "replay" || p.LastSeq == nil || *p.LastSeq != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatal(rec.Header())
	}

	// Bad signature and unknown collector look identical.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	var b wire.Batch
	must(t, json.Unmarshal(env.Payload, &b))
	b.Seq = 99
	forged, _ := wire.Sign(other, &b)
	r1 := f.post(mux, f.collector.ID, "application/json", body(t, forged))
	r2 := f.post(mux, "dac_00000000000000000000000000", "application/json", body(t, env))
	if r1.Code != http.StatusUnauthorized || r2.Code != http.StatusUnauthorized || r1.Body.String() != r2.Body.String() {
		t.Fatalf("%d %s / %d %s", r1.Code, r1.Body, r2.Code, r2.Body)
	}

	if rec := f.post(mux, f.collector.ID, "text/plain", body(t, env)); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type: %d", rec.Code)
	}
	if rec := f.post(mux, f.collector.ID, "application/json", make([]byte, wire.MaxEnvelopeBytes+10)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large: %d", rec.Code)
	}
	if rec := f.post(mux, f.collector.ID, "application/json", []byte(`{"payload":"x"`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", rec.Code)
	}
	req := httptest.NewRequestWithContext(f.ctx, http.MethodGet, "/hooks/destaudit/"+f.collector.ID, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rr.Code)
	}
	// Without a {collector_id} wildcard the last path segment is used.
	f.nextSeq = 5
	if rec := f.post(f.svc.Handler(), f.collector.ID, "application/json", body(t, f.envelope())); rec.Code != http.StatusOK {
		t.Fatalf("fallback: %d %s", rec.Code, rec.Body)
	}
}

func TestRegisterAndRevoke(t *testing.T) {
	f := newFx(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	line := authorizedLine(t, pub)
	if _, err := f.svc.RegisterCollector(f.ctx, admin, RegisterInput{ServerID: f.srv.ID, Name: "x", PublicKey: sshkeys.ECDSA256(t).AuthorizedLine("")}); apperr.CodeOf(err) != apperr.CodeInvalid {
		t.Fatalf("ecdsa: %v", err)
	}
	if _, err := f.svc.RegisterCollector(f.ctx, admin, RegisterInput{ServerID: f.srv.ID, Name: "x", PublicKey: "garbage"}); apperr.CodeOf(err) != apperr.CodeInvalid {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := f.svc.RegisterCollector(f.ctx, admin, RegisterInput{ServerID: f.srv.ID, Name: "", PublicKey: line}); apperr.CodeOf(err) != apperr.CodeInvalid {
		t.Fatalf("name: %v", err)
	}
	if _, err := f.svc.RegisterCollector(f.ctx, admin, RegisterInput{ServerID: "srv_00000000000000000000000000", Name: "x", PublicKey: line}); apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("server: %v", err)
	}
	c, err := f.svc.RegisterCollector(f.ctx, admin, RegisterInput{ServerID: f.srv.ID, Name: "x", PublicKey: line})
	must(t, err)
	if c.State != StateActive || c.PublicKey != line || c.Fingerprint == "" {
		t.Fatalf("%+v", c)
	}
	if _, err := f.svc.RegisterCollector(f.ctx, admin, RegisterInput{ServerID: f.srv.ID, Name: "y", PublicKey: line}); apperr.CodeOf(err) != apperr.CodeAlreadyExists {
		t.Fatalf("duplicate key: %v", err)
	}
	list, err := f.svc.ListCollectors(f.ctx, f.srv.ID)
	must(t, err)
	all, err := f.svc.ListCollectors(f.ctx, "")
	must(t, err)
	if len(list) != 2 || len(all) != 2 {
		t.Fatalf("%d %d", len(list), len(all))
	}
	c, err = f.svc.RevokeCollector(f.ctx, admin, c.ID, "rotated")
	must(t, err)
	if c.State != StateRevoked || c.RevokedAt == nil || c.RevokeReason != "rotated" {
		t.Fatalf("%+v", c)
	}
	if _, err := f.svc.RevokeCollector(f.ctx, admin, c.ID, ""); apperr.CodeOf(err) != apperr.CodeConflict {
		t.Fatalf("twice: %v", err)
	}
	if _, err := f.svc.RevokeCollector(f.ctx, admin, "dac_00000000000000000000000000", ""); apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("missing: %v", err)
	}
	if _, err := f.svc.GetCollector(f.ctx, "dac_00000000000000000000000000"); apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("get missing: %v", err)
	}
	var n int
	must(t, f.s.ReadDB().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM audit_events WHERE action LIKE 'destaudit.collector.%'`).Scan(&n))
	if n != 3 { // two registrations (fixture + this test's) and one revocation
		t.Fatalf("audit events %d", n)
	}
}
