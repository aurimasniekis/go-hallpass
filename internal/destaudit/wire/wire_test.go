package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Test vector (also in docs/destination/audit-collector.md). Key: Ed25519 seed 00 01 … 1f. The signature was
// cross-checked with an independent implementation (Python cryptography) when the format was defined.
const (
	vecPayload = `{"v":1,"collector_id":"dac_00000000000000000000000000","seq":1,"sent_at":"2026-10-23T12:00:00Z","records":[]}`
	vecPub     = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	vecSig     = "253247ae406e02bc28f65571b0da67e5f1a81795d690813927f288eb7a22ab6fa6470e580a76685034d24ceda2b083e448aef47fd7889887a3c18060c1ed2b09"
)

func vecKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestSignatureVector(t *testing.T) {
	priv := vecKey()
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != vecPub {
		t.Fatalf("public key %s", got)
	}
	sig, _ := hex.DecodeString(vecSig)
	pub, _ := hex.DecodeString(vecPub)
	env := &Envelope{Payload: []byte(vecPayload), Signature: sig}
	if err := Verify(pub, env); err != nil {
		t.Fatalf("vector does not verify: %v", err)
	}
	if got := hex.EncodeToString(ed25519.Sign(priv, SignedMessage([]byte(vecPayload)))); got != vecSig {
		t.Fatalf("signature %s", got)
	}
	// Without the domain-separation context the signature is different and must not verify.
	if ed25519.Verify(pub, []byte(vecPayload), sig) {
		t.Fatal("signature verifies without context")
	}
	b, err := DecodeBatch(env.Payload)
	if err != nil || b.Seq != 1 || !b.SentAt.Equal(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v %v", b, err)
	}
}

func TestSignVerifyTamper(t *testing.T) {
	priv := vecKey()
	pub := priv.Public().(ed25519.PublicKey)
	env, err := Sign(priv, &Batch{V: Version, CollectorID: "dac_x", Seq: 7, SentAt: time.Now(), Records: []Record{{ID: "1.000:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, env); err != nil {
		t.Fatal(err)
	}
	for i := range env.Payload {
		bad := *env
		bad.Payload = append([]byte(nil), env.Payload...)
		bad.Payload[i] ^= 0x01
		if Verify(pub, &bad) == nil {
			t.Fatalf("tampered byte %d verified", i)
		}
	}
	short := *env
	short.Signature = env.Signature[:10]
	if Verify(pub, &short) == nil || Verify(pub[:5], env) == nil {
		t.Fatal("malformed key or signature verified")
	}
	if _, err := Sign(priv[:10], &Batch{}); err == nil {
		t.Fatal("short private key accepted")
	}
	raw, _ := json.Marshal(env)
	back, err := DecodeEnvelope(raw)
	if err != nil || Verify(pub, back) != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestStrictDecoding(t *testing.T) {
	for _, body := range []string{``, `{}`, `{"payload":"e30=","signature":"AA==","x":1}`, `{"payload":"e30=","signature":"AA=="} {}`, `[`} {
		if _, err := DecodeEnvelope([]byte(body)); err == nil {
			t.Errorf("envelope %q accepted", body)
		}
	}
	ok := `{"v":1,"collector_id":"dac_x","seq":1,"sent_at":"2026-10-23T12:00:00Z","records":[]}`
	if _, err := DecodeBatch([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		`{"v":2,"collector_id":"dac_x","seq":1,"sent_at":"2026-10-23T12:00:00Z","records":[]}`,
		`{"v":1,"collector_id":"","seq":1,"sent_at":"2026-10-23T12:00:00Z","records":[]}`,
		`{"v":1,"collector_id":"dac_x","seq":0,"sent_at":"2026-10-23T12:00:00Z","records":[]}`,
		`{"v":1,"collector_id":"dac_x","seq":1,"records":[]}`,
		`{"v":1,"collector_id":"dac_x","seq":1,"sent_at":"2026-10-23T12:00:00Z","records":[],"session_id":"ses_x"}`,
		`{"v":1,"collector_id":"dac_x","seq":1,"sent_at":"2026-10-23T12:00:00Z","records":[{"id":"a","session_id":"ses_x"}]}`,
	} {
		if _, err := DecodeBatch([]byte(p)); err == nil {
			t.Errorf("batch %s accepted", p)
		}
	}
	many := Batch{V: 1, CollectorID: "dac_x", Seq: 1, SentAt: time.Now(), Records: make([]Record, MaxRecords+1)}
	raw, _ := json.Marshal(many)
	if _, err := DecodeBatch(raw); err == nil {
		t.Fatal("too many records accepted")
	}
}

func validRecord() Record {
	return Record{ID: "1761220000.123:456", Source: SourceAuditd, Time: time.Now(), Login: Login{Ref: "1761219990.000:400/5", User: "ro", CertKeyID: "hallpass:rol_a:grt_b:con_c"},
		PID: 10, PPID: 1, UID: 1001, AUID: 1001, Exe: "/bin/ls", Argv: []string{"ls"}}
}

func TestRecordValidate(t *testing.T) {
	if r := validRecord(); r.Validate() != "" {
		t.Fatalf("valid record rejected: %s", r.Validate())
	}
	cases := map[string]func(*Record){
		"invalid_id":      func(r *Record) { r.ID = "" },
		"invalid_source":  func(r *Record) { r.Source = "bash_history" },
		"invalid_time":    func(r *Record) { r.Time = time.Time{} },
		"invalid_login":   func(r *Record) { r.Login.User = "a b" },
		"invalid_process": func(r *Record) { r.PID = 0 },
		"too_large":       func(r *Record) { r.Argv = make([]string, MaxArgs+1) },
	}
	for want, mut := range cases {
		r := validRecord()
		mut(&r)
		if got := r.Validate(); got != want {
			t.Errorf("%s: got %q", want, got)
		}
	}
	r := validRecord()
	r.Login.Ref = "ref\x1b[31m"
	if r.Validate() != "invalid_login" {
		t.Fatal("control characters accepted in login ref")
	}
	r = validRecord()
	r.CWD = strings.Repeat("a", MaxPathLen+1)
	if r.Validate() != "too_large" {
		t.Fatal("long cwd accepted")
	}
}

func TestParseCertKeyID(t *testing.T) {
	k, ok := ParseCertKeyID("hallpass:rol_a:grt_b:con_c")
	if !ok || k.RoleID != "rol_a" || k.GrantID != "grt_b" || k.ConnectionID != "con_c" {
		t.Fatalf("%+v %v", k, ok)
	}
	for _, s := range []string{"", "hallpass:", "hallpass:a:b", "hallpass:a:b:c:d", "other:a:b:c", "hallpass:a::c", "hallpass:a b:c:d"} {
		if _, ok := ParseCertKeyID(s); ok {
			t.Errorf("%q parsed", s)
		}
	}
}

func TestTruncateArgv(t *testing.T) {
	argv := []string{"a", strings.Repeat("é", MaxArgvBytes)} // 2-byte runes
	out, tr := TruncateArgv(argv)
	if !tr || ArgvBytes(out) > MaxArgvBytes || !utf8.ValidString(out[1]) || out[0] != "a" {
		t.Fatalf("truncated=%v bytes=%d", tr, ArgvBytes(out))
	}
	many := make([]string, MaxArgs+5)
	out, tr = TruncateArgv(many)
	if !tr || len(out) != MaxArgs {
		t.Fatal("args not limited")
	}
	out, tr = TruncateArgv([]string{"ls", "-l"})
	if tr || len(out) != 2 {
		t.Fatal("small argv changed")
	}
}
