package wire

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// HP-TST-002, HP-REC-012: an envelope from the network verifies only for payloads the collector key signed, and a
// verified payload decodes only to a bounded, versioned batch.
func FuzzDecodeEnvelopeVerify(f *testing.F) {
	priv := vecKey()
	pub := priv.Public().(ed25519.PublicKey)
	signed := map[string]bool{}
	for _, b := range []*Batch{
		{V: 1, CollectorID: "dac_x", Seq: 1, SentAt: time.Unix(1_800_000_000, 0).UTC()},
		{V: 1, CollectorID: "dac_x", Seq: 2, SentAt: time.Unix(1_800_000_000, 0).UTC(), Records: []Record{{ID: "1.0:1", Source: SourceAuditd}}},
	} {
		env, err := Sign(priv, b)
		if err != nil {
			f.Fatal(err)
		}
		signed[string(env.Payload)] = true
		body, _ := json.Marshal(env)
		f.Add(body)
	}
	f.Add([]byte(`{"payload":"e30=","signature":"AAAA","extra":1}`))
	f.Add([]byte(`{"payload":"e30=","signature":"AAAA"} {}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		env, err := DecodeEnvelope(body)
		if err != nil {
			return
		}
		if Verify(pub, env) != nil {
			return
		}
		if !signed[string(env.Payload)] {
			t.Fatalf("forged payload verified: %q", env.Payload)
		}
		b, err := DecodeBatch(env.Payload)
		if err != nil {
			return
		}
		if b.V != Version || b.CollectorID == "" || b.Seq <= 0 || len(b.Records) > MaxRecords {
			t.Fatalf("invalid batch accepted: %+v", b)
		}
	})
}

// HP-TST-002, HP-REC-012: batches decode strictly and records that pass Validate respect every documented limit.
func FuzzDecodeBatch(f *testing.F) {
	f.Add([]byte(vecPayload))
	rec := `{"id":"1700000000.123:42","source":"auditd","time":"2026-10-23T12:00:00Z","login":{"ref":"1.0:1/7","user":"ro",` +
		`"cert_key_id":"hallpass:rol_a:grt_b:con_c"},"pid":10,"ppid":1,"uid":1000,"auid":1000,"success":true,"exe":"/bin/id","argv":["id"]}`
	f.Add([]byte(`{"v":1,"collector_id":"dac_x","seq":3,"sent_at":"2026-10-23T12:00:00Z","records":[` + rec + `]}`))
	f.Add([]byte(`{"v":2,"collector_id":"dac_x","seq":3,"sent_at":"2026-10-23T12:00:00Z","records":[]}`))
	f.Add([]byte(`{"v":1,"collector_id":"dac_x","seq":3,"sent_at":"2026-10-23T12:00:00Z","records":[],"x":1}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		b, err := DecodeBatch(payload)
		if err != nil {
			return
		}
		if b.V != Version || b.CollectorID == "" || b.Seq <= 0 || b.SentAt.IsZero() || len(b.Records) > MaxRecords {
			t.Fatalf("invalid batch accepted: %+v", b)
		}
		for i := range b.Records {
			r := &b.Records[i]
			if r.Validate() != "" {
				continue
			}
			if r.ID == "" || len(r.ID) > MaxIDLen || r.Source != SourceAuditd || r.PID <= 0 || len(r.Argv) > MaxArgs ||
				ArgvBytes(r.Argv) > MaxArgvBytes || len(r.Exe) > MaxPathLen || len(r.CWD) > MaxPathLen ||
				!utf8.ValidString(r.Login.User) || strings.ContainsAny(r.Login.User+r.Login.Ref+r.ID, " \t\r\n\x00") {
				t.Fatalf("record violating limits validated: %+v", r)
			}
		}
	})
}

// HP-TST-002: certificate key IDs parse only in the exact "hallpass:<role>:<grant>:<connection>" shape.
func FuzzParseCertKeyID(f *testing.F) {
	f.Add("hallpass:rol_a:grt_b:con_c")
	f.Add("hallpass:rol_a:grt_b")
	f.Add("hallpass::grt_b:con_c")
	f.Add("hallpass:a:b:c:d")
	f.Fuzz(func(t *testing.T, s string) {
		k, ok := ParseCertKeyID(s)
		if !ok {
			return
		}
		if CertKeyIDPrefix+k.RoleID+":"+k.GrantID+":"+k.ConnectionID != s {
			t.Fatalf("%q parsed to %+v", s, k)
		}
		for _, p := range []string{k.RoleID, k.GrantID, k.ConnectionID} {
			if p == "" || len(p) > 64 || !printable(p) || strings.Contains(p, ":") {
				t.Fatalf("bad part %q in %q", p, s)
			}
		}
	})
}

// HP-TST-002: argv truncation always fits the limits, keeps a prefix of the input and never splits a UTF-8 rune.
func FuzzTruncateArgv(f *testing.F) {
	f.Add("a", 3, 1)
	f.Add("é", 9000, 2)
	f.Add("x", 1, 300)
	f.Fuzz(func(t *testing.T, arg string, repeat, count int) {
		repeat, count = max(0, min(repeat, MaxArgvBytes)), max(0, min(count, 2*MaxArgs))
		argv := make([]string, count)
		for i := range argv {
			argv[i] = strings.Repeat(arg, max(1, repeat/max(1, len(arg))))
		}
		out, truncated := TruncateArgv(slices.Clone(argv))
		if len(out) > MaxArgs || ArgvBytes(out) > MaxArgvBytes {
			t.Fatalf("truncated argv exceeds limits: %d args, %d bytes", len(out), ArgvBytes(out))
		}
		if !truncated && !slices.Equal(out, argv) {
			t.Fatal("argv changed without the truncated flag")
		}
		for i, a := range out {
			if i >= len(argv) || !strings.HasPrefix(argv[i], a) || (i < len(out)-1 && a != argv[i]) {
				t.Fatalf("output is not a prefix of the input at %d", i)
			}
			if utf8.ValidString(argv[i]) && !utf8.ValidString(a) {
				t.Fatalf("rune split in argument %d", i)
			}
		}
	})
}
