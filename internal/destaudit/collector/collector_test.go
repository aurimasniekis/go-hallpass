package collector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
)

// Sample input: an sshd certificate login (pid 2001 → audit session 7), a managed-key login (pid 2002 → ses 8), a
// login by an unrelated user (pid 2003 → ses 9), and exec events in each. Lines from both sources interleave.
const sample = `Oct 23 12:00:00 web1 sshd[2001]: Accepted publickey for ro from 203.0.113.10 port 51234 ssh2: ED25519-CERT SHA256:ephemeralFP0123456789abcdefABCDEF0123456789ab ID hallpass:rol_1:grt_2:con_3 (serial 991) CA ED25519 SHA256:caFP0123456789abcdefABCDEF0123456789abcdefg
type=LOGIN msg=audit(1792756800.100:500): pid=2001 uid=0 subj=unconfined old-auid=4294967295 auid=1001 tty=(none) old-ses=4294967295 ses=7 res=1
type=SYSCALL msg=audit(1792756801.200:510): arch=c000003e syscall=59 success=yes exit=0 a0=55d a1=55e a2=55f a3=8 items=2 ppid=2005 pid=2010 auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=(none) ses=7 comm="cat" exe="/usr/bin/cat" key="hallpass"
type=EXECVE msg=audit(1792756801.200:510): argc=3 a0="cat" a1="-n" a2=2F746D702F6D792066696C65
type=CWD msg=audit(1792756801.200:510): cwd="/home/ro"
type=PATH msg=audit(1792756801.200:510): item=0 name="/usr/bin/cat" inode=1 dev=08:01 mode=0100755
type=PROCTITLE msg=audit(1792756801.200:510): proctitle=636174002D6E
type=EOE msg=audit(1792756801.200:510):
node=web1 type=LOGIN msg=audit(1792756802.000:520): pid=2002 uid=0 old-auid=4294967295 auid=1002 tty=(none) old-ses=4294967295 ses=8 res=1
type=SYSCALL msg=audit(1792756803.000:530): arch=c000003e syscall=59 success=no exit=-2 ppid=2006 pid=2011 auid=1002 uid=1002 ses=8 comm="nope" exe="/usr/bin/nope"
type=EXECVE msg=audit(1792756803.000:530): argc=1 a0="nope"
type=EOE msg=audit(1792756803.000:530):
Oct 23 12:00:02 web1 sshd-session[2002]: Accepted publickey for deploy from 203.0.113.10 port 51240 ssh2: ED25519 SHA256:managedKeyFP0123456789abcdefABCDEF0123456789abc
Oct 23 12:00:03 web1 sshd[2003]: Accepted publickey for alice from 198.51.100.7 port 40000 ssh2: RSA SHA256:aliceFP0123456789abcdefABCDEF0123456789abcdefgh
type=LOGIN msg=audit(1792756803.500:540): pid=2003 uid=0 old-auid=4294967295 auid=1500 tty=(none) old-ses=4294967295 ses=9 res=1
type=SYSCALL msg=audit(1792756804.000:550): arch=c000003e syscall=59 success=yes exit=0 ppid=2007 pid=2012 auid=1500 uid=1500 ses=9 comm="ls" exe="/usr/bin/ls"
type=EXECVE msg=audit(1792756804.000:550): argc=1 a0="ls"
type=EOE msg=audit(1792756804.000:550):
type=SYSCALL msg=audit(1792756805.000:560): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=300 auid=4294967295 uid=0 ses=4294967295 comm="cron" exe="/usr/sbin/cron"
type=EXECVE msg=audit(1792756805.000:560): argc=1 a0="cron"
type=EOE msg=audit(1792756805.000:560):
some unrelated syslog line
`

func assemble(t *testing.T, f Filter, input string) ([]wire.Record, Stats) {
	t.Helper()
	a := NewAssembler(f)
	now := time.Now()
	for line := range strings.SplitSeq(input, "\n") {
		if line != "" {
			a.Add(line, now)
		}
	}
	return a.Drain(now, true), a.Stats
}

func TestAssembleSample(t *testing.T) {
	recs, st := assemble(t, Filter{Fingerprints: map[string]bool{"SHA256:managedKeyFP0123456789abcdefABCDEF0123456789abc": true}}, sample)
	if len(recs) != 2 {
		t.Fatalf("records: %+v", recs)
	}
	byID := map[string]wire.Record{}
	for _, r := range recs {
		byID[r.ID] = r
		if reason := r.Validate(); reason != "" {
			t.Fatalf("%s invalid: %s", r.ID, reason)
		}
	}
	c := byID["1792756801.200:510"]
	if c.Login.CertKeyID != "hallpass:rol_1:grt_2:con_3" || c.Login.KeyFingerprint != "" || c.Login.User != "ro" ||
		c.Login.Ref != "1792756800.100:500/7" || !c.Login.Time.Equal(time.Unix(1792756800, 100e6)) {
		t.Fatalf("cert login %+v", c.Login)
	}
	if c.Exe != "/usr/bin/cat" || strings.Join(c.Argv, "|") != "cat|-n|/tmp/my file" || c.CWD != "/home/ro" || !c.Success ||
		c.PID != 2010 || c.PPID != 2005 || c.AUID != 1001 || !c.Time.Equal(time.Unix(1792756801, 200e6)) {
		t.Fatalf("cert exec %+v", c)
	}
	k := byID["1792756803.000:530"]
	if k.Login.KeyFingerprint != "SHA256:managedKeyFP0123456789abcdefABCDEF0123456789abc" || k.Login.CertKeyID != "" || k.Login.User != "deploy" || k.Success {
		t.Fatalf("key exec %+v", k)
	}
	// alice (not in the filter) and cron (no audit session) are not shipped.
	if st.Execs != 4 || st.Shipped != 2 || st.NotShipped != 2 || st.Ignored != 1 {
		t.Fatalf("stats %+v", st)
	}
	// Without the fingerprint filter only HallPass certificate logins ship; an account filter also works.
	recs, _ = assemble(t, Filter{}, sample)
	if len(recs) != 1 || recs[0].Login.CertKeyID == "" {
		t.Fatalf("%+v", recs)
	}
	recs, _ = assemble(t, Filter{Accounts: map[string]bool{"deploy": true}}, sample)
	if len(recs) != 2 {
		t.Fatalf("%+v", recs)
	}
}

func TestPendingUntilLoginKnown(t *testing.T) {
	a := NewAssembler(Filter{})
	t0 := time.Now()
	lines := strings.Split(strings.TrimSpace(sample), "\n")
	// Exec lines first, login lines later (e.g. auth.log shipped with a delay).
	for _, l := range lines[2:8] {
		a.Add(l, t0)
	}
	if got := a.Drain(t0, false); len(got) != 0 {
		t.Fatalf("shipped before login known: %+v", got)
	}
	a.Add(lines[0], t0.Add(time.Second))
	a.Add(lines[1], t0.Add(time.Second))
	if got := a.Drain(t0.Add(2*time.Second), false); len(got) != 1 {
		t.Fatalf("not resolved: %+v", got)
	}
	// An exec whose login never appears is dropped after the timeout.
	for _, l := range lines[9:12] {
		a.Add(l, t0)
	}
	if got := a.Drain(t0.Add(time.Minute), false); len(got) != 0 || a.Stats.NotShipped != 1 {
		t.Fatalf("%+v %+v", got, a.Stats)
	}
}

func TestEventWithoutEOEAndSplitArgs(t *testing.T) {
	in := `Oct 23 12:00:00 web1 sshd[2001]: Accepted publickey for ro from 203.0.113.10 port 51234 ssh2: ED25519-CERT SHA256:abc ID hallpass:rol_1:grt_2:con_3 (serial 1) CA ED25519 SHA256:def
type=LOGIN msg=audit(1792756800.100:500): pid=2001 uid=0 auid=1001 ses=7 res=1
type=SYSCALL msg=audit(1792756801.200:510): syscall=59 success=yes ppid=1 pid=5 auid=1001 uid=1001 ses=7 exe=2F7573722F62696E2F6563686F
type=EXECVE msg=audit(1792756801.200:510): argc=3 a0="echo" a1_len=6 a1[0]=616263 a1[1]=646566
type=EXECVE msg=audit(1792756801.200:510): a2="(null)"` + "\x1d" + `ARCH=x86_64`
	recs, _ := assemble(t, Filter{}, in)
	if len(recs) != 1 || recs[0].Exe != "/usr/bin/echo" || strings.Join(recs[0].Argv, "|") != "echo|abcdef|" {
		t.Fatalf("%+v", recs)
	}
}

func TestParseRejectsJunk(t *testing.T) {
	for _, l := range []string{"", "type=X", "type=X msg=audit(abc): a=b", "type=X msg=audit(1.2:3): a=b", "type=X msg=xyz", "node=only"} {
		if _, err := ParseAuditLine(l); err == nil {
			t.Errorf("%q parsed", l)
		}
	}
	for _, l := range []string{
		"sshd[1]: Accepted password for ro from 1.2.3.4 port 1 ssh2",
		"sshd[x]: Accepted publickey for ro from 1.2.3.4 port 1 ssh2: ED25519 SHA256:abc",
		"sshd[1]: Accepted publickey for ro from 1.2.3.4 port 1 ssh2: ED25519 SHA256:abc ID hallpass:a:b:c (serial 1) CA ED25519 SHA256:d",
	} {
		if _, ok := ParseSSHDLine(l); ok {
			t.Errorf("%q parsed", l)
		}
	}
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	line, err := GenerateKeyFile(p, "c@web1")
	if err != nil || !strings.HasPrefix(line, "ssh-ed25519 ") || !strings.HasSuffix(line, " c@web1") {
		t.Fatalf("%q %v", line, err)
	}
	if _, err := GenerateKeyFile(p, ""); err == nil {
		t.Fatal("overwrote existing key")
	}
	k, err := LoadKeyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := PublicLine(k.Public().(ed25519.PublicKey), "c@web1")
	if pub != line {
		t.Fatalf("%q != %q", pub, line)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(p); err == nil {
		t.Fatal("world-readable key accepted")
	}
}

// fakeHallpass verifies signatures and sequence numbers like the real endpoint.
type fakeHallpass struct {
	mu       sync.Mutex
	pub      ed25519.PublicKey
	lastSeq  int64
	batches  []wire.Batch
	failNext int // respond 503 this many times
}

func (h *fakeHallpass) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if h.failNext > 0 {
		h.failNext--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	env, err := wire.DecodeEnvelope(body)
	if err != nil || wire.Verify(h.pub, env) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	b, err := wire.DecodeBatch(env.Payload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if b.Seq <= h.lastSeq {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "replay", "last_seq": h.lastSeq})
		return
	}
	h.lastSeq = b.Seq
	h.batches = append(h.batches, *b)
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(b.Records), "rejections": []any{}})
}

func TestShipper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := &fakeHallpass{pub: pub}
	srv := httptest.NewServer(h)
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "seq")
	clock := time.Unix(1792756800, 0)
	sh := &Shipper{URL: srv.URL, CollectorID: "dac_x", Key: priv, Client: srv.Client(), StatePath: state,
		Now: func() time.Time { return clock }, Sleep: func(context.Context, time.Duration) error { return nil }}
	recs, _ := assemble(t, Filter{}, sample)
	res, err := sh.Send(context.Background(), recs)
	if err != nil || res.Accepted != 1 || res.Batches != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if h.batches[0].Seq != clock.UnixMicro() {
		t.Fatalf("seq %d", h.batches[0].Seq)
	}
	// Transient failures are retried with the same envelope.
	h.failNext = 2
	if _, err := sh.Send(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	// Lost state and a clock behind HallPass: the collector resynchronizes from last_seq.
	h.lastSeq += 1000
	sh2 := &Shipper{URL: srv.URL, CollectorID: "dac_x", Key: priv, Client: srv.Client(), Now: func() time.Time { return clock.Add(-time.Hour) }}
	if _, err := sh2.Send(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	// Persisted state is reloaded.
	sh3 := &Shipper{StatePath: state}
	if err := sh3.LoadState(); err != nil || sh3.lastSeq != h.batches[1].Seq {
		t.Fatalf("state %d %v", sh3.lastSeq, err)
	}
	// A key HallPass does not know is a permanent error.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad := &Shipper{URL: srv.URL, CollectorID: "dac_x", Key: other, Client: srv.Client()}
	var pe *PermanentError
	if _, err := bad.Send(context.Background(), recs); !errors.As(err, &pe) || pe.Status != http.StatusUnauthorized {
		t.Fatalf("%v", err)
	}
	// Large inputs are split into several batches within the limits.
	many := make([]wire.Record, wire.MaxRecords+10)
	for i := range many {
		many[i] = recs[0]
	}
	res, err = sh.Send(context.Background(), many)
	if err != nil || res.Batches != 2 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRunFlushesAtEOF(t *testing.T) {
	var got []wire.Record
	sink := func(_ context.Context, recs []wire.Record) error { got = append(got, recs...); return nil }
	if err := Run(context.Background(), strings.NewReader(sample), NewAssembler(Filter{}), sink, time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	fail := func(context.Context, []wire.Record) error { return errors.New("down") }
	if err := Run(context.Background(), strings.NewReader(sample), NewAssembler(Filter{}), fail, time.Hour, nil); err == nil {
		t.Fatal("sink error swallowed")
	}
	var reported error
	if err := Run(context.Background(), strings.NewReader(sample), NewAssembler(Filter{}), fail, time.Hour, func(err error) { reported = err }); err != nil || reported == nil {
		t.Fatalf("%v %v", err, reported)
	}
}
