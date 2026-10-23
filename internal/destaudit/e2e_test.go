package destaudit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/destaudit/collector"
)

// The reference collector's output, shipped through the HTTP handler, lands on the right session timeline.
func TestCollectorToTimeline(t *testing.T) {
	f := newFx(t)
	a := f.activity(f.a1, "ca:ca_test")
	other := f.activity(f.a2, "ca:ca_test")
	login := f.clk.Now().Add(-30e9) // 30s ago
	sec, ms := login.Unix(), login.Nanosecond()/1e6
	lines := strings.Join([]string{
		fmt.Sprintf("Oct 23 11:59:30 web1 sshd[2001]: Accepted publickey for ro from 203.0.113.10 port 5 ssh2: ED25519-CERT SHA256:eph ID %s (serial 1) CA ED25519 SHA256:ca", a.keyID()),
		fmt.Sprintf("type=LOGIN msg=audit(%d.%03d:500): pid=2001 uid=0 auid=1001 ses=7 res=1", sec, ms),
		fmt.Sprintf("type=SYSCALL msg=audit(%d.%03d:510): syscall=59 success=yes ppid=2005 pid=2010 auid=1001 uid=1001 ses=7 exe=\"/usr/bin/id\"", sec+5, ms),
		fmt.Sprintf("type=EXECVE msg=audit(%d.%03d:510): argc=1 a0=\"id\"", sec+5, ms),
		fmt.Sprintf("type=EOE msg=audit(%d.%03d:510):", sec+5, ms),
	}, "\n")
	asm := collector.NewAssembler(collector.Filter{})
	for l := range strings.SplitSeq(lines, "\n") {
		asm.Add(l, f.clk.Now())
	}
	recs := asm.Drain(f.clk.Now(), true)
	if len(recs) != 1 {
		t.Fatalf("assembled %+v", recs)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /hooks/destaudit/{collector_id}", f.svc.Handler())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sh := &collector.Shipper{URL: srv.URL + "/hooks/destaudit/" + f.collector.ID, CollectorID: f.collector.ID, Key: f.priv, Client: srv.Client(), Now: f.clk.Now}
	res, err := sh.Send(context.Background(), recs)
	if err != nil || res.Accepted != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := len(destExecEvents(f.timeline(a.grant.SessionID))); n != 1 {
		t.Fatalf("events on session: %d", n)
	}
	if n := len(destExecEvents(f.timeline(other.grant.SessionID))); n != 0 {
		t.Fatalf("events on other session: %d", n)
	}
	d, err := f.svc.SessionRecords(f.ctx, a.grant.SessionID, 1)
	if err != nil || len(d) != 1 {
		t.Fatal(err)
	}
	full, err := f.svc.RecordDetails(f.ctx, d[0].ID)
	if err != nil || full.Exe != "/usr/bin/id" || full.Argv[0] != "id" || full.Confidence != ConfidenceHigh {
		t.Fatalf("%+v %v", full, err)
	}
}
