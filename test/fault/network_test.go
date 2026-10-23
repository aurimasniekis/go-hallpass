//go:build fault

package fault

import (
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshtest"
)

// endingExec runs every exec until stdin closes and reports start and end.
func endingExec(dest *sshtest.Server) (started, ended chan struct{}) {
	started, ended = make(chan struct{}, 8), make(chan struct{}, 8)
	dest.Exec = func(_ string, stdin io.Reader, _, _ io.Writer) uint32 {
		started <- struct{}{}
		_, _ = io.Copy(io.Discard, stdin)
		ended <- struct{}{}
		return 0
	}
	return started, ended
}

func keepalive(c *config.Config) {
	c.SSH.KeepaliveInterval = config.Duration(time.Second)
	c.SSH.KeepaliveMaxMissed = 2
	c.SSH.IdleTimeout = config.Duration(10 * time.Minute)
}

// FI-15: the destination path blackholes mid-session (packets silently dropped, no FIN/RST). Keepalives must detect
// the dead peer within the configured probes, close the channel and release its resources (HP-SSH-012, HP-SSH-015).
func TestFI15DestinationBlackhole(t *testing.T) {
	w := newWorld(t)
	px := startProxy(t, w.destAddr)
	w.destAddr = px.addr()
	g := w.start(t, withConfig(keepalive))
	started, _ := endingExec(w.dest)
	le := startExec(t, g.addr, w, "exec web1 -- sleep")
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("exec never started")
	}
	px.blackhole.Store(true)
	t0 := time.Now()
	bound := 3*time.Second + 5*time.Second // interval × (missed + 1) plus slack
	select {
	case err := <-le.done:
		t.Logf("blackholed destination detected after %s (exit %d)", time.Since(t0).Round(time.Millisecond), exitCode(err))
	case <-time.After(bound):
		t.Errorf("FINDING: channel to a blackholed destination still open after %s with ssh.keepalive_interval=1s and "+
			"keepalive_max_missed=2; the destination leg sends no keepalives (only the 10 m idle timeout would end it) "+
			"(HP-SSH-012: keepalives on both legs, dead peers detected)", bound)
		_ = le.c.Close()
	}
	if !eventually(5*time.Second, func() bool { return g.a.Enforcer.Count() == 0 }) {
		t.Errorf("enforcer still tracks %d live channels", g.a.Enforcer.Count())
	}
}

// Agent-leg counterpart of FI-15: the agent's network path blackholes; gateway keepalives close the connection and the
// destination session is released (HP-SSH-012, HP-SSH-015).
func TestAgentLegBlackhole(t *testing.T) {
	w := newWorld(t)
	g := w.start(t, withConfig(keepalive))
	started, ended := endingExec(w.dest)
	px := startProxy(t, g.addr)
	le := startExec(t, px.addr(), w, "exec web1 -- sleep")
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("exec never started")
	}
	_ = le // the client side hangs with the blackhole; only the gateway side is asserted
	px.blackhole.Store(true)
	t0 := time.Now()
	select {
	case <-ended:
		t.Logf("blackholed agent detected; destination session released after %s", time.Since(t0).Round(time.Millisecond))
	case <-time.After(8 * time.Second):
		t.Fatal("destination session still open 8 s after the agent path blackholed (keepalive 1 s × 2)")
	}
	if !eventually(5*time.Second, func() bool { return g.a.Enforcer.Count() == 0 }) {
		t.Errorf("enforcer still tracks %d live channels", g.a.Enforcer.Count())
	}
}

// FI-16: the destination's host key changes (the same address now answers with another key). The connection is
// refused with exit 88, an alert is recorded, and the impostor never sees the login credential (HP-SSH-011,
// HP-SRV-005).
func TestFI16DestinationHostKeyChanged(t *testing.T) {
	w := newWorld(t)
	px := startProxy(t, w.destAddr)
	w.destAddr = px.addr()
	g := w.start(t)
	if _, _, code := g.run("exec web1 -- id"); code != 0 {
		t.Fatalf("baseline exec: exit %d", code)
	}
	impostor := sshtest.Start(t)
	pub := queryStr(t, g.a.Store.ReadDB(), `SELECT public_key FROM login_credentials WHERE role_id = ? AND state = 'active'`, w.roleID)
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	must(t, err)
	impostor.Authorize(pk) // a login with the credential would be recorded
	var ran atomic.Bool
	impostor.Exec = func(string, io.Reader, io.Writer, io.Writer) uint32 { ran.Store(true); return 0 }
	h, p := impostor.Addr()
	px.target.Store(net.JoinHostPort(h, itoa(p)))
	_, errOut, code := g.run("exec web1 -- id")
	if code != sshproxy.CodeDestinationUnavailable {
		t.Fatalf("exit %d (%q), want %d", code, errOut, sshproxy.CodeDestinationUnavailable)
	}
	if ran.Load() || len(impostor.Logins()) != 0 {
		t.Fatal("credential accepted by / command run on the impostor")
	}
	if n := queryInt(t, g.a.Store.ReadDB(), `SELECT count(*) FROM audit_events WHERE action = 'server.host_key_mismatch'`); n == 0 {
		t.Fatal("no host key mismatch alert recorded")
	}
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{digits[n%10]}, b...)
	}
	return string(b)
}

// FI-17: the agent stops reading output. Memory stays bounded, the destination is throttled by the SSH window, and
// the idle timeout ends the session (HP-SSH-014, HP-SSH-012).
func TestFI17AgentStopsReading(t *testing.T) {
	w := newWorld(t)
	g := w.start(t, withConfig(func(c *config.Config) { c.SSH.IdleTimeout = config.Duration(2 * time.Second) }))
	var written atomic.Int64
	destDone := make(chan struct{})
	w.dest.Exec = func(_ string, _ io.Reader, stdout, _ io.Writer) uint32 {
		defer close(destDone)
		chunk := make([]byte, 4096)
		for {
			n, err := stdout.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return 1
			}
		}
	}
	c, err := g.client()
	must(t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(t, err)
	_, err = s.StdoutPipe() // never read
	must(t, err)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	must(t, s.Start("exec web1 -- stream"))
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	time.Sleep(1500 * time.Millisecond)
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	sent := written.Load()
	t.Logf("paused agent: destination sent %d KiB; heap %d → %d MiB", sent>>10, before.HeapAlloc>>20, during.HeapAlloc>>20)
	if sent > 16<<20 {
		t.Fatalf("destination not throttled: %d MiB sent to a paused agent", sent>>20)
	}
	if during.HeapAlloc > before.HeapAlloc+64<<20 {
		t.Fatalf("heap grew by %d MiB", (during.HeapAlloc-before.HeapAlloc)>>20)
	}
	select {
	case <-destDone:
		t.Log("idle timeout closed the destination session")
	case <-time.After(5 * time.Second):
		t.Fatal("idle timeout did not close the destination session of a paused agent")
	}
	d := g.a.Store.ReadDB()
	select {
	case err := <-done:
		t.Logf("paused agent's session ended: %v", err)
	case <-time.After(8 * time.Second):
		st := queryStr(t, d, `SELECT state FROM ssh_channels ORDER BY opened_at DESC LIMIT 1`)
		t.Errorf("FINDING: the idle-terminated channel of an agent that stopped reading is never closed on the agent side "+
			"(channel row %q, enforcer tracks %d): the proxy's output pump stays blocked writing to the full agent window, so "+
			"the termination path (exit status, channel close, CloseChannel) is never reached until the agent disconnects "+
			"(HP-SSH-012, HP-SSH-015)", st, g.a.Enforcer.Count())
		_ = c.Close()
	}
}

// HP-SSH-015: closing the agent side releases the destination connection even when the destination ignores stdin EOF
// and produces no output (or its path is dead).
func TestAgentDisconnectReleasesDestination(t *testing.T) {
	for _, blackhole := range []bool{false, true} {
		name := "silent_destination"
		if blackhole {
			name = "blackholed_destination"
		}
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			px := startProxy(t, w.destAddr)
			w.destAddr = px.addr()
			g := w.start(t)
			started := make(chan struct{}, 1)
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			w.dest.Exec = func(string, io.Reader, io.Writer, io.Writer) uint32 {
				started <- struct{}{}
				<-stop // ignores stdin, prints nothing
				return 0
			}
			le := startExec(t, g.addr, w, "exec web1 -- sleep")
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("exec never started")
			}
			d := g.a.Store.ReadDB()
			if !eventually(5*time.Second, func() bool {
				return queryStr(t, d, `SELECT state FROM ssh_channels ORDER BY opened_at DESC LIMIT 1`) == "active"
			}) {
				t.Fatal("channel never active")
			}
			px.blackhole.Store(blackhole)
			_ = le.c.Close()
			if !eventually(5*time.Second, func() bool { return g.a.Enforcer.Count() == 0 }) {
				st := queryStr(t, g.a.Store.ReadDB(), `SELECT state FROM ssh_channels ORDER BY opened_at DESC LIMIT 1`)
				t.Errorf("FINDING: 5 s after the agent disconnected the channel is still live (enforcer %d, row %q); the destination "+
					"session is only released when the destination closes it or the idle timeout fires (HP-SSH-015)",
					g.a.Enforcer.Count(), st)
			}
		})
	}
}
