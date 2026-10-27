package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// runEnv is run with environment variables sent before the command (what "SendEnv" does).
func (g *gw) runEnv(env map[string]string, cmd string) (string, string, int) {
	g.t.Helper()
	c, err := g.client(g.key)
	must(g.t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(g.t, err)
	defer s.Close()
	for k, v := range env {
		must(g.t, s.Setenv(k, v))
	}
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	err = s.Run(cmd)
	code := 0
	var ee *ssh.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitStatus()
	case err != nil:
		g.t.Fatalf("%s: %v", cmd, err)
	}
	return out.String(), errb.String(), code
}

// Two Claude Code conversations of one agent: each gets its own grant, sees only its own, and the session shows in
// whoami. HALLPASS_SESSION takes precedence over CLAUDE_CODE_SESSION_ID.
func TestGatewayAgentSessions(t *testing.T) {
	g := startGateway(t)
	a := map[string]string{"CLAUDE_CODE_SESSION_ID": "0a1b2c3d-1111-4222-8333-444455556666"}
	b := map[string]string{"CLAUDE_CODE_SESSION_ID": "9f8e7d6c-1111-4222-8333-444455556666"}

	if out, _, code := g.runEnv(a, "whoami --json"); code != 0 || !strings.Contains(out, `"agent_session":"0a1b2c3d-1111-4222-8333-444455556666"`) {
		t.Fatalf("whoami a: %d %s", code, out)
	}
	if out, _, code := g.runEnv(map[string]string{"CLAUDE_CODE_SESSION_ID": "x-1", "HALLPASS_SESSION": "build-7"}, "whoami --json"); code != 0 ||
		!strings.Contains(out, `"agent_session":"build-7"`) {
		t.Fatalf("whoami precedence: %d %s", code, out)
	}
	if out, _, code := g.run("whoami --json"); code != 0 || !strings.Contains(out, `"agent_session":null`) {
		t.Fatalf("whoami default: %d %s", code, out)
	}
	if _, stderr, code := g.runEnv(map[string]string{"HALLPASS_SESSION": "bad session"}, "whoami"); code != 81 || !strings.Contains(stderr, "HALLPASS_SESSION") {
		t.Fatalf("invalid session: %d %q", code, stderr)
	}

	if _, stderr, code := g.runEnv(a, "exec web1 -- true"); code != 0 {
		t.Fatalf("exec a: %d %q", code, stderr)
	}
	count := func(env map[string]string) int {
		t.Helper()
		out, _, code := g.runEnv(env, "sessions --json")
		if code != 0 {
			t.Fatalf("sessions: %d", code)
		}
		return strings.Count(out, `"grant_id"`)
	}
	if n := count(a); n != 1 {
		t.Fatalf("session a sees %d grants", n)
	}
	if n := count(b); n != 0 {
		t.Fatalf("session b sees %d grants of session a", n)
	}
	if n := count(nil); n != 0 {
		t.Fatalf("the default session sees %d grants of session a", n)
	}
	// Session b gets its own grant (auto-approved here) rather than reusing a's.
	if _, stderr, code := g.runEnv(b, "exec web1 -- true"); code != 0 {
		t.Fatalf("exec b: %d %q", code, stderr)
	}
	if n := count(b); n != 1 {
		t.Fatalf("session b sees %d grants", n)
	}
	var grants int
	must(t, g.a.Store.ReadDB().QueryRow(`SELECT count(DISTINCT agent_session) FROM grants WHERE state = 'active'`).Scan(&grants))
	if grants != 2 {
		t.Fatalf("%d sessions hold grants, want 2", grants)
	}
}
