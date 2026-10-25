package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshtest"
)

func strPtr(s string) *string { return &s }

// terminalTarget creates web1/ops on an in-process destination with an active login key.
func terminalTarget(t *testing.T, h *harness) (srvID, roleID string) {
	t.Helper()
	dest := sshtest.Start(t)
	host, port := dest.Addr()
	srv, err := h.a.Inventory.CreateServer(h.ctx, sysActor, inventory.ServerInput{Alias: strPtr("web1"), Address: &host, Port: &port})
	must(t, err)
	_, err = h.a.Inventory.AddHostIdentity(h.ctx, sysActor, srv.ID, dest.KnownHostsLine(0))
	must(t, err)
	role, err := h.a.Inventory.CreateRole(h.ctx, sysActor, srv.ID, inventory.RoleInput{Alias: strPtr("ops"), RemoteUser: strPtr("ops")})
	must(t, err)
	cred, err := h.a.Credentials.Generate(h.ctx, sysActor, role.ID)
	must(t, err)
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cred.PublicKey))
	must(t, err)
	dest.Authorize(pk)
	_, err = h.a.Credentials.Probe(h.ctx, sysActor, cred.ID)
	must(t, err)
	_, err = h.a.Credentials.Activate(h.ctx, sysActor, cred.ID, false)
	must(t, err)
	return srv.ID, role.ID
}

func dialTerminal(t *testing.T, h *harness, c *client, path, ticket, origin string) (*websocket.Conn, error) {
	t.Helper()
	u, _ := url.Parse(h.base)
	wsURL := "ws://" + u.Host + path + "?ticket=" + url.QueryEscape(ticket)
	cfg, err := websocket.NewConfig(wsURL, origin)
	must(t, err)
	var cookies []string
	for _, ck := range c.hc.Jar.Cookies(u) {
		cookies = append(cookies, ck.Name+"="+ck.Value)
	}
	cfg.Header = http.Header{"Cookie": {strings.Join(cookies, "; ")}}
	return websocket.DialConfig(cfg)
}

type terminalOpened struct {
	GrantID    string `json:"grant_id"`
	SessionID  string `json:"session_id"`
	Ticket     string `json:"ticket"`
	StreamPath string `json:"stream_path"`
}

// ADR-0055: an administrator opens a recorded terminal; the WebSocket needs the same origin, session and a single-use
// ticket; typing reaches the destination; closing ends the grant and finalizes the recording.
func TestWebTerminal(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{dataPln: true, matrix: rbac.Options{WebTerminal: true}, config: func(c *config.Config) {
		c.Egress.AllowCIDRs = []string{"127.0.0.0/8"}
		c.Egress.AllowSpecialCIDRs = []string{"127.0.0.1/32"}
	}})
	admin := h.bootstrapAdmin()
	srvID, roleID := terminalTarget(t, h)

	var op terminalOpened
	admin.ok("openTerminal", 201, http.MethodPost, "/api/v1/terminals", map[string]any{"server_id": srvID, "role_id": roleID}).json(t, &op)
	if op.StreamPath != "/api/v1/terminals/"+op.GrantID+"/stream" || op.Ticket == "" {
		t.Fatalf("opened %+v", op)
	}
	if _, err := dialTerminal(t, h, admin, op.StreamPath, op.Ticket, "http://evil.example"); err == nil {
		t.Fatal("cross-origin WebSocket accepted")
	}
	// The cross-origin attempt did not consume the ticket (refused before), so it still works once.
	ws, err := dialTerminal(t, h, admin, op.StreamPath, op.Ticket, h.base)
	must(t, err)
	if _, err := dialTerminal(t, h, admin, op.StreamPath, op.Ticket, h.base); err == nil {
		t.Fatal("ticket reused")
	}
	send := func(v any) {
		b, _ := json.Marshal(v)
		must(t, websocket.Message.Send(ws, string(b)))
	}
	send(map[string]any{"type": "resize", "cols": 100, "rows": 30})
	send(map[string]any{"type": "input", "data": "echo hello-terminal\n"})
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var got strings.Builder
	for !strings.Contains(got.String(), "hello-terminal") {
		var frame []byte
		if err := websocket.Message.Receive(ws, &frame); err != nil {
			t.Fatalf("receive (got %q): %v", got.String(), err)
		}
		if len(frame) > 0 && frame[0] == '{' {
			continue // control frame
		}
		got.Write(frame)
	}
	must(t, ws.Close())

	deadline := time.Now().Add(10 * time.Second)
	var g *access.Grant
	for time.Now().Before(deadline) {
		g, err = h.a.Access.GetGrant(h.ctx, op.GrantID)
		must(t, err)
		if g.State != access.GrantActive {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if g.State != access.GrantRevoked || g.EndReason != access.ReasonTerminalClosed || g.OperatorID == "" || g.AgentID != access.ConsoleAgentID {
		t.Fatalf("grant after close: %+v", g)
	}
	for time.Now().Before(deadline) {
		var total, open int
		must(t, h.a.Store.ReadDB().QueryRowContext(h.ctx, `SELECT count(*), coalesce(sum(s.state = 'open'), 0) FROM recording_segments s
			JOIN access_sessions a ON a.id = s.access_session_id WHERE a.grant_id = ?`, op.GrantID).Scan(&total, &open))
		if total == 1 && open == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("terminal recording not finalized")
}

// Only administrators open terminals, and only when console.terminal is on.
func TestWebTerminalPermission(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{dataPln: true, matrix: rbac.Options{WebTerminal: false}})
	admin := h.bootstrapAdmin()
	if r := admin.do(http.MethodPost, "/api/v1/terminals", map[string]any{"server_id": "srv_x", "role_id": "rol_x"}); r.status != http.StatusForbidden {
		t.Fatalf("terminal with console.terminal off: %d %s", r.status, r.body)
	}
	on := newHarnessWith(t, harnessOptions{dataPln: true, matrix: rbac.Options{WebTerminal: true}})
	on.bootstrapAdmin()
	viewer := on.principalClient([]string{"viewer", "approver", "auditor"}, "password")
	if r := viewer.do(http.MethodPost, "/api/v1/terminals", map[string]any{"server_id": "srv_x", "role_id": "rol_x"}); r.status != http.StatusForbidden {
		t.Fatalf("non-administrator opened a terminal: %d %s", r.status, r.body)
	}
}
