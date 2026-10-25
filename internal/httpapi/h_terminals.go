package httpapi

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/webterm"
)

// Web terminals (ADR-0055). openTerminal creates the grant and a single-use ticket; streamTerminal upgrades to a
// WebSocket for the same operator and web session, opens the connection under the built-in agent and runs the shell
// through the SSH data plane, which records it and enforces the grant. Closing the socket ends the grant.

const (
	terminalTicketTTL = time.Minute
	terminalSizeWait  = 15 * time.Second
	maxTerminalTicket = 1024
)

type terminalTicket struct {
	grantID, operatorID, sessionID string
	expires                        time.Time
}

type terminalTickets struct {
	mu sync.Mutex
	m  map[string]terminalTicket
}

func (t *terminalTickets) issue(tk terminalTicket, now time.Time) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]terminalTicket{}
	}
	for k, v := range t.m {
		if now.After(v.expires) {
			delete(t.m, k)
		}
	}
	if len(t.m) >= maxTerminalTicket {
		return "", apperr.New(apperr.CodeRateLimited, "too many terminals waiting to connect")
	}
	id := rand.Text()
	tk.expires = now.Add(terminalTicketTTL)
	t.m[id] = tk
	return id, nil
}

// consume returns and removes a ticket that matches grantID, operatorID and sessionID and has not expired.
func (t *terminalTickets) consume(id, grantID, operatorID, sessionID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk, ok := t.m[id]
	if !ok {
		return false
	}
	delete(t.m, id)
	return now.Before(tk.expires) && subtle.ConstantTimeCompare([]byte(tk.grantID), []byte(grantID)) == 1 &&
		tk.operatorID == operatorID && tk.sessionID == sessionID
}

func (s *Server) OpenTerminal(c *gen.Call) (*gen.Result, error) {
	var in struct {
		ServerID string `json:"server_id"`
		RoleID   string `json:"role_id"`
		Duration int64  `json:"duration"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if s.d.Proxy == nil {
		return nil, apperr.New(apperr.CodeUnavailable, "web terminals are not available on this server")
	}
	g, err := s.d.Access.OpenConsole(c.R.Context(), access.OpenConsoleInput{Operator: operatorInfo(c), ServerID: in.ServerID, RoleID: in.RoleID,
		Duration: time.Duration(in.Duration) * time.Second})
	if err != nil {
		return nil, err
	}
	ticket, err := s.terminals.issue(terminalTicket{grantID: g.ID, operatorID: c.Principal.Operator.ID, sessionID: c.Principal.SessionID}, s.o.Clock.Now())
	if err != nil {
		return nil, err
	}
	return created(struct {
		GrantID    string    `json:"grant_id"`
		SessionID  string    `json:"session_id"`
		ServerID   string    `json:"server_id"`
		RoleID     string    `json:"role_id"`
		RemoteUser string    `json:"remote_user"`
		ExpiresAt  time.Time `json:"expires_at"`
		Ticket     string    `json:"ticket"`
		StreamPath string    `json:"stream_path"`
	}{g.ID, g.SessionID, g.ServerID, g.RoleID, g.RemoteUser, g.ExpiresAt, ticket, "/api/v1/terminals/" + g.ID + "/stream"})
}

// hijacker exposes Hijack through http.ResponseController, so wrapping middleware (metrics, tracing) that implements
// Unwrap does not hide it from the WebSocket server.
type hijacker struct{ http.ResponseWriter }

func (h hijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(h.ResponseWriter).Hijack()
}

func (s *Server) StreamTerminal(c *gen.Call) (*gen.Result, error) {
	r := c.R
	grantID := r.PathValue("id")
	// A WebSocket handshake is a GET, so the cross-site checks of mutations do not run: require our own origin and a
	// ticket bound to this operator and web session (cross-site WebSocket hijacking).
	if o := r.Header.Get("Origin"); o == "" || o != s.origin {
		return nil, ErrOrigin
	}
	if c.Principal.TokenID != "" {
		return nil, errTokenNotAllowed
	}
	if !s.terminals.consume(r.URL.Query().Get("ticket"), grantID, c.Principal.Operator.ID, c.Principal.SessionID, s.o.Clock.Now()) {
		return nil, apperr.New(apperr.CodeForbidden, "invalid or expired terminal ticket; open the terminal again")
	}
	g, err := s.d.Access.GetGrant(r.Context(), grantID)
	if err != nil || g.OperatorID != c.Principal.Operator.ID || !g.ActiveAt(s.o.Clock.Now()) {
		return nil, access.ErrAccessEnded
	}
	operatorID, sourceIP := c.Principal.Operator.ID, s.clientIP(r)
	email := c.Principal.Operator.Email
	srv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil }, // origin checked above
		Handler: func(ws *websocket.Conn) {
			s.runTerminal(ws, g, operatorID, email, sourceIP)
		},
	}
	srv.ServeHTTP(hijacker{c.W}, r)
	return nil, nil //nolint:nilnil // the connection was hijacked; nothing more to write
}

func (s *Server) runTerminal(ws *websocket.Conn, g *access.Grant, operatorID, email, sourceIP string) {
	_ = ws.SetDeadline(time.Time{}) // the HTTP server's timeouts must not end a long session
	ctx := context.WithoutCancel(ws.Request().Context())
	log := s.log.With(slog.String(obs.FieldGrantID, g.ID), slog.String("operator_id", operatorID))
	ch := webterm.New(ws)
	defer func() {
		_ = ch.Close()
		if err := s.d.Access.CloseConsole(ctx, g.ID, operatorID); err != nil {
			log.Error("ending web terminal grant failed", obs.Err(err))
		}
	}()
	cols, rows, err := ch.InitialSize(terminalSizeWait)
	if err != nil {
		return
	}
	connID, err := s.d.Access.OpenConnection(ctx, access.ConnectionInfo{AgentID: access.ConsoleAgentID, KeyID: access.ConsoleKeyID, OperatorID: operatorID,
		ClientUser: email, ClientVersion: "hallpass-web-terminal", SourceIP: sourceIP})
	if err != nil {
		log.Error("opening web terminal connection failed", obs.Err(err))
		return
	}
	defer func() { _ = s.d.Access.CloseConnection(ctx, connID, "closed") }()
	notify := func(msg string) { _, _ = ch.Write([]byte("\r\n[hallpass] " + msg + "\r\n")) }
	res := s.d.Proxy.Run(ctx, &sshproxy.Session{
		ConnectionID: connID, AgentID: access.ConsoleAgentID, KeyID: access.ConsoleKeyID, SourceIP: sourceIP, Grant: g, Kind: access.KindShell,
		PTY:        &sshproxy.PTYRequest{Term: "xterm-256color", Cols: cols, Rows: rows},
		Env:        [][2]string{{"TERM", "xterm-256color"}},
		Agent:      ch,
		AgentReqs:  ch.Requests(),
		Notify:     notify,
		OperatorID: operatorID,
	})
	if !res.Delivered {
		if res.Detail != "" {
			notify(res.Detail)
		}
		code := res.GatewayCode
		_, _ = ch.SendRequest("exit-status", false, sshproxy.ExitStatusPayload(uint32(code))) //nolint:gosec // gateway codes are small
	}
}
