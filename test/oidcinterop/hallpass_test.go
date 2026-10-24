//go:build oidcinterop

package oidcinterop

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi"
	"github.com/aurimasniekis/go-hallpass/internal/oidc"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"
)

var sysActor = audit.Actor{Type: audit.ActorSystem, ID: "oidcinterop"}

func ptr[T any](v T) *T { return &v }

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func randomHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func randomUUID(t testing.TB) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// shiftClock is the real clock plus an adjustable offset. It lets a test make an honest, fresh IdP login look stale
// to HallPass (step-up auth_time refusal) without touching the IdP.
type shiftClock struct{ off atomic.Int64 }

func (c *shiftClock) Now() time.Time        { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *shiftClock) Shift(d time.Duration) { c.off.Store(int64(d)) }

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

// Since returns what was written after offset mark.
func (s *syncBuffer) Since(mark int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b.Bytes()[mark:])
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// hallpass is an in-process HallPass (development mode, so http://localhost issuers are accepted) serving the real
// HTTP API and SSO endpoints on a loopback port, exactly like internal/httpapi's test harness.
type hallpass struct {
	t    *testing.T
	ctx  context.Context
	A    *app.App
	Base string // public URL, e.g. http://127.0.0.1:PORT
	clk  *shiftClock
	logs *syncBuffer
}

func startHallpass(t *testing.T) *hallpass {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test listener
	must(t, err)
	cfg := config.Default()
	cfg.Mode = "development"
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.KEK.File = ""
	cfg.HTTP.Listen = ""
	cfg.PublicURL = "http://" + ln.Addr().String()
	ctx := context.Background()
	logs := &syncBuffer{}
	clk := &shiftClock{}
	a, err := app.New(ctx, cfg, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), app.WithClock(clk))
	must(t, err)
	api := httpapi.New(httpapi.Deps{Store: a.Store, Audit: a.Audit, Bus: a.Bus, Agents: a.Agents, Inventory: a.Inventory, Credentials: a.Credentials,
		Engine: a.Engine, Policy: a.Policy, Access: a.Access, Enforcer: a.Enforcer, Recording: a.Recording, Auth: a.Auth, OIDC: a.OIDC,
		Matrix: rbac.New(rbac.Options{}), Metrics: a.Metrics, BootID: a.BootID, Version: buildinfo.Get().Version},
		httpapi.Options{PublicURL: cfg.PublicURL, Clock: clk, Logger: a.Log, SessionRate: 100000, IPRate: 100000, AuthRate: 100000})
	rctx, cancel := context.WithCancel(ctx)
	go api.Run(rctx)
	srv := httptest.NewUnstartedServer(api.Handler())
	srv.Listener = ln
	srv.Start()
	t.Cleanup(func() {
		srv.Close()
		cancel()
		_ = a.Close()
		if t.Failed() {
			t.Logf("hallpass logs:\n%s", logs.String())
		}
	})
	return &hallpass{t: t, ctx: ctx, A: a, Base: cfg.PublicURL, clk: clk, logs: logs}
}

// RedirectURI is the single callback URI that must be registered at the IdP.
func (h *hallpass) RedirectURI() string { return h.A.OIDC.RedirectURI() }

// PostLogoutURI is what HallPass sends as post_logout_redirect_uri (Logout passes "/login").
func (h *hallpass) PostLogoutURI() string { return h.Base + "/login" }

// createProvider configures a provider like an administrator would: groups claim "groups", loopback IdP allowed
// (allow_private_network), RP-initiated logout on. scopes nil keeps HallPass's default (openid profile email).
func (h *hallpass) createProvider(slug, issuer, clientID, secret string, scopes []string) *oidc.Provider {
	h.t.Helper()
	in := oidc.ProviderInput{Slug: ptr(slug), DisplayName: ptr(slug + " interop"), Issuer: ptr(issuer),
		ClientID: ptr(clientID), ClientSecret: ptr(secret), GroupsClaim: ptr("groups"), AllowPrivateNetwork: ptr(true), EndSessionEnabled: ptr(true),
		Enabled: ptr(true)}
	if scopes != nil {
		in.Scopes = &scopes
	}
	p, err := h.A.OIDC.CreateProvider(h.ctx, sysActor, in)
	must(h.t, err)
	return p
}

func (h *hallpass) operator(email string, roles ...string) *opauth.Operator {
	h.t.Helper()
	op, err := h.A.Auth.Create(h.ctx, sysActor, opauth.CreateInput{Email: email, DisplayName: email, Roles: roles})
	must(h.t, err)
	return op
}

// me is the subset of GET /api/v1/me the tests read.
type me struct {
	Operator struct {
		ID          string   `json:"id"`
		Roles       []string `json:"roles"`
		Assignments []struct {
			Role   string `json:"role"`
			Source string `json:"source"`
		} `json:"role_assignments"`
	} `json:"operator"`
	CSRF    string `json:"csrf_token"`
	Session struct {
		ID     string    `json:"id"`
		Method string    `json:"method"`
		AuthAt time.Time `json:"auth_at"`
	} `json:"session"`
}

func (b *browser) me() (*me, int) {
	b.t.Helper()
	status, body := b.api("GET", "/api/v1/me")
	if status != 200 {
		return nil, status
	}
	var m me
	if err := json.Unmarshal(body, &m); err != nil {
		b.t.Fatalf("me: %v: %s", err, body)
	}
	b.csrf = m.CSRF
	return &m, status
}

// countAudit counts audit events with an action and outcome.
func (h *hallpass) countAudit(action, outcome string) int {
	h.t.Helper()
	var n int
	must(h.t, h.A.Store.ReadDB().QueryRowContext(h.ctx, `SELECT count(*) FROM audit_events WHERE action = ? AND outcome = ?`, action, outcome).Scan(&n))
	return n
}
