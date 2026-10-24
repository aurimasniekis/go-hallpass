// Package sshfront is the agent-facing SSH server: public-key-only authentication with identity taken from the
// verified key, pre-authentication limits, refusal of forwarding and subsystems, keepalives, and dispatch of
// session channels to the command handler (PLAN §7, HP-SSH-001..024).
package sshfront

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/tracing"
	"github.com/aurimasniekis/go-hallpass/internal/ratelimit"
	"github.com/aurimasniekis/go-hallpass/internal/sshalg"
	"github.com/aurimasniekis/go-hallpass/internal/sshban"
	"github.com/aurimasniekis/go-hallpass/internal/sshkeepalive"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// ServerVersion is the SSH identification string presented to agents.
const ServerVersion = "SSH-2.0-Hallpass"

// Permission extension keys carrying the verified identity (never derived from the SSH username, HP-SSH-002).
const (
	extAgent = "hallpass-agent-id"
	extKey   = "hallpass-key-id"
	extFP    = "hallpass-key-fp"
	extName  = "hallpass-agent-name"
)

// Conn is an authenticated agent connection.
type Conn struct {
	ID          string
	AgentID     string
	AgentName   string
	KeyID       string
	Fingerprint string
	SourceIP    netip.Addr
	ClientUser  string
	SSH         *ssh.ServerConn

	mu          sync.Mutex
	channels    int
	closeReason string
	refusals    int // refused requests and channels on this connection (SR-20)
	suppressed  int // refusals not audited individually since the last audited one
}

// SetCloseReason records why the connection is closing (first reason wins).
func (c *Conn) SetCloseReason(r string) {
	c.mu.Lock()
	if c.closeReason == "" {
		c.closeReason = r
	}
	c.mu.Unlock()
}

// CloseReason returns the recorded close reason ("client_closed" by default).
func (c *Conn) CloseReason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeReason == "" {
		return "client_closed"
	}
	return c.closeReason
}

// SessionHandler serves one "session" channel of an authenticated connection.
type SessionHandler interface {
	HandleSession(ctx context.Context, c *Conn, ch ssh.Channel, reqs <-chan *ssh.Request)
}

// HostKeySource provides the gateway host signers (credentials.Service).
type HostKeySource interface {
	GatewayHostSigners(ctx context.Context) ([]ssh.Signer, error)
}

// Server is the agent-facing SSH server.
type Server struct {
	cfg     config.SSHConfig
	agents  *agents.Service
	access  *access.Service
	audit   *audit.Writer
	store   *store.Store
	hosts   HostKeySource
	handler SessionHandler
	bans    *sshban.Service
	log     *slog.Logger
	m       *metrics.Metrics

	bus        *eventbus.Bus
	revalidate time.Duration

	unauth    chan struct{} // global pre-auth slots
	mu        sync.Mutex
	perSource map[string]int // pre-auth connections per source: IPv4 address or IPv6 /64 (sshban.Source)
	perWide   map[string]int // pre-auth connections per IPv6 /48 (SR-22)
	perAgent  map[string]int
	conns     map[*Conn]struct{}
	// authFails and authFailsAll rate-limit auth-failure audit rows per source (/64 for IPv6) and globally; memory is
	// bounded by ratelimit.Window (HP-SSH-003, SR-44).
	authFails, authFailsAll *ratelimit.Window
	// connDenials and agentDenials rate-limit audit rows for refused requests per connection and per agent (SR-20).
	connDenials, agentDenials *ratelimit.Window
	wg                        sync.WaitGroup
	closing                   bool
	stopConns                 context.CancelFunc
}

// Refusal and audit limits for authenticated agents (SR-20, T-01, T-22).
const (
	// MaxRefusalsPerConn closes a connection after this many refused channels or requests.
	MaxRefusalsPerConn = 64
	// deniedAuditsPerConn and deniedAuditsPerAgent bound individually audited refusals per minute; the rest are
	// counted and reported as "suppressed" on the next audited refusal or when the connection closes.
	deniedAuditsPerConn  = 10
	deniedAuditsPerAgent = 30
	// wideTierFactor caps one IPv6 /48 at this many times the per-source pre-auth limit (SR-22).
	wideTierFactor = 4
	// DefaultRevalidate is how often established connections re-check their key and agent (SR-15); it is well
	// inside the enforcement bound (access.EnforcementBound).
	DefaultRevalidate = 2 * time.Second
)

// Options configure the server.
type Options struct {
	Config  config.SSHConfig
	Agents  *agents.Service
	Access  *access.Service
	Audit   *audit.Writer
	Store   *store.Store
	Hosts   HostKeySource
	Handler SessionHandler
	// Bans refuses sources banned after repeated failed authentication (HP-SSH-026). Nil disables.
	Bans   *sshban.Service
	Logger *slog.Logger
	// Metrics records connection results, authentication failures, active connections and refused requests
	// (HP-OBS-004). Nil disables.
	Metrics *metrics.Metrics
	// Bus delivers key revocations and agent disables so established connections close at once (HP-AGT-005, SR-15).
	// Nil leaves only the periodic re-check.
	Bus *eventbus.Bus
	// Revalidate is the period of the database re-check of established connections (default DefaultRevalidate).
	Revalidate time.Duration
}

// New returns a server.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Revalidate <= 0 {
		o.Revalidate = DefaultRevalidate
	}
	return &Server{
		cfg: o.Config, agents: o.Agents, access: o.Access, audit: o.Audit, store: o.Store, hosts: o.Hosts, handler: o.Handler, bans: o.Bans, m: o.Metrics,
		log: obs.Component(o.Logger, "sshfront"), unauth: make(chan struct{}, max(o.Config.MaxUnauthenticated, 1)),
		bus: o.Bus, revalidate: o.Revalidate,
		perSource: map[string]int{}, perWide: map[string]int{}, perAgent: map[string]int{}, conns: map[*Conn]struct{}{},
		authFails:    &ratelimit.Window{Limit: 20, Period: time.Minute, MaxKeys: 4096},
		authFailsAll: &ratelimit.Window{Limit: 600, Period: time.Minute},
		connDenials:  &ratelimit.Window{Limit: deniedAuditsPerConn, Period: time.Minute, MaxKeys: 8192},
		agentDenials: &ratelimit.Window{Limit: deniedAuditsPerAgent, Period: time.Minute, MaxKeys: 8192},
	}
}

// Serve accepts connections until ctx is canceled or ln is closed. Canceling ctx only stops accepting: established
// connections keep running (graceful drain, HP-OPS-002) until they end or Shutdown is called.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	signers, err := s.hosts.GatewayHostSigners(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("gateway host keys: %w", err)
	}
	connCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	s.mu.Lock()
	s.stopConns = stop
	s.mu.Unlock()
	var sub *eventbus.Subscription
	if s.bus != nil {
		sub = s.bus.Subscribe(256, eventbus.TopicAgentKeyRevoked, eventbus.TopicAgentDisabled)
	}
	go s.watchCredentials(connCtx, sub)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // closed by ctx cancellation or the caller
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(connCtx, nc, signers)
		}()
	}
}

// Wait blocks until all connection goroutines have finished.
func (s *Server) Wait() { s.wg.Wait() }

// ActiveConnections returns the number of authenticated connections.
func (s *Server) ActiveConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Shutdown refuses new connections and closes every established one.
func (s *Server) Shutdown() {
	s.mu.Lock()
	s.closing = true
	if s.stopConns != nil {
		s.stopConns()
	}
	conns := make([]*Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.SetCloseReason("shutdown")
		_ = c.SSH.Close()
	}
}

func addrOf(nc net.Conn) netip.Addr {
	if ta, ok := nc.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ta.IP); ok {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

// wideSource returns the IPv6 /48 containing ip, or "" for IPv4.
func wideSource(ip netip.Addr) string {
	ip = ip.Unmap()
	if !ip.Is6() {
		return ""
	}
	p, _ := ip.Prefix(48)
	return p.String()
}

// acquirePreAuth enforces global and per-source pre-authentication limits (HP-SSH-013). A source is an IPv4
// address or an IPv6 /64 (the unit a single host controls, as for bans), and one IPv6 /48 may hold at most
// wideTierFactor times the per-source limit, so one allocation cannot take every global slot (SR-22).
func (s *Server) acquirePreAuth(ip netip.Addr) bool {
	select {
	case s.unauth <- struct{}{}:
	default:
		return false
	}
	src, wide := sshban.Source(ip), wideSource(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.perSource[src] >= s.cfg.MaxUnauthenticatedPerIP ||
		(wide != "" && s.perWide[wide] >= wideTierFactor*s.cfg.MaxUnauthenticatedPerIP) {
		<-s.unauth
		return false
	}
	s.perSource[src]++
	if wide != "" {
		s.perWide[wide]++
	}
	return true
}

func (s *Server) releasePreAuth(ip netip.Addr) {
	src, wide := sshban.Source(ip), wideSource(ip)
	s.mu.Lock()
	if s.perSource[src]--; s.perSource[src] <= 0 {
		delete(s.perSource, src)
	}
	if wide != "" {
		if s.perWide[wide]--; s.perWide[wide] <= 0 {
			delete(s.perWide, wide)
		}
	}
	s.mu.Unlock()
	<-s.unauth
}

func (s *Server) serverConfig(ctx context.Context, ip netip.Addr, signers []ssh.Signer, authFailed *atomic.Bool) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		Config:                  sshalg.Config(),
		ServerVersion:           ServerVersion,
		MaxAuthTries:            s.cfg.MaxAuthTries,
		PublicKeyAuthAlgorithms: sshalg.PublicKeyAuthAlgorithms,
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			id, err := s.agents.Authenticate(ctx, key, ip)
			if err != nil {
				return nil, err
			}
			return &ssh.Permissions{Extensions: map[string]string{
				extAgent: id.AgentID, extKey: id.KeyID, extFP: id.Fingerprint, extName: id.AgentName,
			}}, nil
		},
		AuthLogCallback: func(meta ssh.ConnMetadata, method string, err error) {
			if err == nil || method == "none" {
				return
			}
			authFailed.Store(true)
			var ae *agents.AuthError
			if !errors.As(err, &ae) {
				if method != "publickey" {
					s.m.SSHAuthFailed(metrics.AuthMethodRejected)
				}
				return
			}
			s.m.SSHAuthFailed(metrics.AuthFailReason(ae.Reason))
			s.recordAuthFailure(ctx, ip, meta, ae)
		},
	}
	for _, k := range signers {
		cfg.AddHostKey(k)
	}
	return cfg
}

// recordAuthFailure audits failed authentications, rate limited per source (IPv4 address or IPv6 /64) and globally
// (HP-SSH-003, SR-44).
func (s *Server) recordAuthFailure(ctx context.Context, ip netip.Addr, meta ssh.ConnMetadata, ae *agents.AuthError) {
	now := time.Now()
	if !s.authFails.Allow(sshban.Source(ip), now) || !s.authFailsAll.Allow("all", now) {
		return
	}
	_ = s.store.W().TxNamed(ctx, "sshfront.auth_failed", func(tx *store.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{
			Actor: audit.Actor{Type: audit.ActorAgent, ID: ae.AgentID}, Action: "ssh.auth.failed", Outcome: audit.OutcomeDenied,
			SourceIP: ip.String(), Details: map[string]any{"reason": ae.Reason, "fingerprint": ae.Fingerprint, "client_user": truncate(meta.User(), 64),
				"client_version": truncate(string(meta.ClientVersion()), 128)},
		})
		return err
	})
}

func (s *Server) serveConn(ctx context.Context, nc net.Conn, signers []ssh.Signer) {
	defer nc.Close()
	ip := addrOf(nc)
	if s.bans.Banned(ip) { // before any SSH processing (HP-SSH-026)
		s.m.SSHConnection(metrics.ConnBanned)
		return
	}
	if !s.acquirePreAuth(ip) {
		s.m.SSHConnection(s.refusal(metrics.ConnPreAuthLimit))
		return
	}
	preAuth := true
	defer func() {
		if preAuth {
			s.releasePreAuth(ip)
		}
	}()
	_ = nc.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout.D()))
	var authFailed atomic.Bool
	_, span := tracing.StartKind(ctx, tracing.SpanSSHAuth, trace.SpanKindServer)
	sconn, chans, reqs, err := ssh.NewServerConn(nc, s.serverConfig(ctx, ip, signers, &authFailed))
	if err != nil {
		res := metrics.ConnHandshakeFailed
		if authFailed.Load() {
			res = metrics.ConnAuthFailed
			s.bans.Failed(ctx, ip, "failed public-key authentication")
		}
		tracing.SetAttributes(span, tracing.Outcome("failure"))
		tracing.End(span, errors.New(string(res)))
		s.m.SSHConnection(res)
		return
	}
	tracing.SetAttributes(span, tracing.Outcome("success"), tracing.AgentID(sconn.Permissions.Extensions[extAgent]),
		tracing.KeyID(sconn.Permissions.Extensions[extKey]))
	tracing.End(span, nil)
	defer sconn.Close()
	_ = nc.SetDeadline(time.Time{})
	s.releasePreAuth(ip)
	preAuth = false

	// Identity comes from the Permissions of the key whose signature verified (CVE-2024-45337 class).
	ext := sconn.Permissions.Extensions
	c := &Conn{AgentID: ext[extAgent], AgentName: ext[extName], KeyID: ext[extKey], Fingerprint: ext[extFP], SourceIP: ip,
		ClientUser: sconn.User(), SSH: sconn}
	if c.AgentID == "" || c.KeyID == "" {
		return
	}
	if !s.addConn(c) {
		s.m.SSHConnection(s.refusal(metrics.ConnAgentLimit))
		s.log.Warn("agent connection limit reached", slog.String(obs.FieldAgentID, c.AgentID))
		return
	}
	defer s.removeConn(c)
	if c.ID, err = s.access.OpenConnection(ctx, access.ConnectionInfo{AgentID: c.AgentID, KeyID: c.KeyID, ClientUser: c.ClientUser,
		ClientVersion: string(sconn.ClientVersion()), SourceIP: ip.String()}); err != nil {
		s.m.SSHConnection(metrics.ConnResult("storage_error")) // exported as "other"
		s.log.Error("recording connection failed; closing (fail closed)", obs.Err(err))
		return
	}
	defer func() { _ = s.access.CloseConnection(context.WithoutCancel(ctx), c.ID, c.CloseReason()) }()
	defer s.flushSuppressed(ctx, c)
	s.m.SSHConnection(metrics.ConnAccepted)
	s.m.SSHConnectionOpened()
	defer s.m.SSHConnectionClosed()

	// Correlation IDs for every log record, span and audit event of this connection (HP-OBS-003).
	ctx = obs.WithIDs(ctx, obs.AgentID(c.AgentID), obs.KeyID(c.KeyID), obs.ConnectionID(c.ID))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.keepalive(cctx, c)
	go s.globalRequests(cctx, c, reqs)
	var wg sync.WaitGroup
	for nch := range chans {
		if !s.acceptChannel(cctx, c, nch) {
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		wg.Go(func() {
			defer c.releaseChannel()
			defer ch.Close()
			s.handler.HandleSession(cctx, c, ch, creqs)
		})
	}
	cancel()
	wg.Wait()
}

// refusal returns shutting_down while the server is closing, otherwise r.
func (s *Server) refusal(r metrics.ConnResult) metrics.ConnResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return metrics.ConnShuttingDown
	}
	return r
}

func (s *Server) addConn(c *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.perAgent[c.AgentID] >= s.cfg.MaxConnectionsPerAgent {
		return false
	}
	s.perAgent[c.AgentID]++
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) removeConn(c *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perAgent[c.AgentID]--; s.perAgent[c.AgentID] <= 0 {
		delete(s.perAgent, c.AgentID)
	}
	delete(s.conns, c)
}

func (c *Conn) releaseChannel() {
	c.mu.Lock()
	c.channels--
	c.mu.Unlock()
}

// acceptChannel admits only "session" channels within the per-connection limit; everything else — direct-tcpip,
// forwarded-tcpip, x11, auth-agent, streamlocal and unknown types — is refused and audited (HP-SSH-007).
func (s *Server) acceptChannel(ctx context.Context, c *Conn, nch ssh.NewChannel) bool {
	if nch.ChannelType() != "session" {
		s.m.SSHRefused(metrics.RefusedChannelType)
		_ = nch.Reject(ssh.Prohibited, "channel type not permitted by Hallpass")
		s.AuditDenied(ctx, c, "ssh.channel.denied", map[string]any{"channel_type": truncate(nch.ChannelType(), 64)})
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.channels >= s.cfg.MaxChannelsPerConn {
		_ = nch.Reject(ssh.ResourceShortage, "too many channels on this connection")
		return false
	}
	c.channels++
	return true
}

// globalRequests refuses every global request (tcpip-forward, streamlocal-forward, …) and audits forwarding attempts.
func (s *Server) globalRequests(ctx context.Context, c *Conn, reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
		switch r.Type {
		case "keepalive@openssh.com", "no-more-sessions@openssh.com", "hostkeys-prove-00@openssh.com":
		default:
			s.m.SSHRefused(refusedType(r.Type))
			s.AuditDenied(ctx, c, "ssh.global_request.denied", map[string]any{"request_type": truncate(r.Type, 64)})
		}
	}
}

// AuditDenied records a refused agent action (channel types, forwarding, subsystems). It is usable as Handler.Deny.
// Audit rows are rate limited per connection and per agent; refusals over the limit are counted and reported as
// "suppressed" on the next audited one (or at connection close), and a connection exceeding MaxRefusalsPerConn
// refusals is closed (SR-20).
func (s *Server) AuditDenied(ctx context.Context, c *Conn, action string, details map[string]any) {
	ctx = context.WithoutCancel(ctx)
	now := time.Now()
	c.mu.Lock()
	c.refusals++
	tooMany := c.refusals > MaxRefusalsPerConn
	allowed := s.connDenials.Allow(c.ID, now) && s.agentDenials.Allow(c.AgentID, now)
	suppressed := 0
	if allowed {
		suppressed, c.suppressed = c.suppressed, 0
	} else {
		c.suppressed++
	}
	c.mu.Unlock()
	if tooMany {
		c.SetCloseReason("too_many_refusals")
		if c.SSH != nil {
			_ = c.SSH.Close()
		}
	}
	if !allowed {
		return
	}
	if suppressed > 0 {
		details["suppressed"] = suppressed
	}
	s.auditDenied(ctx, c, action, details)
}

// flushSuppressed records refusals that were counted but not audited individually.
func (s *Server) flushSuppressed(ctx context.Context, c *Conn) {
	c.mu.Lock()
	n := c.suppressed
	c.suppressed = 0
	refusals := c.refusals
	c.mu.Unlock()
	if n > 0 {
		s.auditDenied(context.WithoutCancel(ctx), c, "ssh.denied.suppressed", map[string]any{"suppressed": n, "refusals": refusals})
	}
}

func (s *Server) auditDenied(ctx context.Context, c *Conn, action string, details map[string]any) {
	details["connection_id"] = c.ID
	_ = s.store.W().TxNamed(ctx, "sshfront.denied", func(tx *store.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorAgent, ID: c.AgentID}, Action: action,
			Outcome: audit.OutcomeDenied, SourceIP: c.SourceIP.String(), Details: details})
		return err
	})
}

// keepalive probes the client; after KeepaliveMaxMissed unanswered probes the connection is closed (HP-SSH-012).
func (s *Server) keepalive(ctx context.Context, c *Conn) {
	if reason := sshkeepalive.Run(ctx, c.SSH, s.cfg.KeepaliveInterval.D(), s.cfg.KeepaliveMaxMissed); reason != "" {
		c.SetCloseReason(reason)
		_ = c.SSH.Close()
	}
}

// refusedType maps a refused SSH request type to its metric label (HP-SSH-007).
func refusedType(t string) metrics.RefusedRequest {
	switch t {
	case "tcpip-forward", "cancel-tcpip-forward", "streamlocal-forward@openssh.com", "cancel-streamlocal-forward@openssh.com":
		return metrics.RefusedPortForward
	case "subsystem":
		return metrics.RefusedSubsystem
	case "x11-req":
		return metrics.RefusedX11
	case "auth-agent-req@openssh.com", "auth-agent-req":
		return metrics.RefusedAgentForward
	default:
		return metrics.Other
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// watchCredentials closes established connections whose key was revoked or whose agent was disabled (HP-AGT-005,
// SR-15): at once on the bus events, and by a periodic database re-check that also covers lost events. Destination
// channels are ended separately by the enforcer; closing the connection also ends its control-plane use (listing
// targets, filing requests).
func (s *Server) watchCredentials(ctx context.Context, sub *eventbus.Subscription) {
	var events <-chan eventbus.Event
	if sub != nil {
		defer sub.Close()
		events = sub.C
	}
	t := time.NewTicker(s.revalidate)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			switch ev.Topic {
			case eventbus.TopicAgentKeyRevoked:
				s.closeWhere(access.ReasonKeyRevoked, func(c *Conn) bool { return c.KeyID == ev.Key })
			case eventbus.TopicAgentDisabled:
				s.closeWhere(access.ReasonAgentDisabled, func(c *Conn) bool { return c.AgentID == ev.Key })
			}
		case <-t.C:
			s.revalidateConns(ctx)
		}
	}
}

// revalidateConns re-reads each connection's key and agent state (read pool only).
func (s *Server) revalidateConns(ctx context.Context) {
	s.mu.Lock()
	conns := make([]*Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		r, err := s.store.R().AuthLookup(ctx, c.Fingerprint)
		switch {
		case errors.Is(err, sql.ErrNoRows), err == nil && (r.KeyID != c.KeyID || r.AgentID != c.AgentID || r.KeyState != "active"):
			s.closeConn(c, access.ReasonKeyRevoked)
		case err == nil && r.Enabled != 1:
			s.closeConn(c, access.ReasonAgentDisabled)
		}
	}
}

func (s *Server) closeWhere(reason string, match func(*Conn) bool) {
	s.mu.Lock()
	var hit []*Conn
	for c := range s.conns {
		if match(c) {
			hit = append(hit, c)
		}
	}
	s.mu.Unlock()
	for _, c := range hit {
		s.closeConn(c, reason)
	}
}

func (s *Server) closeConn(c *Conn, reason string) {
	c.SetCloseReason(reason)
	s.log.Info("closing agent connection", slog.String(obs.FieldAgentID, c.AgentID), slog.String(obs.FieldKeyID, c.KeyID),
		slog.String("reason", reason))
	_ = c.SSH.Close()
}
