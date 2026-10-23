// Package sshfront is the agent-facing SSH server: public-key-only authentication with identity taken from the
// verified key, pre-authentication limits, refusal of forwarding and subsystems, keepalives, and dispatch of
// session channels to the command handler (PLAN §7, HP-SSH-001..024).
package sshfront

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/sshalg"
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
	log     *slog.Logger

	unauth    chan struct{} // global pre-auth slots
	mu        sync.Mutex
	perIP     map[netip.Addr]int
	perAgent  map[string]int
	conns     map[*Conn]struct{}
	authFails *rateLimiter
	wg        sync.WaitGroup
	closing   bool
	stopConns context.CancelFunc
}

// Options configure the server.
type Options struct {
	Config  config.SSHConfig
	Agents  *agents.Service
	Access  *access.Service
	Audit   *audit.Writer
	Store   *store.Store
	Hosts   HostKeySource
	Handler SessionHandler
	Logger  *slog.Logger
}

// New returns a server.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		cfg: o.Config, agents: o.Agents, access: o.Access, audit: o.Audit, store: o.Store, hosts: o.Hosts, handler: o.Handler,
		log: obs.Component(o.Logger, "sshfront"), unauth: make(chan struct{}, max(o.Config.MaxUnauthenticated, 1)),
		perIP: map[netip.Addr]int{}, perAgent: map[string]int{}, conns: map[*Conn]struct{}{},
		authFails: newRateLimiter(20, time.Minute),
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

// acquirePreAuth enforces global and per-IP pre-authentication limits (HP-SSH-013).
func (s *Server) acquirePreAuth(ip netip.Addr) bool {
	select {
	case s.unauth <- struct{}{}:
	default:
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.perIP[ip] >= s.cfg.MaxUnauthenticatedPerIP {
		<-s.unauth
		return false
	}
	s.perIP[ip]++
	return true
}

func (s *Server) releasePreAuth(ip netip.Addr) {
	s.mu.Lock()
	if s.perIP[ip]--; s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
	s.mu.Unlock()
	<-s.unauth
}

func (s *Server) serverConfig(ctx context.Context, ip netip.Addr, signers []ssh.Signer) *ssh.ServerConfig {
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
			var ae *agents.AuthError
			if !errors.As(err, &ae) {
				return
			}
			s.recordAuthFailure(ctx, ip, meta, ae)
		},
	}
	for _, k := range signers {
		cfg.AddHostKey(k)
	}
	return cfg
}

// recordAuthFailure audits failed authentications, rate limited per source IP (HP-SSH-003).
func (s *Server) recordAuthFailure(ctx context.Context, ip netip.Addr, meta ssh.ConnMetadata, ae *agents.AuthError) {
	if !s.authFails.allow(ip.String()) {
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
	if !s.acquirePreAuth(ip) {
		return
	}
	preAuth := true
	defer func() {
		if preAuth {
			s.releasePreAuth(ip)
		}
	}()
	_ = nc.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout.D()))
	sconn, chans, reqs, err := ssh.NewServerConn(nc, s.serverConfig(ctx, ip, signers))
	if err != nil {
		return
	}
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
		s.log.Warn("agent connection limit reached", slog.String(obs.FieldAgentID, c.AgentID))
		return
	}
	defer s.removeConn(c)
	if c.ID, err = s.access.OpenConnection(ctx, access.ConnectionInfo{AgentID: c.AgentID, KeyID: c.KeyID, ClientUser: c.ClientUser,
		ClientVersion: string(sconn.ClientVersion()), SourceIP: ip.String()}); err != nil {
		s.log.Error("recording connection failed; closing (fail closed)", obs.Err(err))
		return
	}
	defer func() { _ = s.access.CloseConnection(context.WithoutCancel(ctx), c.ID, c.CloseReason()) }()

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
			s.AuditDenied(ctx, c, "ssh.global_request.denied", map[string]any{"request_type": truncate(r.Type, 64)})
		}
	}
}

// AuditDenied records a refused agent action (channel types, forwarding, subsystems). It is usable as Handler.Deny.
func (s *Server) AuditDenied(ctx context.Context, c *Conn, action string, details map[string]any) {
	ctx = context.WithoutCancel(ctx)
	details["connection_id"] = c.ID
	_ = s.store.W().TxNamed(ctx, "sshfront.denied", func(tx *store.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorAgent, ID: c.AgentID}, Action: action,
			Outcome: audit.OutcomeDenied, SourceIP: c.SourceIP.String(), Details: details})
		return err
	})
}

// keepalive probes the client; after KeepaliveMaxMissed unanswered probes the connection is closed (HP-SSH-012).
func (s *Server) keepalive(ctx context.Context, c *Conn) {
	interval := s.cfg.KeepaliveInterval.D()
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	missed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := c.SSH.SendRequest("keepalive@openssh.com", true, nil)
			done <- err
		}()
		select {
		case <-ctx.Done():
			return
		case err := <-done:
			if err != nil {
				c.SetCloseReason("keepalive_failed")
				_ = c.SSH.Close()
				return
			}
			missed = 0
		case <-time.After(interval):
			missed++
			if missed >= s.cfg.KeepaliveMaxMissed {
				c.SetCloseReason("keepalive_timeout")
				_ = c.SSH.Close()
				return
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// rateLimiter allows n events per window per key.
type rateLimiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string][]time.Time
}

func newRateLimiter(n int, window time.Duration) *rateLimiter {
	return &rateLimiter{n: n, window: window, seen: map[string][]time.Time{}}
}

func (r *rateLimiter) allow(key string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	ts := r.seen[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) > r.window {
		i++
	}
	ts = ts[i:]
	if len(ts) >= r.n {
		r.seen[key] = ts
		return false
	}
	r.seen[key] = append(ts, now)
	if len(r.seen) > 10000 {
		for k, v := range r.seen {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > r.window {
				delete(r.seen, k)
			}
		}
	}
	return true
}
