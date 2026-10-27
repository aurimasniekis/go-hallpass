package apiproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apirules"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
)

// Host is the destination name an agent forwards to (ssh -L 18080:hallpass:443 <gateway>) to reach the API proxy.
const Host = "hallpass"

// Limits and timeouts.
const (
	connectTimeout   = 30 * time.Second
	maxConnectBytes  = 64 << 10
	handshakeTimeout = 30 * time.Second
	idleTimeout      = 5 * time.Minute
	maxHeaderBytes   = 64 << 10
	// MaxGraphQLBody bounds the body read to classify GraphQL operations; a larger body counts as unknown.
	MaxGraphQLBody = 1 << 20
	candidateTTL   = 2 * time.Second
	maxLoggedBytes = 2048
)

// Options configure the proxy.
type Options struct {
	Service   *Service
	Access    *access.Service
	Enforcer  *access.Enforcer
	Engine    *policy.Engine
	Inventory *inventory.Service
	// Guard is the egress policy for API hosts (public addresses by default; see config api_proxy).
	Guard *egress.Guard
	Log   *slog.Logger
	Clock clock.Clock
	// RootCAs verifies the APIs' certificates (nil: the system roots).
	RootCAs *x509.CertPool
	// UpstreamPort overrides 443 for upstream connections (tests).
	UpstreamPort int
}

// Proxy is the data plane: it serves tunnels opened by authenticated agents.
type Proxy struct {
	o         Options
	log       *slog.Logger
	leafKey   *ecdsa.PrivateKey
	transport *http.Transport

	mu     sync.Mutex
	leaves map[string]*leafCert          // server ID + host → cached leaf
	tokens map[string]oauth2.TokenSource // credential ref → Google access tokens
}

// New returns a proxy.
func New(o Options) (*Proxy, error) {
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	port := 443
	if o.UpstreamPort != 0 {
		port = o.UpstreamPort
	}
	p := &Proxy{o: o, log: obs.Component(o.Log, "apiproxy"), leafKey: key, leaves: map[string]*leafCert{}, tokens: map[string]oauth2.TokenSource{}}
	p.transport = &http.Transport{
		// Never an environment proxy: API hosts are dialed directly, through the egress policy.
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return o.Guard.Dial(ctx, host, port)
		},
		TLSClientConfig:       &tls.Config{RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ExpectContinueTimeout: time.Second,
	}
	return p, nil
}

// Close releases idle upstream connections.
func (p *Proxy) Close() { p.transport.CloseIdleConnections() }

// Client is the authenticated agent connection a tunnel belongs to.
type Client struct {
	ConnectionID string
	AgentID      string
	KeyID        string
	SourceIP     string
	// Deny audits a refusal that has no session to record it in (rate limited by the caller); may be nil.
	Deny func(action string, details map[string]any)
}

func (c Client) deny(action string, details map[string]any) {
	if c.Deny != nil {
		c.Deny(action, details)
	}
}

// Serve runs one tunnel: an HTTP CONNECT to an API host, TLS with the target's CA, then HTTP/1.1 requests until
// either side closes, the tunnel is idle for idleTimeout, or access ends.
func (p *Proxy) Serve(ctx context.Context, cl Client, conn io.ReadWriteCloser) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	timer := time.AfterFunc(connectTimeout, func() { _ = conn.Close() })
	lr := &io.LimitedReader{R: conn, N: maxConnectBytes}
	br := bufio.NewReaderSize(lr, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		timer.Stop()
		return
	}
	_ = req.Body.Close()
	t, ok := p.open(ctx, cl, req, conn)
	timer.Stop()
	if !ok {
		return
	}
	lr.N = math.MaxInt64
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	// net.Pipe gives the TLS and HTTP layers deadlines, which an SSH channel does not have.
	inner, outer := net.Pipe()
	go func() { _, _ = io.Copy(outer, br); _ = outer.Close() }()
	go func() { _, _ = io.Copy(conn, outer); _ = conn.Close() }()
	t.closeRaw = func() { _ = inner.Close(); _ = outer.Close(); _ = conn.Close() }

	tlsConn := tls.Server(inner, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, t.host) {
				return nil, fmt.Errorf("TLS server name %q does not match the CONNECT host", hello.ServerName)
			}
			return p.certificate(ctx, t.srv.ID, t.host)
		},
	})
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = tlsConn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		t.close(ctx)
		return
	}
	srv := &http.Server{
		Handler:           t,
		ReadHeaderTimeout: connectTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(slog.DiscardHandler, slog.LevelError),
		BaseContext:       func(net.Listener) context.Context { return t.ctx },
	}
	ln := newOneConnListener(tlsConn)
	srv.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed || s == http.StateHijacked {
			ln.done()
		}
	}
	_ = srv.Serve(ln)
	t.close(ctx)
}

// open checks the CONNECT request and finds the API target the agent may see for its host. On refusal it answers
// with a plain HTTP error.
func (p *Proxy) open(ctx context.Context, cl Client, req *http.Request, conn io.Writer) (*tunnel, bool) {
	refuse := func(status int, msg string) (*tunnel, bool) {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s",
			status, http.StatusText(status), len(msg)+1, msg+"\n")
		return nil, false
	}
	if req.Method != http.MethodConnect {
		return refuse(http.StatusMethodNotAllowed, "hallpass: the API proxy only carries HTTPS (CONNECT); use https:// URLs")
	}
	host, port, err := net.SplitHostPort(req.Host)
	host = strings.ToLower(host)
	if err != nil || port != "443" || !apirules.ValidHost(host) || strings.HasPrefix(host, "*.") {
		return refuse(http.StatusBadRequest, "hallpass: CONNECT needs an API host name and port 443")
	}
	srv, err := p.target(ctx, cl.AgentID, host)
	if err != nil {
		if !errors.Is(err, policy.ErrNotFoundOrForbidden) {
			p.log.Error("API target lookup failed", obs.Err(err))
			return refuse(http.StatusServiceUnavailable, "hallpass: the API proxy is unavailable")
		}
		cl.deny("api.connect.denied", map[string]any{"host": truncate(host, 253)})
		return refuse(http.StatusForbidden, "hallpass: "+host+" is not an API host you can reach (not found or not permitted)")
	}
	tctx, cancel := context.WithCancel(ctx)
	t := &tunnel{p: p, cl: cl, srv: srv, host: host, ctx: tctx, cancel: cancel, chans: map[string]*tunnelChannel{}}
	return t, true
}

// target returns the visible API target covering host. When several do, the first by alias wins.
func (p *Proxy) target(ctx context.Context, agentID, host string) (*inventory.Server, error) {
	snap, err := p.o.Engine.Current(ctx)
	if err != nil {
		return nil, err
	}
	for _, vs := range snap.Visible(agentID) {
		srv, err := p.o.Inventory.GetServer(ctx, vs.Server.ID)
		if err != nil {
			return nil, err
		}
		if srv.Kind == inventory.KindAPI && srv.Enabled && srv.API.Covers(host) {
			return srv, nil
		}
	}
	return nil, policy.ErrNotFoundOrForbidden
}

// certificate returns a leaf for host signed by the target's CA, minted once and reused until close to expiry.
func (p *Proxy) certificate(ctx context.Context, serverID, host string) (*tls.Certificate, error) {
	ca, err := p.o.Service.signer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	now := p.o.Clock.Now()
	key := serverID + "|" + host
	p.mu.Lock()
	defer p.mu.Unlock()
	lc := p.leaves[key]
	if lc == nil || lc.notAfter.Sub(now) < leafRenew || !lc.issuedBy(ca) {
		if lc, err = ca.leaf(host, p.leafKey, now); err != nil {
			return nil, err
		}
		lc.ca = ca.cert
		p.leaves[key] = lc
	}
	return &tls.Certificate{Certificate: lc.chain, PrivateKey: lc.key}, nil
}

// authorize sets the access profile's credential on an upstream request.
func (p *Proxy) authorize(ctx context.Context, h http.Header, c *secretCredential) error {
	switch c.Type {
	case CredBearer:
		h.Set("Authorization", "Bearer "+string(c.secret))
	case CredHeader:
		h.Set(c.Header, string(c.secret))
	case CredBasic:
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+string(c.secret))))
	case CredGoogle:
		tok, err := p.googleToken(ctx, c)
		if err != nil {
			return err
		}
		h.Set("Authorization", "Bearer "+tok)
	default:
		return fmt.Errorf("unknown credential type %q", c.Type)
	}
	return nil
}

// googleToken returns a cached access token for a service account key, fetching a new one from Google's token
// endpoint (through the egress policy) when it expires.
func (p *Proxy) googleToken(ctx context.Context, c *secretCredential) (string, error) {
	ref := c.Ref()
	p.mu.Lock()
	ts := p.tokens[ref]
	if ts == nil {
		sa, err := parseServiceAccount(c.secret)
		if err != nil {
			p.mu.Unlock()
			return "", err
		}
		cfg := &jwt.Config{Email: sa.ClientEmail, PrivateKey: []byte(sa.PrivateKey), PrivateKeyID: sa.PrivateKeyID,
			Scopes: c.Scopes, TokenURL: GoogleTokenURL}
		// The token source outlives this request: give it its own context with the proxy's transport.
		tctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: p.transport, Timeout: 30 * time.Second})
		ts = oauth2.ReuseTokenSource(nil, cfg.TokenSource(tctx)) //nolint:contextcheck // cached across requests; must not end with one

		for k := range p.tokens { // older versions of the same credential
			if strings.HasPrefix(k, "api_credential:"+c.RoleID+":") {
				delete(p.tokens, k)
			}
		}
		p.tokens[ref] = ts
	}
	p.mu.Unlock()
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("google token: %w", err)
	}
	return tok.AccessToken, nil
}

// oneConnListener hands one connection to http.Server and then blocks until it is closed.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
	used   bool
	mu     sync.Mutex
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, closed: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) done()          { l.once.Do(func() { close(l.closed) }) }
func (l *oneConnListener) Close() error   { l.done(); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
