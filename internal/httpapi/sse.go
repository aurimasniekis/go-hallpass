package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"
)

// SSE contract (PLAN §8.3, HP-API-005): frames carry `id: <boot_id>.<n>`; a ring buffer of the last 4096 events
// supports Last-Event-ID resume; unknown IDs, other boots and per-client overflow (256) produce `event: reset`.
// Events carry only type, resource and ID — never reasons, addresses or secrets — and are filtered per subscriber
// by permission at fan-out. Limits: 4 streams per web session, 512 total. Heartbeat every 15 s.
const (
	ringSize        = 4096
	clientBuffer    = 256
	streamsPerSess  = 4
	streamsTotal    = 512
	heartbeatPeriod = 15 * time.Second
	revalidateEvery = 30 * time.Second
)

// sseRoute maps bus topics to SSE event types and the permission needed to receive them.
var sseRoute = map[string]struct {
	typ, resource string
	perm          rbac.Permission
}{
	eventbus.TopicRequestCreated:  {"request.created", "request", rbac.RequestsRead},
	eventbus.TopicRequestUpdated:  {"request.updated", "request", rbac.RequestsRead},
	eventbus.TopicGrantUpdated:    {"grant.updated", "grant", rbac.RequestsRead},
	eventbus.TopicSessionUpdated:  {"session.updated", "access_session", rbac.SessionsRead},
	eventbus.TopicActivityStarted: {"activity.started", "channel", rbac.SessionsRead},
	eventbus.TopicActivityEnded:   {"activity.ended", "channel", rbac.SessionsRead},
	eventbus.TopicNotification:    {"notification.updated", "notification", rbac.RequestsRead},
	eventbus.TopicAudit:           {"audit.appended", "audit_event", rbac.AuditRead},
	eventbus.TopicSystemStatus:    {"system.status", "system", rbac.DashboardView},
	eventbus.TopicLockdown:        {"system.status", "system", rbac.DashboardView},
	eventbus.TopicPolicyChanged:   {"policy.changed", "policy", rbac.PolicyRead},
}

type sseEvent struct {
	n    uint64
	perm rbac.Permission
	data []byte
	typ  string
}

type sseClient struct {
	ch       chan *sseEvent
	session  string
	mu       sync.Mutex
	roles    []string
	overflow bool
}

// Hub fans bus events out to SSE clients.
type Hub struct {
	d   Deps
	clk clock.Clock
	log *slog.Logger

	mu      sync.Mutex
	n       uint64
	ring    []*sseEvent
	clients map[*sseClient]struct{}
	perSess map[string]int
}

// NewHub returns a hub.
func NewHub(d Deps, clk clock.Clock, log *slog.Logger) *Hub {
	return &Hub{d: d, clk: clk, log: log, clients: map[*sseClient]struct{}{}, perSess: map[string]int{}}
}

// Run consumes bus events until ctx ends.
func (h *Hub) Run(ctx context.Context) {
	if h.d.Bus == nil {
		<-ctx.Done()
		return
	}
	topics := make([]string, 0, len(sseRoute))
	for t := range sseRoute {
		topics = append(topics, t)
	}
	sub := h.d.Bus.Subscribe(1024, topics...)
	defer sub.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-sub.C:
			h.Publish(ev)
		}
	}
}

// Publish records an event in the ring and fans it out.
func (h *Hub) Publish(ev eventbus.Event) {
	r, found := sseRoute[ev.Topic]
	if !found {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.n++
	payload := map[string]any{"type": r.typ, "resource": r.resource, "resource_id": ev.Key, "version": nil, "at": h.clk.Now().UTC(),
		"summary": map[string]any{}}
	if st, isStr := ev.Payload.(string); isStr && len(st) <= 32 {
		payload["summary"] = map[string]any{"state": st}
	}
	data, _ := json.Marshal(payload)
	e := &sseEvent{n: h.n, perm: r.perm, data: data, typ: r.typ}
	if len(h.ring) == ringSize {
		copy(h.ring, h.ring[1:])
		h.ring = h.ring[:ringSize-1]
	}
	h.ring = append(h.ring, e)
	for c := range h.clients {
		select {
		case c.ch <- e:
		default:
			c.mu.Lock()
			c.overflow = true
			c.mu.Unlock()
		}
	}
}

func (h *Hub) register(p *opauth.Principal) (*sseClient, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= streamsTotal || h.perSess[p.SessionID] >= streamsPerSess {
		return nil, apperr.New(apperr.CodeRateLimited, "too many live-event streams")
	}
	c := &sseClient{ch: make(chan *sseEvent, clientBuffer), session: p.SessionID, roles: p.Operator.Roles}
	h.clients[c] = struct{}{}
	h.perSess[p.SessionID]++
	h.d.Metrics.SSEClientConnected()
	return c, nil
}

func (h *Hub) unregister(c *sseClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
	h.d.Metrics.SSEClientDisconnected()
	if h.perSess[c.session]--; h.perSess[c.session] <= 0 {
		delete(h.perSess, c.session)
	}
}

// replay returns events after lastID, or ok=false when the ID is unknown, from another boot or too old.
func (h *Hub) replay(lastID string) ([]*sseEvent, bool) {
	boot, nstr, found := strings.Cut(lastID, ".")
	if !found || boot != h.d.BootID {
		return nil, false
	}
	n, err := strconv.ParseUint(nstr, 10, 64)
	if err != nil {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > h.n || (len(h.ring) > 0 && n+1 < h.ring[0].n && n != h.n) {
		return nil, false
	}
	var out []*sseEvent
	for _, e := range h.ring {
		if e.n > n {
			out = append(out, e)
		}
	}
	return out, true
}

// Clients returns the number of connected streams.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// StreamEvents serves GET /api/v1/events.
func (s *Server) StreamEvents(c *gen.Call) (*gen.Result, error) {
	flusher, canFlush := c.W.(http.Flusher)
	if !canFlush {
		return nil, apperr.New(apperr.CodeUnavailable, "streaming not supported")
	}
	h := s.hub
	cl, err := h.register(c.Principal)
	if err != nil {
		return nil, err
	}
	defer h.unregister(cl)
	rc := http.NewResponseController(c.W)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{}) // the server's ReadTimeout must not end long-lived streams
	w := c.W
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")

	send := func(e *sseEvent) error {
		cl.mu.Lock()
		allowed := s.d.Matrix.Has(cl.roles, e.perm)
		cl.mu.Unlock()
		if !allowed {
			return nil
		}
		_, err := fmt.Fprintf(w, "id: %s.%d\nevent: %s\ndata: %s\n\n", s.d.BootID, e.n, e.typ, e.data)
		return err
	}
	reset := func() error {
		h.mu.Lock()
		n := h.n
		h.mu.Unlock()
		_, err := fmt.Fprintf(w, "id: %s.%d\nevent: reset\ndata: {\"type\":\"reset\"}\n\n", s.d.BootID, n)
		return err
	}
	if last := c.R.Header.Get("Last-Event-ID"); last != "" {
		events, known := h.replay(last)
		if !known {
			if err := reset(); err != nil {
				return nil, nil //nolint:nilerr // client went away
			}
		}
		for _, e := range events {
			if err := send(e); err != nil {
				return nil, nil //nolint:nilerr // client went away
			}
		}
	}
	flusher.Flush()

	hb := time.NewTicker(heartbeatPeriod)
	defer hb.Stop()
	reval := time.NewTicker(revalidateEvery)
	defer reval.Stop()
	ctx := c.R.Context()
	for {
		var err error
		select {
		case <-ctx.Done():
			return nil, nil
		case <-hb.C:
			_, err = fmt.Fprint(w, ": hb\n\n")
		case <-reval.C:
			// Session revocation closes the stream; role changes take effect for later events.
			p, aerr := s.d.Auth.Authenticate(ctx, c.SessionToken)
			if aerr != nil {
				return nil, nil
			}
			cl.mu.Lock()
			cl.roles = p.Operator.Roles
			cl.mu.Unlock()
			continue
		case e := <-cl.ch:
			cl.mu.Lock()
			over := cl.overflow
			cl.overflow = false
			cl.mu.Unlock()
			if over {
				for len(cl.ch) > 0 {
					<-cl.ch
				}
				err = reset()
			} else {
				err = send(e)
			}
		}
		if err != nil {
			return nil, nil //nolint:nilerr // client went away
		}
		flusher.Flush()
	}
}
