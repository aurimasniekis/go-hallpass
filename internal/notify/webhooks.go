package notify

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/ratelimit"
)

// Webhook rate limits (HP-NTF-012, PLAN §10.7).
const (
	// WebhookPerIntegration is the per-integration limit (requests per second).
	WebhookPerIntegration = 20
	// WebhookPerSource is the per-source limit (IPv4 address or IPv6 /64, requests per second). It is above the
	// per-integration limit so a gateway behind a reverse proxy (one source) keeps the per-integration budget.
	WebhookPerSource = 40
)

// WebhookHandler serves /hooks/{slack|telegram}/{integration_id} (HP-API-009): no cookies, rate limits per source
// and per integration, and provider verification inside the adapter before any parsing beyond size limits.
//
// Only IDs of existing integrations reach the per-integration limiter: unknown IDs are answered 404 from a cached
// ID set, so a flood of random IDs cannot crowd real integrations into the limiter's shared overflow window and
// drop their callbacks (SR-19).
func (svc *Service) WebhookHandler() http.Handler {
	perID := &ratelimit.Window{Limit: WebhookPerIntegration, Period: time.Second}
	perSource := &ratelimit.Window{Limit: WebhookPerSource, Period: time.Second, MaxKeys: 8192}
	known := svc.knownIntegrations
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/hooks/")
		provider, id, ok := strings.Cut(rest, "/")
		if !ok || (provider != chat.ProviderSlack && provider != chat.ProviderTelegram) || id == "" || strings.Contains(id, "/") || len(id) > 64 {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		now := svc.opts.Clock.Now()
		if !perSource.Allow(ratelimit.SourceKeyOf(r.RemoteAddr), now) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		if !known.Contains(r.Context(), id, now) {
			http.NotFound(w, r)
			return
		}
		if !perID.Allow(provider+"/"+id, now) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		h, err := svc.webhookHandler(r.Context(), provider, id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		r.Header.Del("Cookie")
		h.ServeHTTP(w, r)
	})
}

// integrationIDs lists the IDs of enabled integrations (KnownSet loader).
func (svc *Service) integrationIDs(ctx context.Context) ([]string, error) {
	rows, err := svc.s.R().ListIntegrations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Enabled == 1 {
			out = append(out, r.ID)
		}
	}
	return out, nil
}
