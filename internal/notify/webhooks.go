package notify

import (
	"net/http"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/notify/chat"
	"github.com/aurimasniekis/go-hallpass/internal/ratelimit"
)

// WebhookHandler serves /hooks/{slack|telegram}/{integration_id} (HP-API-009): no cookies, a per-integration
// rate limit (20 requests/s), and provider verification inside the adapter before any parsing beyond size limits.
func (svc *Service) WebhookHandler() http.Handler {
	limiter := &ratelimit.Window{Limit: 20, Period: time.Second}
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
		if !limiter.Allow(provider+"/"+id, svc.opts.Clock.Now()) {
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
