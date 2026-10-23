package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi"
	"github.com/aurimasniekis/go-hallpass/internal/jobs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/health"
	"github.com/aurimasniekis/go-hallpass/internal/obs/tracing"
	"github.com/aurimasniekis/go-hallpass/internal/ratelimit"
	"github.com/aurimasniekis/go-hallpass/internal/rbac"

	"github.com/aurimasniekis/go-hallpass/internal/sshfront"
)

// Serve runs the gateway until ctx is canceled, then drains: new connections are refused, established sessions get
// shutdown.drain_timeout to finish, and whatever remains is terminated and recorded as "shutdown" (HP-OPS-002).
// sshLn may be nil to listen on ssh.listen.
func (a *App) Serve(ctx context.Context, sshLn net.Listener) error {
	if a.Proxy == nil {
		a.NewProxy()
	}
	var err error
	if sshLn == nil {
		if sshLn, err = Listen(ctx, a.Cfg.SSH.Listen); err != nil {
			return err
		}
	}
	tp, err := tracing.Setup(ctx, a.Cfg.Telemetry, tracing.WithLogger(a.Log))
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = tp.Shutdown(sctx)
		cancel()
	}()
	h := &sshfront.Handler{Access: a.Access, Engine: a.Engine, Proxy: a.Proxy, Bus: a.Bus, Log: a.Log,
		WaitDefault: a.Cfg.Access.WaitTimeoutDefault.D(), WaitMax: a.Cfg.Access.WaitTimeoutMax.D(), Metrics: a.Metrics}
	srv := sshfront.New(sshfront.Options{Config: a.Cfg.SSH, Agents: a.Agents, Access: a.Access, Audit: a.Audit, Store: a.Store,
		Hosts: a.Credentials, Handler: h, Logger: a.Log, Metrics: a.Metrics})
	var sshUp atomic.Bool
	_ = a.Health.Register(health.Flag("ssh.listener", "listener_down", sshUp.Load))
	h.Deny = srv.AuditDenied

	bgCtx, stopBG := context.WithCancel(context.WithoutCancel(ctx))
	waitBG := a.RunBackground(bgCtx)
	go a.Health.Run(bgCtx, 15*time.Second)

	httpLn := a.HTTPListener
	if httpLn == nil && a.Cfg.HTTP.Listen != "" {
		if httpLn, err = Listen(ctx, a.Cfg.HTTP.Listen); err != nil {
			stopBG()
			waitBG()
			return err
		}
	}
	var httpSrv *http.Server
	httpDone := make(chan error, 1)
	if httpLn != nil {
		api := a.NewAPI()
		go api.Run(bgCtx)
		go func() {
			jobs.Periodic(bgCtx, a.Log, "api.idempotency_purge", time.Hour, false, api.PurgeIdempotency)
		}()
		httpSrv = &http.Server{Handler: a.rootHandler(api.Handler()), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return bgCtx }}
		go func() {
			var err error
			if a.Cfg.HTTP.TLSCertFile != "" {
				err = httpSrv.ServeTLS(httpLn, a.Cfg.HTTP.TLSCertFile, a.Cfg.HTTP.TLSKeyFile)
			} else {
				err = httpSrv.Serve(httpLn)
			}
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			httpDone <- err
		}()
	} else {
		httpDone <- nil
	}
	attrs := []any{slog.String("ssh", sshLn.Addr().String()), slog.String("boot_id", a.BootID)}
	if httpLn != nil {
		attrs = append(attrs, slog.String("http", httpLn.Addr().String()))
	}
	metricsSrv := a.serveMetrics(bgCtx)
	a.Log.Info("hallpass serving", attrs...)

	sshUp.Store(true)
	a.Health.MarkReady()
	serveErr := srv.Serve(ctx, sshLn)
	a.Health.MarkStopping()
	sshUp.Store(false)
	if metricsSrv != nil {
		_ = metricsSrv.Close()
	}
	if httpSrv != nil {
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = httpSrv.Shutdown(shutCtx)
		cancel()
	}
	if err := <-httpDone; err != nil && serveErr == nil {
		serveErr = err
	}

	drain := a.Cfg.Shutdown.DrainTimeout.D()
	a.Log.Info("draining", slog.Int("connections", srv.ActiveConnections()), slog.Duration("timeout", drain))
	deadline := time.Now().Add(drain)
	for srv.ActiveConnections() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if n := a.Enforcer.Count(); n > 0 {
		a.Log.Warn("terminating sessions still active after drain", slog.Int("channels", n))
		a.Enforcer.TerminateAll("shutdown")
	}
	srv.Shutdown()
	srv.Wait()
	stopBG()
	waitBG()
	a.Log.Info("hallpass stopped")
	return serveErr
}

// NewAPI builds the operator HTTP API (PLAN §8).
func (a *App) NewAPI() *httpapi.Server {
	var proxies []netip.Prefix
	for _, c := range a.Cfg.HTTP.TrustedProxies {
		if p, err := netip.ParsePrefix(c); err == nil {
			proxies = append(proxies, p)
		}
	}
	rc := a.Cfg.RBAC
	return httpapi.New(httpapi.Deps{Store: a.Store, Audit: a.Audit, Bus: a.Bus, Agents: a.Agents, Inventory: a.Inventory, Credentials: a.Credentials,
		Engine: a.Engine, Policy: a.Policy, Access: a.Access, Enforcer: a.Enforcer, Recording: a.Recording, Auth: a.Auth, OIDC: a.OIDC,
		Matrix: rbac.New(rbac.Options{AuditorAddressRead: rc.AuditorAddressRead, ApproverRecordingPlay: rc.ApproverRecordingPlay,
			AuditorRecordingExport: rc.AuditorRecordingExport, ApproversCanLockdown: rc.ApproversCanLockdown}),
		Metrics: a.Metrics,
		Notify:  a.Notify, Destaudit: a.Destaudit, BootID: a.BootID, Version: buildinfo.Get().Version},
		httpapi.Options{PublicURL: a.Cfg.PublicURL, Secure: strings.HasPrefix(a.Cfg.PublicURL, "https://"), TrustedProxies: proxies, UI: a.UI,
			Clock: a.Clock, Logger: a.Log})
}

// rootHandler adds the infrastructure endpoints (HP-OPS-001) and HTTP metrics/tracing (HP-OBS-003/004) around the API.
// /metrics is served here only when Prometheus is enabled without a separate http.metrics_listen.
func (a *App) rootHandler(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", a.Health.LivenessHandler())
	mux.Handle("GET /readyz", a.Health.ReadinessHandler())
	if a.Cfg.Telemetry.Prometheus && a.Cfg.HTTP.MetricsListen == "" {
		mux.Handle("GET /metrics", a.Metrics.Handler())
	}
	mux.Handle("/hooks/", a.Notify.WebhookHandler())
	// Signature-authenticated collector batches: no operator session or CSRF token (HP-REC-012, ADR-0037).
	mux.Handle("POST /hooks/destaudit/{collector_id}", destauditLimit(a.Clock, a.Destaudit.Handler()))
	mux.Handle("/", api)
	return tracing.HTTPMiddleware(a.Metrics.HTTPMiddleware(mux))
}

// serveMetrics starts the separate metrics listener (http.metrics_listen) when configured.
func (a *App) serveMetrics(ctx context.Context) *http.Server {
	if !a.Cfg.Telemetry.Prometheus || a.Cfg.HTTP.MetricsListen == "" {
		return nil
	}
	ln, err := Listen(ctx, a.Cfg.HTTP.MetricsListen)
	if err != nil {
		a.Log.Error("metrics listener", slog.String("error", err.Error()))
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", a.Metrics.Handler())
	mux.Handle("GET /healthz", a.Health.LivenessHandler())
	mux.Handle("GET /readyz", a.Health.ReadinessHandler())
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return srv
}

// RootHandlerForTest exposes the infrastructure endpoints without the API (tests).
func (a *App) RootHandlerForTest() http.Handler { return a.rootHandler(http.NotFoundHandler()) }

// destauditLimit rate-limits collector batches per collector ID (bounded memory; unauthenticated IDs included).
func destauditLimit(clk clock.Clock, next http.Handler) http.Handler {
	limiter := &ratelimit.Window{Limit: 10, Period: time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(r.PathValue("collector_id"), clk.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
