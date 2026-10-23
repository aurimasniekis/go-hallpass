// Package app wires Hallpass components together and runs the process lifecycle (PLAN §3.4).
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/credentials"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/jobs"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/notify"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/fsstat"
	"github.com/aurimasniekis/go-hallpass/internal/obs/health"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/oidc"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/outbox"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/recording"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	webui "github.com/aurimasniekis/go-hallpass/web"
)

// App holds every long-lived component.
type App struct {
	Cfg    *config.Config
	Log    *slog.Logger
	Clock  clock.Clock
	BootID string

	Store       *store.Store
	Keyring     *keyring.Keyring
	Audit       *audit.Writer
	Bus         *eventbus.Bus
	Jobs        *jobs.Runner
	Outbox      *outbox.Outbox
	Guard       *egress.Guard
	Agents      *agents.Service
	Inventory   *inventory.Service
	Credentials *credentials.Service
	Engine      *policy.Engine
	Policy      *policy.Service
	Access      *access.Service
	Enforcer    *access.Enforcer
	Recording   *recording.Service
	Metrics     *metrics.Metrics
	Health      *health.Checker
	Auth        *opauth.Service
	OIDC        *oidc.Service
	Notify      *notify.Service
	Proxy       *sshproxy.Proxy

	// Recorders opens channel recordings; nil means recording is unavailable and mandatory-recording roles fail
	// closed. New sets it to Recording.
	Recorders sshproxy.RecorderFactory

	// HTTPListener overrides http.listen (tests); when nil and http.listen is empty, no HTTP API is served.
	HTTPListener net.Listener
	// UI serves the embedded web application (nil: API only).
	UI http.Handler

	notifyOpts func(*notify.Options)
	auditFile  *os.File
}

// Option customizes New.
type Option func(*App)

// WithNotifyOptions adjusts the notification core's options (tests: fake provider API endpoints).
func WithNotifyOptions(f func(*notify.Options)) Option { return func(a *App) { a.notifyOpts = f } }

// WithClock overrides the clock (tests).
func WithClock(c clock.Clock) Option { return func(a *App) { a.Clock = c } }

// New opens storage and the keyring, wires services and runs startup reconciliation (PLAN §3.4 steps 1–7).
func New(ctx context.Context, cfg *config.Config, log *slog.Logger, opts ...Option) (*App, error) {
	a := &App{Cfg: cfg, Log: log, Clock: clock.System{}, BootID: ids.New(ids.Boot), Metrics: metrics.New()}
	ui, _ := webui.Dist()
	a.UI = webui.Handler(ui)
	for _, o := range opts {
		o(a)
	}
	setUmask()
	kek, err := keyring.LoadKEK(keyring.Source{Kind: cfg.KEK.Source, File: cfg.KEK.File, Production: cfg.IsProduction(),
		DataDir: cfg.DataDir, Environ: os.Environ()})
	if err != nil {
		return nil, err
	}
	if !cfg.IsProduction() && cfg.KEK.File == "" {
		log.Warn("using a development KEK stored inside the data directory; never use this in production")
	}
	if a.Store, err = store.Open(ctx, store.Options{
		DataDir: cfg.DataDir, AllowNetworkFS: cfg.Storage.AllowNetworkFS, PreMigrationSnapshots: cfg.Storage.PreMigrationSnapshots,
		Logger: obs.Component(log, "store"), Clock: a.Clock, Metrics: a.Metrics,
	}); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = a.Store.Close()
		}
	}()
	if a.Keyring, err = keyring.Load(ctx, a.Store, kek); err != nil {
		return nil, err
	}
	if a.Guard, err = egress.New(cfg.Egress.AllowCIDRs, cfg.Egress.AllowSpecialCIDRs, nil, cfg.SSH.DialTimeout.D()); err != nil {
		return nil, err
	}
	a.Audit = audit.NewWriter(a.Keyring)
	if cfg.Log.AuditFile != "" {
		f, err := os.OpenFile(cfg.Log.AuditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // operator-configured path
		if err != nil {
			return nil, fmt.Errorf("audit file: %w", err)
		}
		a.auditFile = f
		a.Audit.SetSink(audit.NewJSONSink(f))
	}
	a.Bus = eventbus.New()
	a.Jobs = jobs.NewRunner(a.Store, jobs.Options{Logger: log, Clock: a.Clock, Metrics: a.Metrics})
	a.Outbox = outbox.New(a.Store, a.Keyring, outbox.Options{Logger: log, Clock: a.Clock, Metrics: a.Metrics})
	a.Agents = agents.New(a.Store, a.Keyring, a.Audit, a.Bus, a.Clock)
	a.Inventory = inventory.New(a.Store, a.Audit, a.Bus, inventory.Options{Guard: a.Guard, MaxGrantDuration: cfg.Access.MaxGrantDuration.D(),
		Clock: a.Clock, DialTimeout: cfg.SSH.DialTimeout.D()})
	a.Credentials = credentials.New(a.Store, a.Keyring, a.Audit, a.Bus, a.Inventory, credentials.Options{
		Guard: a.Guard, SourceAddresses: cfg.Egress.SourceAddresses, DialTimeout: cfg.SSH.DialTimeout.D(), Clock: a.Clock})
	presets := make([]time.Duration, len(cfg.Access.DurationPresets))
	for i, p := range cfg.Access.DurationPresets {
		presets[i] = p.D()
	}
	a.Engine = policy.NewEngine(a.Store, cfg.Access.MaxGrantDuration.D(), presets)
	a.Policy = policy.NewService(a.Store, a.Audit, a.Bus, a.Engine)
	a.Access = access.New(a.Store, a.Keyring, a.Audit, a.Bus, a.Engine, access.Options{
		PendingExpiry: cfg.Access.PendingExpiry.D(), RequestsPerAgentHour: cfg.Access.RequestsPerAgentHour,
		MaxPendingPerAgent: cfg.Access.MaxPendingPerAgent, MinRemainingToConnect: cfg.Access.MinRemainingToConnect.D(),
		DefaultRetention: cfg.Recording.DefaultRetention.D(), BootID: a.BootID, Clock: a.Clock, Logger: log, Metrics: a.Metrics,
		StorageReserve: fsstat.ReserveCheck(cfg.DataDir, cfg.Storage.MinFreeBytes, cfg.Storage.MinFreePercent),
	})
	a.Agents.OnDisable(a.Access.AgentDisabledHook)
	a.Agents.OnKeyRevoke(a.Access.KeyRevokedHook)
	a.Inventory.OnDisable(a.Access.TargetDisabledHook)
	a.Enforcer = access.NewEnforcer(a.Access, a.Bus, cfg.Access.EnforcementTick.D())
	rc := cfg.Recording
	a.Recording = recording.New(a.Store, a.Keyring, a.Access.Sequencer(), recording.Options{
		Durability: rc.Durability, FlushInterval: rc.FlushInterval.D(), SegmentMaxBytes: rc.SegmentMaxBytes, SegmentMaxAge: rc.SegmentMaxAge.D(),
		QueueRecords: rc.QueueRecords, QueueBytes: rc.QueueBytes, BlockTimeout: rc.BlockTimeout.D(), Clock: a.Clock, Logger: log, Metrics: a.Metrics,
	})
	a.Recorders = a.Recording
	a.Auth = opauth.New(a.Store, a.Keyring, a.Audit, a.Bus, opauth.Options{PasswordMinBytes: cfg.Auth.PasswordMinBytes,
		SessionIdle: cfg.Auth.SessionIdleTimeout.D(), SessionAbsolute: cfg.Auth.SessionAbsoluteTimeout.D(), ReauthWindow: cfg.Auth.ReauthWindow.D(),
		Clock: a.Clock, Metrics: a.Metrics})
	a.OIDC = oidc.New(a.Store, a.Keyring, a.Audit, a.Bus, a.Auth, oidc.Options{PublicURL: cfg.PublicURL, DevMode: !cfg.IsProduction(),
		Clock: a.Clock, Logger: log, Metrics: a.Metrics})
	nopts := notify.Options{PublicURL: cfg.PublicURL, Clock: a.Clock, Logger: log}
	if a.notifyOpts != nil {
		a.notifyOpts(&nopts)
	}
	a.Notify = notify.New(notify.Deps{Store: a.Store, Keyring: a.Keyring, Audit: a.Audit, Access: a.Access, Engine: a.Engine, Agents: a.Agents,
		Inventory: a.Inventory, Auth: a.Auth, Outbox: a.Outbox}, nopts)
	a.Health = health.New(health.Options{ExposeDetails: !cfg.IsProduction()})
	a.Health.MustRegister(
		health.StoreHealth("store", a.Store.Health()),
		health.StoreWritable("store.writable", a.Store.W()),
		health.DirWritable("recordings.writable", a.Store.Path(store.RecordingsDir)),
		health.DiskSpace("disk.data", cfg.DataDir, cfg.Storage.MinFreeBytes, cfg.Storage.MinFreePercent),
	)
	_ = a.Metrics.Register(a.Health.Collector())
	a.Metrics.ObserveFilesystem(metrics.VolumeData, cfg.DataDir)

	if err := a.Credentials.EnsureGatewayHostKey(ctx); err != nil {
		return nil, fmt.Errorf("gateway host key: %w", err)
	}
	res, err := a.Access.ReconcileStartup(ctx)
	if err != nil {
		return nil, fmt.Errorf("startup reconciliation: %w", err)
	}
	if res.Channels > 0 || res.Connections > 0 {
		log.Warn("reconciled activity interrupted by the previous process", slog.Int64("connections", res.Connections), slog.Int("channels", res.Channels))
	}
	if on, at, err := a.Auth.BreakGlassAlert(ctx); err == nil && on {
		log.Error("break-glass recovery was used and has not been acknowledged; review the audit log and acknowledge it in system settings",
			slog.Time("used_at", at))
	}
	rr, err := a.Recording.ReconcileStartup(ctx)
	if err != nil {
		return nil, fmt.Errorf("recording reconciliation: %w", err)
	}
	if *rr != (recording.ReconcileResult{}) {
		log.Warn("reconciled recordings after restart", slog.Int("finalized", rr.Finalized), slog.Int("interrupted", rr.Interrupted),
			slog.Int("missing", rr.Missing), slog.Int("failed", rr.Failed), slog.Int("orphans", rr.Orphans))
	}
	ok = true
	return a, nil
}

// NewProxy builds the data plane once the recorder is known.
func (a *App) NewProxy() *sshproxy.Proxy {
	a.Proxy = sshproxy.New(sshproxy.Options{
		Access: a.Access, Inventory: a.Inventory, Credentials: a.Credentials, Guard: a.Guard, Enforcer: a.Enforcer,
		Recorders: a.Recorders, Audit: a.Audit, Store: a.Store, Logger: a.Log, DialTimeout: a.Cfg.SSH.DialTimeout.D(),
		IdleTimeout: a.Cfg.SSH.IdleTimeout.D(), EnvAllow: a.Cfg.SSH.EnvAllow, Metrics: a.Metrics,
	})
	return a.Proxy
}

// RunBackground starts background workers and returns a function that waits for them after ctx is canceled.
func (a *App) RunBackground(ctx context.Context) (wait func()) {
	var wg sync.WaitGroup
	log := a.Log
	wg.Go(func() { a.Jobs.Run(ctx) })
	wg.Go(func() { a.Outbox.Run(ctx, 4) })
	wg.Go(func() { a.Enforcer.Run(ctx) })
	wg.Go(func() { a.Access.RunBackground(ctx, time.Second) })
	wg.Go(func() {
		jobs.Periodic(ctx, log, "credentials.retire_due", time.Minute, false, func(ctx context.Context) error {
			_, err := a.Credentials.RetireDue(ctx)
			return err
		})
	})
	wg.Go(func() {
		jobs.Periodic(ctx, log, "recording.retention", 10*time.Minute, false, func(ctx context.Context) error {
			_, err := a.Recording.ApplyRetention(ctx, a.Cfg.Recording.RetentionFor)
			return err
		})
	})
	wg.Go(func() {
		jobs.Periodic(ctx, log, "auth.purge_expired", 15*time.Minute, false, func(ctx context.Context) error {
			if err := a.Notify.Purge(ctx); err != nil {
				return err
			}
			if _, err := a.OIDC.PurgeStates(ctx); err != nil {
				return err
			}
			return a.Auth.PurgeExpired(ctx)
		})
	})
	wg.Go(func() {
		// HP-CRY-002: move sealed fields to the active key version after a purpose-key rotation.
		jobs.Periodic(ctx, log, "keyring.reseal", 6*time.Hour, false, func(ctx context.Context) error {
			_, err := a.Keyring.ResealColumns(ctx, a.Store, SealedColumns(), 500)
			return err
		})
	})
	wg.Go(func() {
		jobs.Periodic(ctx, log, "store.wal_checkpoint", 5*time.Minute, false, func(ctx context.Context) error {
			return a.Store.Checkpoint(ctx, "TRUNCATE")
		})
	})
	wg.Go(func() {
		jobs.Periodic(ctx, log, "store.integrity_check", 24*time.Hour, false, func(ctx context.Context) error {
			return a.Store.IntegrityCheck(ctx)
		})
	})
	return wg.Wait
}

// Close releases storage and the audit file.
func (a *App) Close() error {
	if a.auditFile != nil {
		_ = a.auditFile.Close()
	}
	return a.Store.Close()
}

// Listen opens a TCP listener.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

// ErrShutdown marks a clean shutdown.
var ErrShutdown = errors.New("shutdown")

// SealedColumns lists the columns re-encrypted after purpose-key rotation (HP-CRY-002). Audit details are excluded
// because the audit hash chain covers the ciphertext: field key versions used by audit rows stay decrypt-only.
// Recording segment keys are rewrapped separately (HPREC1 key slots). Short-lived OIDC PKCE verifiers expire instead.
func SealedColumns() []keyring.Column {
	return []keyring.Column{
		keyring.FieldColumn("access_requests", "id", "reason_enc", keyring.PurposeField),
		keyring.FieldColumn("approval_decisions", "id", "comment_enc", keyring.PurposeField),
		keyring.FieldColumn("agent_keys", "id", "revoke_reason_enc", keyring.PurposeField),
		keyring.FieldColumn("mfa_totp", "operator_id", "secret_enc", keyring.PurposeField),
		keyring.FieldColumn("outbox_messages", "id", "body_enc", keyring.PurposeField),
		keyring.FieldColumn("integrations", "id", "secrets_enc", keyring.PurposeCredential),
		keyring.FieldColumn("login_credentials", "id", "private_enc", keyring.PurposeCredential),
		keyring.FieldColumn("user_cas", "id", "private_enc", keyring.PurposeCredential),
		keyring.FieldColumn("gateway_host_keys", "id", "private_enc", keyring.PurposeCredential),
		{Table: "oidc_providers", IDColumn: "id", BlobColumn: "client_secret_enc", Purpose: keyring.PurposeField,
			AAD: func(id string) []byte { return []byte("hallpass/oidc-client-secret/v1|" + id) }},
	}
}
