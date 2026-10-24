// Package metrics defines the HallPass Prometheus metric catalog (HP-OBS-004, docs/operator/observability.md).
//
// Every metric lives on a dedicated registry (never the global default). Callers record events through small
// typed methods; label values are normalized against allowlists or bounded sets, so no call can create an
// unbounded number of series or put secrets, reasons, commands, tokens or client addresses into labels.
// A nil *Metrics is valid and every method on it is a no-op.
package metrics

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/obs/fsstat"
	"github.com/aurimasniekis/go-hallpass/internal/obs/internal/httpwrap"
)

// Namespace prefixes every HallPass metric.
const Namespace = "hallpass"

// Histogram buckets (seconds).
var (
	// LatencyBuckets suit request/transaction latencies.
	LatencyBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	// EnforcementBuckets suit the time from access end to termination of activity.
	EnforcementBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 30, 60}
	// DialBuckets suit outbound SSH dials and handshakes.
	DialBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	// HTTPBuckets suit API requests.
	HTTPBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
)

// Metrics holds every HallPass metric family.
type Metrics struct {
	reg *prometheus.Registry

	txNames, jobNames, oidcProviders, routes *bounded

	sshConnActive   prometheus.Gauge
	sshConnTotal    *prometheus.CounterVec
	sshAuthFailures *prometheus.CounterVec
	sshChanActive   *prometheus.GaugeVec
	sshChanTotal    *prometheus.CounterVec
	sshRefused      *prometheus.CounterVec
	sshEnvRejected  prometheus.Counter
	dialDuration    *prometheus.HistogramVec
	requestsTotal   *prometheus.CounterVec
	requestsPending prometheus.Gauge
	decisions       *prometheus.CounterVec
	grantsActive    prometheus.Gauge
	grantsEnded     *prometheus.CounterVec
	enfTerminations *prometheus.CounterVec
	enfLatency      prometheus.Histogram
	recRecords      prometheus.Counter
	recBytes        prometheus.Counter
	recQueueDepth   prometheus.Gauge
	recFailures     *prometheus.CounterVec
	recSegments     *prometheus.CounterVec
	recFinalize     prometheus.Histogram
	txDuration      *prometheus.HistogramVec
	txTotal         *prometheus.CounterVec
	txBusyRetries   prometheus.Counter
	writerWait      prometheus.Histogram
	writerQueue     prometheus.Gauge
	outboxPending   prometheus.Gauge
	outboxDead      prometheus.Gauge
	deliveries      *prometheus.CounterVec
	jobRuns         *prometheus.CounterVec
	httpRequests    *prometheus.CounterVec
	httpDuration    *prometheus.HistogramVec
	httpInFlight    prometheus.Gauge
	sseClients      prometheus.Gauge
	oidcLogins      *prometheus.CounterVec
	operatorLogins  *prometheus.CounterVec
	storeDBBytes    prometheus.Gauge
	storeWALBytes   prometheus.Gauge
	fs              *fsCollector
	handlerTimeout  time.Duration
	handlerInFlight int
}

// New builds the registry with Go runtime and process collectors, build info, and every HallPass family.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg:             reg,
		txNames:         newBounded(reDotted, MaxTxNames, 64, "unnamed"),
		jobNames:        newBounded(reDotted, MaxJobNames, 64, "unnamed"),
		oidcProviders:   newBounded(reSlug, MaxOIDCProvider, 48, "unknown"),
		routes:          newBounded(reRoute, MaxRoutes, 128, "unmatched"),
		fs:              newFSCollector(),
		handlerTimeout:  10 * time.Second,
		handlerInFlight: 4,
	}
	f := factory{reg: reg}

	bi := buildinfo.Get()
	f.gaugeVec("build_info", "Build information; always 1.", "version", "revision", "goversion").
		WithLabelValues(bi.Version, bi.Commit, bi.GoVersion).Set(1)

	m.sshConnActive = f.gauge("ssh_connections_active", "Authenticated agent SSH connections currently open.")
	m.sshConnTotal = f.counterVec("ssh_connections_total", "Inbound agent SSH connection attempts by result.", "result")
	m.sshAuthFailures = f.counterVec("ssh_auth_failures_total", "Failed agent public-key authentications by reason.", "reason")
	m.sshChanActive = f.gaugeVec("ssh_channels_active", "Open agent activity channels by kind.", "kind")
	m.sshChanTotal = f.counterVec("ssh_channels_total", "Agent activity channel open attempts by kind and result.", "kind", "result")
	m.sshRefused = f.counterVec("ssh_refused_requests_total", "Refused SSH channel types and requests (forwarding, subsystems) by type.", "type")
	m.sshEnvRejected = f.counter("ssh_env_rejected_total", "Environment variables dropped because they are not allowlisted.")
	m.dialDuration = f.histogramVec("ssh_dial_duration_seconds", "Outbound destination dial and handshake duration by result.", DialBuckets, "result")

	m.requestsTotal = f.counterVec("access_requests_total", "Access request state transitions by target state.", "state")
	m.requestsPending = f.gauge("access_requests_pending", "Access requests currently pending a decision.")
	m.decisions = f.counterVec("access_decisions_total", "Operator decisions by channel and outcome.", "channel", "outcome")
	m.grantsActive = f.gauge("access_grants_active", "Grants currently active.")
	m.grantsEnded = f.counterVec("access_grants_ended_total", "Grants ended by reason.", "reason")

	m.enfTerminations = f.counterVec("enforcer_terminations_total", "Activity terminated by the enforcer by reason.", "reason")
	m.enfLatency = f.histogram("enforcer_latency_seconds", "Time from access ending to its activity being terminated.", EnforcementBuckets)

	m.recRecords = f.counter("recording_records_total", "Recording records written.")
	m.recBytes = f.counter("recording_bytes_total", "Plaintext recording payload bytes written.")
	m.recQueueDepth = f.gauge("recording_queue_depth", "Records queued for the recording writers.")
	m.recFailures = f.counterVec("recording_failures_total", "Recording failures by stage.", "stage")
	m.recSegments = f.counterVec("recording_segments_total", "Recording segments closed by result.", "result")
	m.recFinalize = f.histogram("recording_segment_finalize_seconds", "Segment finalize (final frame, fsync, commit) duration.", LatencyBuckets)

	m.txDuration = f.histogramVec("store_tx_duration_seconds", "Write transaction duration including retries, by transaction name.", LatencyBuckets, "name")
	m.txTotal = f.counterVec("store_tx_total", "Write transactions by name and final result.", "name", "result")
	m.txBusyRetries = f.counter("store_tx_busy_retries_total", "Write transaction attempts retried after SQLITE_BUSY.")
	m.writerWait = f.histogram("store_writer_wait_seconds", "Time spent waiting to acquire the single writer connection.", LatencyBuckets)
	m.writerQueue = f.gauge("store_writer_queue_depth", "Write transactions currently waiting for the single writer connection.")
	m.storeDBBytes = f.gauge("store_db_bytes", "SQLite main database file size.")
	m.storeWALBytes = f.gauge("store_wal_bytes", "SQLite WAL file size.")

	m.outboxPending = f.gauge("outbox_pending", "Outbox messages queued or awaiting retry.")
	m.outboxDead = f.gauge("outbox_dead", "Outbox messages dead-lettered after exhausting retries.")
	m.deliveries = f.counterVec("notification_deliveries_total", "Notification delivery attempts by provider and outcome.", "provider", "outcome")
	m.jobRuns = f.counterVec("job_runs_total", "Background job runs by job name and result.", "job", "result")

	m.httpRequests = f.counterVec("http_requests_total", "HTTP requests by route template, method and status class.", "route", "method", "code")
	m.httpDuration = f.histogramVec("http_request_duration_seconds", "HTTP request duration by route template and method.", HTTPBuckets, "route", "method")
	m.httpInFlight = f.gauge("http_requests_in_flight", "HTTP requests currently being served.")
	m.sseClients = f.gauge("sse_clients", "Connected live-event (SSE) streams.")

	m.oidcLogins = f.counterVec("oidc_logins_total", "OIDC login completions by provider slug and outcome.", "provider", "outcome")
	m.operatorLogins = f.counterVec("operator_logins_total", "Operator login attempts by method and outcome.", "method", "outcome")

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.fs,
	)
	return m
}

// Registry returns the dedicated registry (for registering extra collectors such as readiness).
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

// Register adds collectors to the registry.
func (m *Metrics) Register(cs ...prometheus.Collector) error {
	if m == nil {
		return nil
	}
	var errs []error
	for _, c := range cs {
		if err := m.reg.Register(c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Handler serves the registry in the Prometheus exposition format. Scrapes are limited in concurrency and time.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	h := promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		Registry:            m.reg,
		ErrorHandling:       promhttp.ContinueOnError,
		MaxRequestsInFlight: m.handlerInFlight,
		Timeout:             m.handlerTimeout,
	})
	return promhttp.InstrumentMetricHandler(m.reg, h)
}

// --- SSH ---

// SSHConnection counts an inbound connection attempt by result.
func (m *Metrics) SSHConnection(r ConnResult) {
	if m == nil {
		return
	}
	m.sshConnTotal.WithLabelValues(enumConnResult.norm(string(r))).Inc()
}

// SSHConnectionOpened increments the active connection gauge (call after authentication succeeds).
func (m *Metrics) SSHConnectionOpened() {
	if m == nil {
		return
	}
	m.sshConnActive.Inc()
}

// SSHConnectionClosed decrements the active connection gauge.
func (m *Metrics) SSHConnectionClosed() {
	if m == nil {
		return
	}
	m.sshConnActive.Dec()
}

// SSHAuthFailed counts a failed authentication by reason (internal/agents Fail* values).
func (m *Metrics) SSHAuthFailed(reason AuthFailReason) {
	if m == nil {
		return
	}
	m.sshAuthFailures.WithLabelValues(enumAuthFail.norm(string(reason))).Inc()
}

// SSHChannel counts a channel open attempt by kind and result.
func (m *Metrics) SSHChannel(kind ChannelKind, r ChannelResult) {
	if m == nil {
		return
	}
	m.sshChanTotal.WithLabelValues(enumChanKind.norm(string(kind)), enumChanResult.norm(string(r))).Inc()
}

// SSHChannelOpened increments the active channel gauge for kind.
func (m *Metrics) SSHChannelOpened(kind ChannelKind) {
	if m == nil {
		return
	}
	m.sshChanActive.WithLabelValues(enumChanKind.norm(string(kind))).Inc()
}

// SSHChannelClosed decrements the active channel gauge for kind.
func (m *Metrics) SSHChannelClosed(kind ChannelKind) {
	if m == nil {
		return
	}
	m.sshChanActive.WithLabelValues(enumChanKind.norm(string(kind))).Dec()
}

// SSHRefused counts a refused channel type or request (HP-SSH-007).
func (m *Metrics) SSHRefused(t RefusedRequest) {
	if m == nil {
		return
	}
	m.sshRefused.WithLabelValues(enumRefused.norm(string(t))).Inc()
}

// SSHEnvRejected counts n dropped environment variables (HP-SSH-008). Variable names are never labels.
func (m *Metrics) SSHEnvRejected(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.sshEnvRejected.Add(float64(n))
}

// Dial observes an outbound destination dial.
func (m *Metrics) Dial(r DialResult, d time.Duration) {
	if m == nil {
		return
	}
	m.dialDuration.WithLabelValues(enumDial.norm(string(r))).Observe(d.Seconds())
}

// --- Access lifecycle ---

// AccessRequest counts a request transition into state (pending = created).
func (m *Metrics) AccessRequest(state RequestState) {
	if m == nil {
		return
	}
	m.requestsTotal.WithLabelValues(enumReqState.norm(string(state))).Inc()
}

// SetAccessRequestsPending sets the pending request gauge (periodic refresh from the store).
func (m *Metrics) SetAccessRequestsPending(n int) {
	if m == nil {
		return
	}
	m.requestsPending.Set(float64(n))
}

// Decision counts an operator decision attempt.
func (m *Metrics) Decision(ch DecisionChannel, o DecisionOutcome) {
	if m == nil {
		return
	}
	m.decisions.WithLabelValues(enumDecChannel.norm(string(ch)), enumDecOutcome.norm(string(o))).Inc()
}

// GrantStarted increments the active grant gauge.
func (m *Metrics) GrantStarted() {
	if m == nil {
		return
	}
	m.grantsActive.Inc()
}

// GrantEnded decrements the active grant gauge and counts the end reason.
func (m *Metrics) GrantEnded(reason EndReason) {
	if m == nil {
		return
	}
	m.grantsActive.Dec()
	m.grantsEnded.WithLabelValues(enumEndReason.norm(string(reason))).Inc()
}

// SetGrantsActive resets the active grant gauge from the store (startup and periodic reconciliation).
func (m *Metrics) SetGrantsActive(n int) {
	if m == nil {
		return
	}
	m.grantsActive.Set(float64(n))
}

// --- Enforcer ---

// EnforcerTerminated counts activity terminated by the enforcer.
func (m *Metrics) EnforcerTerminated(reason EndReason) {
	if m == nil {
		return
	}
	m.enfTerminations.WithLabelValues(enumEndReason.norm(string(reason))).Inc()
}

// EnforcementLatency observes the delay between access ending (grant expiry, revocation) and termination of
// its activity. Negative durations are clamped to zero.
func (m *Metrics) EnforcementLatency(d time.Duration) {
	if m == nil {
		return
	}
	m.enfLatency.Observe(max(d, 0).Seconds())
}

// --- Recording ---

// RecordingWritten counts records and plaintext payload bytes written.
func (m *Metrics) RecordingWritten(records, bytes int) {
	if m == nil {
		return
	}
	if records > 0 {
		m.recRecords.Add(float64(records))
	}
	if bytes > 0 {
		m.recBytes.Add(float64(bytes))
	}
}

// RecordingQueueAdd adjusts the recording queue depth gauge by delta (enqueue +n, dequeue -n).
func (m *Metrics) RecordingQueueAdd(delta int) {
	if m == nil {
		return
	}
	m.recQueueDepth.Add(float64(delta))
}

// RecordingFailed counts a recording failure by stage.
func (m *Metrics) RecordingFailed(stage RecordingStage) {
	if m == nil {
		return
	}
	m.recFailures.WithLabelValues(enumRecStage.norm(string(stage))).Inc()
}

// SegmentClosed counts a closed segment by result.
func (m *Metrics) SegmentClosed(r SegmentResult) {
	if m == nil {
		return
	}
	m.recSegments.WithLabelValues(enumSegResult.norm(string(r))).Inc()
}

// SegmentFinalized observes segment finalize latency.
func (m *Metrics) SegmentFinalized(d time.Duration) {
	if m == nil {
		return
	}
	m.recFinalize.Observe(d.Seconds())
}

// --- Store ---

// StoreTx observes a finished write transaction. name is the TxNamed name (dotted lowercase, bounded).
func (m *Metrics) StoreTx(name string, d time.Duration, r TxResult) {
	if m == nil {
		return
	}
	n := m.txNames.norm(name)
	m.txDuration.WithLabelValues(n).Observe(d.Seconds())
	m.txTotal.WithLabelValues(n, enumTxResult.norm(string(r))).Inc()
}

// TxObserver adapts StoreTx to internal/store.TxObserver's signature; classify maps errors to a TxResult
// (nil error → TxOK is handled here). A nil classify maps every error to TxError.
func (m *Metrics) TxObserver(classify func(error) TxResult) func(name string, d time.Duration, err error) {
	return func(name string, d time.Duration, err error) {
		r := TxOK
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			r = TxCanceled
		case classify != nil:
			r = classify(err)
		default:
			r = TxError
		}
		m.StoreTx(name, d, r)
	}
}

// StoreTxBusyRetry counts a write attempt retried after SQLITE_BUSY.
func (m *Metrics) StoreTxBusyRetry() {
	if m == nil {
		return
	}
	m.txBusyRetries.Inc()
}

// StoreWriterWait observes the time a caller waited for the single writer connection (HP-DB-003).
func (m *Metrics) StoreWriterWait(d time.Duration) {
	if m == nil {
		return
	}
	m.writerWait.Observe(d.Seconds())
}

// StoreWriterQueue adjusts the number of write transactions waiting for the writer connection (HP-DB-003).
func (m *Metrics) StoreWriterQueue(delta int) {
	if m == nil {
		return
	}
	m.writerQueue.Add(float64(delta))
}

// SetStoreSizes sets the database and WAL size gauges (HP-DB-011), e.g. from store.Sizes after checkpoints.
func (m *Metrics) SetStoreSizes(dbBytes, walBytes int64) {
	if m == nil {
		return
	}
	m.storeDBBytes.Set(float64(dbBytes))
	m.storeWALBytes.Set(float64(walBytes))
}

// --- Outbox, notifications, jobs ---

// SetOutboxBacklog sets the pending and dead-letter gauges (periodic refresh from the store).
func (m *Metrics) SetOutboxBacklog(pending, dead int) {
	if m == nil {
		return
	}
	m.outboxPending.Set(float64(pending))
	m.outboxDead.Set(float64(dead))
}

// NotificationDelivery counts a delivery attempt.
func (m *Metrics) NotificationDelivery(p Provider, o DeliveryOutcome) {
	if m == nil {
		return
	}
	m.deliveries.WithLabelValues(enumProvider.norm(string(p)), enumDelivery.norm(string(o))).Inc()
}

// JobRun counts a background job run (job is the code-defined job name, bounded).
func (m *Metrics) JobRun(job string, err error) {
	if m == nil {
		return
	}
	r := "ok"
	if err != nil {
		r = "error"
	}
	m.jobRuns.WithLabelValues(m.jobNames.norm(job), enumJobResult.norm(r)).Inc()
}

// --- HTTP ---

// HTTPMiddleware records request count, duration and in-flight requests. The route label is the matched
// http.ServeMux pattern (path part only), read after the inner handler ran; unmatched requests are
// "unmatched". Raw paths, query strings and client addresses are never used as labels.
func (m *Metrics) HTTPMiddleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.httpInFlight.Inc()
		rec := httpwrap.New(w)
		defer func() {
			m.httpInFlight.Dec()
			m.HTTPRequest(r.Pattern, r.Method, rec.Status(), time.Since(start))
		}()
		next.ServeHTTP(rec, r)
	})
}

// HTTPRequest records one request. pattern is an http.ServeMux pattern or route template, never a raw path.
func (m *Metrics) HTTPRequest(pattern, method string, status int, d time.Duration) {
	if m == nil {
		return
	}
	route := httpwrap.Route(pattern)
	if route == "" && pattern != "" {
		route = Other
	} else {
		route = m.routes.norm(route)
	}
	meth := httpwrap.Method(method)
	m.httpRequests.WithLabelValues(route, meth, httpwrap.CodeClass(status)).Inc()
	m.httpDuration.WithLabelValues(route, meth).Observe(d.Seconds())
}

// SSEClientConnected increments the SSE stream gauge.
func (m *Metrics) SSEClientConnected() {
	if m == nil {
		return
	}
	m.sseClients.Inc()
}

// SSEClientDisconnected decrements the SSE stream gauge.
func (m *Metrics) SSEClientDisconnected() {
	if m == nil {
		return
	}
	m.sseClients.Dec()
}

// --- Operator authentication ---

// OIDCLogin counts an OIDC login completion. provider is the configured provider slug (bounded).
func (m *Metrics) OIDCLogin(provider string, o LoginOutcome) {
	if m == nil {
		return
	}
	m.oidcLogins.WithLabelValues(m.oidcProviders.norm(provider), enumLoginOut.norm(string(o))).Inc()
}

// OperatorLogin counts an operator login attempt.
func (m *Metrics) OperatorLogin(method LoginMethod, o LoginOutcome) {
	if m == nil {
		return
	}
	m.operatorLogins.WithLabelValues(enumLoginMeth.norm(string(method)), enumLoginOut.norm(string(o))).Inc()
}

// --- Filesystems ---

// ObserveFilesystem exports size and available bytes of the filesystem holding path under the given volume
// label (HP-OPS-006). The path itself is never exported. Values are read at scrape time.
func (m *Metrics) ObserveFilesystem(v Volume, path string) {
	if m == nil || path == "" {
		return
	}
	name := enumVolume.norm(string(v))
	if name == Other {
		return
	}
	m.fs.mu.Lock()
	m.fs.paths[name] = path
	m.fs.mu.Unlock()
}

// fsCollector reads filesystem capacity at scrape time.
type fsCollector struct {
	mu          sync.Mutex
	paths       map[string]string
	size, avail *prometheus.Desc
}

func newFSCollector() *fsCollector {
	return &fsCollector{
		paths: map[string]string{},
		size: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "", "storage_filesystem_size_bytes"),
			"Size of the filesystem holding a HallPass volume.", []string{"volume"}, nil),
		avail: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "", "storage_filesystem_avail_bytes"),
			"Space available to HallPass on the filesystem holding a volume.", []string{"volume"}, nil),
	}
}

func (c *fsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.size
	ch <- c.avail
}

func (c *fsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	paths := maps.Clone(c.paths)
	c.mu.Unlock()
	for v, p := range paths {
		u, err := fsstat.Stat(p)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.size, prometheus.GaugeValue, float64(u.Total), v)
		ch <- prometheus.MustNewConstMetric(c.avail, prometheus.GaugeValue, float64(u.Avail), v)
	}
}

// factory registers families under the HallPass namespace.
type factory struct{ reg prometheus.Registerer }

func (f factory) counter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: Namespace, Name: name, Help: help})
	f.reg.MustRegister(c)
	return c
}

func (f factory) counterVec(name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: Namespace, Name: name, Help: help}, labels)
	f.reg.MustRegister(c)
	return c
}

func (f factory) gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: Namespace, Name: name, Help: help})
	f.reg.MustRegister(g)
	return g
}

func (f factory) gaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: Namespace, Name: name, Help: help}, labels)
	f.reg.MustRegister(g)
	return g
}

func (f factory) histogram(name, help string, buckets []float64) prometheus.Histogram {
	h := prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: Namespace, Name: name, Help: help, Buckets: buckets})
	f.reg.MustRegister(h)
	return h
}

func (f factory) histogramVec(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: Namespace, Name: name, Help: help, Buckets: buckets}, labels)
	f.reg.MustRegister(h)
	return h
}
