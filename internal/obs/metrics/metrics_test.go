package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// exercise records one event through every method so every vector family has at least one series.
func exercise(m *Metrics) {
	m.SSHConnection(ConnAccepted)
	m.SSHConnectionOpened()
	m.SSHConnectionClosed()
	m.SSHAuthFailed(AuthUnknownKey)
	m.SSHChannel(ChannelShell, ChannelOpened)
	m.SSHChannelOpened(ChannelExec)
	m.SSHChannelClosed(ChannelExec)
	m.SSHRefused(RefusedPortForward)
	m.SSHEnvRejected(2)
	m.Dial(DialOK, 20*time.Millisecond)
	m.AccessRequest(RequestPending)
	m.SetAccessRequestsPending(3)
	m.Decision(DecisionSlack, DecisionApproved)
	m.GrantStarted()
	m.GrantEnded(EndExpired)
	m.SetGrantsActive(1)
	m.EnforcerTerminated(EndOperator)
	m.EnforcementLatency(300 * time.Millisecond)
	m.RecordingWritten(5, 1024)
	m.RecordingQueueAdd(4)
	m.RecordingFailed(RecWrite)
	m.SegmentClosed(SegmentFinalized)
	m.SegmentFinalized(5 * time.Millisecond)
	m.StoreTx("access.open_connection", 3*time.Millisecond, TxOK)
	m.StoreTxBusyRetry()
	m.StoreWriterWait(time.Millisecond)
	m.SetStoreSizes(4096, 1024)
	m.SetOutboxBacklog(2, 1)
	m.NotificationDelivery(ProviderTelegram, DeliveryRetry)
	m.JobRun("store.wal_checkpoint", nil)
	m.HTTPRequest("GET /api/v1/requests/{id}", http.MethodGet, 200, time.Millisecond)
	m.SSEClientConnected()
	m.SSEClientDisconnected()
	m.OIDCLogin("corp-sso", LoginSuccess)
	m.OperatorLogin(LoginPassword, LoginFailure)
}

func gather(t *testing.T, m *Metrics) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

func labelNames(f *dto.MetricFamily) string {
	if len(f.GetMetric()) == 0 {
		return ""
	}
	var names []string
	for _, l := range f.GetMetric()[0].GetLabel() {
		names = append(names, l.GetName())
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// TestCatalogGolden pins the metric catalog (names, types and label names) documented in
// docs/operator/observability.md. Changing it is a documented, reviewed change.
func TestCatalogGolden(t *testing.T) {
	m := New()
	m.ObserveFilesystem(VolumeData, t.TempDir())
	exercise(m)
	want := map[string]string{
		"hallpass_build_info":                         "gauge:goversion,revision,version",
		"hallpass_ssh_connections_active":             "gauge:",
		"hallpass_ssh_connections_total":              "counter:result",
		"hallpass_ssh_auth_failures_total":            "counter:reason",
		"hallpass_ssh_channels_active":                "gauge:kind",
		"hallpass_ssh_channels_total":                 "counter:kind,result",
		"hallpass_ssh_refused_requests_total":         "counter:type",
		"hallpass_ssh_env_rejected_total":             "counter:",
		"hallpass_ssh_dial_duration_seconds":          "histogram:result",
		"hallpass_access_requests_total":              "counter:state",
		"hallpass_access_requests_pending":            "gauge:",
		"hallpass_access_decisions_total":             "counter:channel,outcome",
		"hallpass_access_grants_active":               "gauge:",
		"hallpass_access_grants_ended_total":          "counter:reason",
		"hallpass_enforcer_terminations_total":        "counter:reason",
		"hallpass_enforcer_latency_seconds":           "histogram:",
		"hallpass_recording_records_total":            "counter:",
		"hallpass_recording_bytes_total":              "counter:",
		"hallpass_recording_queue_depth":              "gauge:",
		"hallpass_recording_failures_total":           "counter:stage",
		"hallpass_recording_segments_total":           "counter:result",
		"hallpass_recording_segment_finalize_seconds": "histogram:",
		"hallpass_store_tx_duration_seconds":          "histogram:name",
		"hallpass_store_tx_total":                     "counter:name,result",
		"hallpass_store_tx_busy_retries_total":        "counter:",
		"hallpass_store_writer_wait_seconds":          "histogram:",
		"hallpass_store_db_bytes":                     "gauge:",
		"hallpass_store_wal_bytes":                    "gauge:",
		"hallpass_outbox_pending":                     "gauge:",
		"hallpass_outbox_dead":                        "gauge:",
		"hallpass_notification_deliveries_total":      "counter:outcome,provider",
		"hallpass_job_runs_total":                     "counter:job,result",
		"hallpass_http_requests_total":                "counter:code,method,route",
		"hallpass_http_request_duration_seconds":      "histogram:method,route",
		"hallpass_http_requests_in_flight":            "gauge:",
		"hallpass_sse_clients":                        "gauge:",
		"hallpass_oidc_logins_total":                  "counter:outcome,provider",
		"hallpass_operator_logins_total":              "counter:method,outcome",
		"hallpass_storage_filesystem_size_bytes":      "gauge:volume",
		"hallpass_storage_filesystem_avail_bytes":     "gauge:volume",
	}
	fams := gather(t, m)
	got := map[string]string{}
	for name, f := range fams {
		if strings.HasPrefix(name, "hallpass_") {
			got[name] = strings.ToLower(f.GetType().String()) + ":" + labelNames(f)
		}
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %q, want %q", name, got[name], w)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("undocumented metric %s (add it to the golden list and docs/operator/observability.md)", name)
		}
	}
	for _, std := range []string{"go_goroutines", "go_memstats_alloc_bytes"} {
		if _, ok := fams[std]; !ok {
			t.Errorf("missing Go collector metric %s", std)
		}
	}
}

func TestDedicatedRegistry(t *testing.T) {
	a, b := New(), New() // would panic on duplicate registration if the global registry were used
	if a.Registry() == b.Registry() {
		t.Fatal("registries must be independent")
	}
}

func seriesValues(t *testing.T, m *Metrics, family, label string) []string {
	t.Helper()
	f := gather(t, m)[family]
	if f == nil {
		return nil
	}
	var vals []string
	for _, mt := range f.GetMetric() {
		for _, l := range mt.GetLabel() {
			if l.GetName() == label {
				vals = append(vals, l.GetValue())
			}
		}
	}
	sort.Strings(vals)
	return slices.Compact(vals)
}

func TestEnumLabelsNormalized(t *testing.T) {
	m := New()
	const planted = "pl4nted-s3cret reason; rm -rf /"
	m.SSHAuthFailed(AuthFailReason(planted))
	m.SSHAuthFailed(AuthRevokedKey)
	m.SSHConnection(ConnResult(planted))
	m.SSHChannel(ChannelKind(planted), ChannelResult(planted))
	m.SSHChannelOpened(ChannelKind("x11"))
	m.SSHRefused(RefusedRequest(planted))
	m.Dial(DialResult(planted), time.Second)
	m.AccessRequest(RequestState(planted))
	m.Decision(DecisionChannel(planted), DecisionOutcome(planted))
	m.GrantEnded(EndReason(planted))
	m.EnforcerTerminated(EndReason(planted))
	m.RecordingFailed(RecordingStage(planted))
	m.SegmentClosed(SegmentResult(planted))
	m.StoreTx("x", 0, TxResult(planted))
	m.NotificationDelivery(Provider(planted), DeliveryOutcome(planted))
	m.OIDCLogin(planted, LoginOutcome(planted))
	m.OperatorLogin(LoginMethod(planted), LoginOutcome(planted))
	m.HTTPRequest("GET /a/"+planted, "BREW", 999, 0)

	if got := seriesValues(t, m, "hallpass_ssh_auth_failures_total", "reason"); !slices.Equal(got, []string{"other", "revoked_key"}) {
		t.Errorf("auth reasons = %v", got)
	}
	if got := seriesValues(t, m, "hallpass_http_requests_total", "method"); !slices.Equal(got, []string{"other"}) {
		t.Errorf("methods = %v", got)
	}
	if got := seriesValues(t, m, "hallpass_http_requests_total", "code"); !slices.Equal(got, []string{"other"}) {
		t.Errorf("codes = %v", got)
	}
	body := scrape(t, m)
	if strings.Contains(body, "pl4nted") || strings.Contains(body, "rm -rf") {
		t.Fatalf("free-form value reached the exposition:\n%s", grepLines(body, "pl4nted"))
	}
}

func TestBoundedLabels(t *testing.T) {
	m := New()
	for i := range 3 * MaxTxNames {
		m.StoreTx(fmt.Sprintf("pkg.tx_%d", i), time.Millisecond, TxOK)
	}
	m.StoreTx("", 0, TxOK)
	m.StoreTx("Bad Name!", 0, TxOK)
	m.StoreTx(strings.Repeat("a", 65), 0, TxOK)
	names := seriesValues(t, m, "hallpass_store_tx_total", "name")
	if len(names) != MaxTxNames+2 { // cap + "other" + "unnamed"
		t.Errorf("tx names = %d, want %d", len(names), MaxTxNames+2)
	}
	for _, want := range []string{"other", "unnamed", "pkg.tx_0"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing %q", want)
		}
	}

	for i := range 2 * MaxOIDCProvider {
		m.OIDCLogin(fmt.Sprintf("idp-%d", i), LoginSuccess)
	}
	m.OIDCLogin("", LoginError)
	m.OIDCLogin("UPPER", LoginError)
	if got := seriesValues(t, m, "hallpass_oidc_logins_total", "provider"); len(got) != MaxOIDCProvider+2 {
		t.Errorf("oidc providers = %d (%v)", len(got), got)
	}

	for i := range 2 * MaxJobNames {
		m.JobRun(fmt.Sprintf("job_%d", i), errors.New("x"))
	}
	if got := seriesValues(t, m, "hallpass_job_runs_total", "job"); len(got) != MaxJobNames+1 {
		t.Errorf("job names = %d", len(got))
	}
	if got := seriesValues(t, m, "hallpass_job_runs_total", "result"); !slices.Equal(got, []string{"error"}) {
		t.Errorf("job results = %v", got)
	}

	for i := range 2 * MaxRoutes {
		m.HTTPRequest(fmt.Sprintf("GET /r/%d", i), http.MethodGet, 200, 0)
	}
	m.HTTPRequest("", http.MethodGet, 404, 0)
	routes := seriesValues(t, m, "hallpass_http_requests_total", "route")
	if len(routes) != MaxRoutes+2 || !slices.Contains(routes, "unmatched") || !slices.Contains(routes, "other") {
		t.Errorf("routes = %d", len(routes))
	}
}

func TestNilSafe(t *testing.T) {
	var m *Metrics
	exercise(m)
	m.ObserveFilesystem(VolumeData, "/")
	_ = m.TxObserver(nil)
	if m.Registry() != nil {
		t.Error("nil registry expected")
	}
	if err := m.Register(nil); err != nil {
		t.Error(err)
	}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if h := m.HTTPMiddleware(next); fmt.Sprintf("%p", h) != fmt.Sprintf("%p", next) {
		t.Error("nil middleware must return next")
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("nil handler code = %d", rec.Code)
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape status %d", resp.StatusCode)
	}
	return string(b)
}

func grepLines(s, sub string) string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestHandlerExposition(t *testing.T) {
	m := New()
	exercise(m)
	body := scrape(t, m)
	for _, want := range []string{
		`hallpass_build_info{goversion="`,
		`hallpass_ssh_auth_failures_total{reason="unknown_key"} 1`,
		`hallpass_access_decisions_total{channel="slack",outcome="approved"} 1`,
		`hallpass_http_requests_total{code="2xx",method="GET",route="/api/v1/requests/{id}"} 1`,
		`hallpass_recording_bytes_total 1024`,
		`hallpass_outbox_dead 1`,
		`hallpass_ssh_env_rejected_total 2`,
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q", want)
		}
	}
	// promhttp self-instrumentation lands on the next scrape.
	if body := scrape(t, m); !strings.Contains(body, "promhttp_metric_handler_requests_total") {
		t.Error("missing promhttp handler metrics")
	}
}

func TestHTTPMiddlewareUsesRouteTemplate(t *testing.T) {
	m := New()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/items/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "x")
		http.NewResponseController(w).Flush() //nolint:errcheck // exercises Flush passthrough
	})
	h := m.HTTPMiddleware(mux)
	for _, target := range []string{"/api/v1/items/act-t0ken-abc?token=s3cret", "/nope/act-t0ken-abc"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if !rec.Flushed && rec.Code == http.StatusTeapot {
			t.Error("flush not forwarded")
		}
	}
	body := scrape(t, m)
	if !strings.Contains(body, `hallpass_http_requests_total{code="4xx",method="GET",route="/api/v1/items/{id}"} 1`) {
		t.Errorf("templated route missing:\n%s", grepLines(body, "http_requests_total"))
	}
	if !strings.Contains(body, `route="unmatched"`) {
		t.Error("unmatched route missing")
	}
	for _, leak := range []string{"t0ken", "s3cret", "/nope"} {
		if strings.Contains(body, leak) {
			t.Errorf("raw path leaked into labels: %q", leak)
		}
	}
	if !strings.Contains(body, "hallpass_http_requests_in_flight 0") {
		t.Error("in-flight gauge not back to zero")
	}
}

func TestTxObserver(t *testing.T) {
	m := New()
	errBusy := errors.New("busy")
	obsFn := m.TxObserver(func(err error) TxResult {
		if errors.Is(err, errBusy) {
			return TxBusy
		}
		return TxError
	})
	obsFn("a.ok", time.Millisecond, nil)
	obsFn("a.busy", time.Millisecond, fmt.Errorf("wrap: %w", errBusy))
	obsFn("a.cancel", time.Millisecond, context.Canceled)
	obsFn("a.other", time.Millisecond, errors.New("boom"))
	m.TxObserver(nil)("a.nil", time.Millisecond, errors.New("boom"))
	body := scrape(t, m)
	for _, want := range []string{
		`hallpass_store_tx_total{name="a.ok",result="ok"} 1`,
		`hallpass_store_tx_total{name="a.busy",result="busy"} 1`,
		`hallpass_store_tx_total{name="a.cancel",result="canceled"} 1`,
		`hallpass_store_tx_total{name="a.other",result="error"} 1`,
		`hallpass_store_tx_total{name="a.nil",result="error"} 1`,
		`hallpass_store_tx_duration_seconds_count{name="a.ok"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestGaugesAndFilesystem(t *testing.T) {
	m := New()
	dir := t.TempDir()
	m.ObserveFilesystem(VolumeRecordings, dir)
	m.ObserveFilesystem(Volume("evil"), dir)
	m.ObserveFilesystem(VolumeBackups, dir+"/does-not-exist")
	m.ObserveFilesystem(VolumeData, "")
	m.SSHConnectionOpened()
	m.SSHConnectionOpened()
	m.SSHConnectionClosed()
	m.RecordingQueueAdd(3)
	m.RecordingQueueAdd(-1)
	m.RecordingWritten(0, 0)
	m.SSHEnvRejected(0)
	m.EnforcementLatency(-time.Second)
	m.GrantStarted()
	m.GrantStarted()
	m.GrantEnded(EndLockdown)
	body := scrape(t, m)
	for _, want := range []string{
		"hallpass_ssh_connections_active 1",
		"hallpass_recording_queue_depth 2",
		"hallpass_access_grants_active 1",
		`hallpass_access_grants_ended_total{reason="lockdown"} 1`,
		`hallpass_storage_filesystem_size_bytes{volume="recordings"}`,
		`hallpass_storage_filesystem_avail_bytes{volume="recordings"}`,
		"hallpass_enforcer_latency_seconds_sum 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{`volume="evil"`, `volume="other"`, `volume="backups"`, `volume="data"`, dir, "hallpass_recording_records_total 1", "hallpass_ssh_env_rejected_total 1"} {
		if strings.Contains(body, bad) {
			t.Errorf("unexpected %q in exposition", bad)
		}
	}
}

func TestRegister(t *testing.T) {
	m := New()
	if err := m.Register(m.fs); err == nil {
		t.Error("duplicate registration must fail")
	}
}
