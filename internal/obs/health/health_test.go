package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/aurimasniekis/go-hallpass/internal/store"
)

func ok(context.Context) error { return nil }

var errNoSpace error = syscall.ENOSPC

func newReady(t *testing.T, opts Options, checks ...Check) *Checker {
	t.Helper()
	c := New(opts)
	c.MustRegister(checks...)
	c.MarkReady()
	return c
}

func get(t *testing.T, h http.Handler, method string) (int, map[string]any, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/readyz", nil))
	body := rec.Body.String()
	var m map[string]any
	if method != http.MethodHead {
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("not JSON: %v: %s", err, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type %q", ct)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("readiness must not be cached by clients")
	}
	return rec.Code, m, body
}

func checksOf(t *testing.T, m map[string]any) map[string]map[string]any {
	t.Helper()
	list, okList := m["checks"].([]any)
	if !okList {
		t.Fatalf("checks is not a list: %v", m)
	}
	out := map[string]map[string]any{}
	for _, c := range list {
		e := c.(map[string]any)
		out[e["name"].(string)] = e
	}
	return out
}

func TestLiveness(t *testing.T) {
	c := New(Options{})
	c.MustRegister(Check{Name: "broken", Func: func(context.Context) error { return errors.New("x") }})
	code, m, _ := get(t, c.LivenessHandler(), http.MethodGet)
	if code != http.StatusOK || m["status"] != "ok" || len(m) != 1 {
		t.Errorf("liveness = %d %v", code, m)
	}
}

func TestLifecycle(t *testing.T) {
	c := New(Options{})
	c.MustRegister(Check{Name: "store", Func: ok})
	code, m, _ := get(t, c.ReadinessHandler(), http.MethodGet)
	if code != http.StatusServiceUnavailable || m["status"] != "starting" || len(m["checks"].([]any)) != 0 {
		t.Errorf("starting = %d %v", code, m)
	}
	c.MarkReady()
	if code, m, _ = get(t, c.ReadinessHandler(), http.MethodGet); code != http.StatusOK || m["status"] != "ready" {
		t.Errorf("ready = %d %v", code, m)
	}
	c.MarkStopping()
	if code, m, _ = get(t, c.ReadinessHandler(), http.MethodGet); code != http.StatusServiceUnavailable || m["status"] != "stopping" {
		t.Errorf("stopping = %d %v", code, m)
	}
	if code, _, body := get(t, c.ReadinessHandler(), http.MethodHead); code != http.StatusServiceUnavailable || body != "" {
		t.Errorf("HEAD = %d %q", code, body)
	}
}

func TestAggregationAndJSONShape(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "private", "recordings")
	c := newReady(t, Options{},
		Check{Name: "store", Func: ok},
		Check{Name: "disk.data", Severity: Degrading, Func: func(context.Context) error {
			return fmt.Errorf("only 1 byte free on %s", secretPath)
		}},
	)
	code, m, body := get(t, c.ReadinessHandler(), http.MethodGet)
	if code != http.StatusOK || m["status"] != "degraded" {
		t.Fatalf("degraded = %d %v", code, m)
	}
	cs := checksOf(t, m)
	if cs["store"]["status"] != "ok" || cs["store"]["error"] != nil {
		t.Errorf("store = %v", cs["store"])
	}
	if cs["disk.data"]["status"] != "degraded" || cs["disk.data"]["error"] != CodeCheckFailed {
		t.Errorf("disk = %v", cs["disk.data"])
	}
	if strings.Contains(body, secretPath) || strings.Contains(body, "detail") {
		t.Errorf("public readiness leaked details: %s", body)
	}
	for k := range m {
		if k != "status" && k != "checks" && k != "checked_at" {
			t.Errorf("unexpected top-level key %q", k)
		}
	}

	// Critical failure: 503 and failed.
	c.MustRegister(Check{Name: "keyring", Func: func(context.Context) error { return Fail("keyring_missing", errors.New("x")) }})
	code, m, _ = get(t, c.ReadinessHandler(), http.MethodGet)
	if code != http.StatusServiceUnavailable || m["status"] != "failed" || checksOf(t, m)["keyring"]["error"] != "keyring_missing" {
		t.Errorf("failed = %d %v", code, m)
	}

	// Details only via DetailHandler or ExposeDetails.
	_, m, body = get(t, c.DetailHandler(), http.MethodGet)
	if !strings.Contains(body, secretPath) || checksOf(t, m)["disk.data"]["detail"] == nil {
		t.Errorf("detail handler lacks detail: %s", body)
	}
	dev := newReady(t, Options{ExposeDetails: true}, Check{Name: "x", Func: func(context.Context) error { return errors.New("why") }})
	if _, _, body = get(t, dev.ReadinessHandler(), http.MethodGet); !strings.Contains(body, `"detail":"why"`) {
		t.Errorf("ExposeDetails ignored: %s", body)
	}
}

func TestDegradedStatusCodeOption(t *testing.T) {
	c := newReady(t, Options{DegradedStatusCode: http.StatusServiceUnavailable},
		Check{Name: "d", Func: func(context.Context) error { return Degrade("disk_reserve", nil) }})
	if code, m, _ := get(t, c.ReadinessHandler(), http.MethodGet); code != http.StatusServiceUnavailable || m["status"] != "degraded" {
		t.Errorf("got %d %v", code, m)
	}
}

func TestSlowPanickingAndInvalidCodes(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := newReady(t, Options{},
		Check{Name: "slow", Timeout: 50 * time.Millisecond, Func: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}},
		Check{Name: "stuck", Timeout: 50 * time.Millisecond, Func: func(context.Context) error {
			<-release // ignores ctx entirely
			return nil
		}},
		Check{Name: "boom", Func: func(context.Context) error { panic("kaboom /secret/path") }},
		Check{Name: "badcode", Func: func(context.Context) error { return Fail("Not A Code /etc", nil) }},
		Check{Name: "fast", Func: ok},
	)
	start := time.Now()
	code, m, body := get(t, c.ReadinessHandler(), http.MethodGet)
	if el := time.Since(start); el > time.Second {
		t.Errorf("readiness took %v; checks must run concurrently with timeouts", el)
	}
	cs := checksOf(t, m)
	if code != http.StatusServiceUnavailable || cs["slow"]["error"] != CodeTimeout || cs["stuck"]["error"] != CodeTimeout {
		t.Errorf("timeouts: %d %v", code, cs)
	}
	if cs["boom"]["error"] != CodePanic || cs["badcode"]["error"] != CodeCheckFailed || cs["fast"]["status"] != "ok" {
		t.Errorf("codes: %v", cs)
	}
	if strings.Contains(body, "/secret/path") || strings.Contains(body, "/etc") {
		t.Errorf("leak: %s", body)
	}
}

func TestCacheAndRefresh(t *testing.T) {
	var n atomic.Int32
	c := newReady(t, Options{CacheTTL: time.Hour}, Check{Name: "count", Func: func(context.Context) error {
		n.Add(1)
		return nil
	}})
	if _, okLast := c.Last(); okLast {
		t.Error("Last before any evaluation")
	}
	for range 5 {
		c.Evaluate(context.Background())
	}
	if n.Load() != 1 {
		t.Errorf("evaluated %d times within TTL", n.Load())
	}
	c.Refresh(context.Background())
	if n.Load() != 2 {
		t.Errorf("refresh did not re-run: %d", n.Load())
	}
	if r, okLast := c.Last(); !okLast || r.Status != StatusReady {
		t.Errorf("Last = %v %v", r, okLast)
	}
	// Registering a check invalidates the cache.
	c.MustRegister(Check{Name: "late", Func: ok})
	if r := c.Evaluate(context.Background()); len(r.Checks) != 2 || n.Load() != 3 {
		t.Errorf("cache not invalidated: %v n=%d", r, n.Load())
	}
	// Returned reports are copies.
	r := c.Evaluate(context.Background())
	r.Checks[0].Status = CheckFailed
	if c.Evaluate(context.Background()).Checks[0].Status != CheckOK {
		t.Error("cache mutated through returned report")
	}

	nc := newReady(t, Options{CacheTTL: -1}, Check{Name: "count", Func: func(context.Context) error { n.Add(1); return nil }})
	before := n.Load()
	nc.Evaluate(context.Background())
	nc.Evaluate(context.Background())
	if n.Load()-before != 2 {
		t.Error("negative TTL must disable caching")
	}
}

func TestRegisterValidation(t *testing.T) {
	c := New(Options{})
	for _, bad := range []Check{
		{Name: "", Func: ok},
		{Name: "Upper", Func: ok},
		{Name: "has space", Func: ok},
		{Name: strings.Repeat("a", 49), Func: ok},
		{Name: "nofunc"},
	} {
		if err := c.Register(bad); err == nil {
			t.Errorf("Register(%q) accepted", bad.Name)
		}
	}
	if err := c.Register(Check{Name: "a.b_c", Func: ok}); err != nil {
		t.Fatal(err)
	}
	if err := c.Register(Check{Name: "a.b_c", Func: ok}); err == nil {
		t.Error("duplicate accepted")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustRegister did not panic")
		}
	}()
	c.MustRegister(Check{Name: "BAD", Func: ok})
}

func TestRun(t *testing.T) {
	var n atomic.Int32
	c := newReady(t, Options{CacheTTL: time.Hour}, Check{Name: "count", Func: func(context.Context) error { n.Add(1); return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, 10*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for n.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if n.Load() < 3 {
		t.Errorf("Run refreshed %d times", n.Load())
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	c.Run(ctx2, 0) // default interval, returns immediately on canceled ctx
}

func gatherCollector(t *testing.T, c *Checker) map[string]map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c.Collector())
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]float64{}
	for _, f := range fams {
		out[f.GetName()] = map[string]float64{}
		for _, m := range f.GetMetric() {
			out[f.GetName()][labelValue(m)] = m.GetGauge().GetValue()
		}
	}
	return out
}

func labelValue(m *dto.Metric) string {
	if len(m.GetLabel()) == 0 {
		return ""
	}
	return m.GetLabel()[0].GetValue()
}

func TestCollector(t *testing.T) {
	c := New(Options{})
	c.MustRegister(Check{Name: "store", Func: ok}, Check{Name: "disk.data", Severity: Degrading, Func: func(context.Context) error { return errors.New("x") }})
	got := gatherCollector(t, c)
	if got["hallpass_readiness_state"]["starting"] != 1 || got["hallpass_readiness_state"]["ready"] != 0 {
		t.Errorf("starting state: %v", got)
	}
	c.MarkReady()
	got = gatherCollector(t, c)
	if got["hallpass_readiness_state"]["starting"] != 1 {
		t.Errorf("never evaluated must report starting: %v", got)
	}
	c.Evaluate(context.Background())
	got = gatherCollector(t, c)
	if got["hallpass_readiness_state"]["degraded"] != 1 || got["hallpass_readiness_state"]["ready"] != 0 {
		t.Errorf("state: %v", got)
	}
	if got["hallpass_readiness_check_ok"]["store"] != 1 || got["hallpass_readiness_check_ok"]["disk.data"] != 0 {
		t.Errorf("checks: %v", got)
	}
}

// --- built-in checks ---

type fakeStatus struct{ st store.HealthStatus }

func (f fakeStatus) Status() store.HealthStatus { return f.st }

type fakeTx struct{ err error }

func (f fakeTx) TxNamed(_ context.Context, name string, fn func(*store.Tx) error) error {
	if name == "" {
		return errors.New("unnamed")
	}
	if f.err != nil {
		return f.err
	}
	return fn(&store.Tx{})
}

func runCheck(t *testing.T, chk Check) CheckResult {
	t.Helper()
	c := newReady(t, Options{CacheTTL: -1}, chk)
	return c.Evaluate(context.Background()).Checks[0]
}

func TestStoreChecks(t *testing.T) {
	for state, want := range map[store.HealthState][2]string{
		store.HealthOK:       {"ok", ""},
		store.HealthDegraded: {"degraded", CodeStorageDegraded},
		store.HealthFailed:   {"failed", CodeStorageFailed},
	} {
		r := runCheck(t, StoreHealth("store", fakeStatus{store.HealthStatus{State: state, Reason: "database disk full"}}))
		if string(r.Status) != want[0] || r.Error != want[1] {
			t.Errorf("%s: %+v", state, r)
		}
	}
	for err, want := range map[error][2]string{
		nil:                      {"ok", ""},
		store.ErrBusy:            {"degraded", CodeStorageBusy},
		store.ErrFull:            {"degraded", CodeDiskFull},
		store.ErrIO:              {"failed", CodeNotWritable},
		context.DeadlineExceeded: {"failed", CodeTimeout},
	} {
		r := runCheck(t, StoreWritable("store.writable", fakeTx{err: err}))
		if string(r.Status) != want[0] || r.Error != want[1] {
			t.Errorf("%v: %+v", err, r)
		}
	}
}

func TestFilesystemChecks(t *testing.T) {
	dir := t.TempDir()
	if r := runCheck(t, DirWritable("recordings.writable", dir)); r.Status != CheckOK {
		t.Errorf("writable dir: %+v", r)
	}
	missing := filepath.Join(dir, "missing")
	r := runCheck(t, DirWritable("recordings.writable", missing))
	if r.Status != CheckFailed || r.Error != CodeNotWritable {
		t.Errorf("missing dir: %+v", r)
	}
	if !errors.Is(writeErr(fmt.Errorf("w: %w", errNoSpace)), errNoSpace) {
		t.Error("writeErr must wrap")
	}
	var he *Error
	if !errors.As(writeErr(errNoSpace), &he) || !he.Degraded || he.Code != CodeDiskFull {
		t.Errorf("ENOSPC must degrade: %+v", he)
	}

	if r := runCheck(t, DiskSpace("disk.data", dir, 0, 0)); r.Status != CheckOK {
		t.Errorf("no reserve: %+v", r)
	}
	if r := runCheck(t, DiskSpace("disk.data", dir, 1<<62, 0)); r.Status != CheckDegraded || r.Error != CodeDiskReserve {
		t.Errorf("huge reserve: %+v", r)
	}
	if r := runCheck(t, DiskSpace("disk.data", dir, 0, 100)); r.Status != CheckDegraded {
		t.Errorf("100%% reserve: %+v", r)
	}
	if r := runCheck(t, DiskSpace("disk.data", missing, 0, 5)); r.Status != CheckDegraded || r.Error != CodeDiskStat {
		t.Errorf("stat failure: %+v", r)
	}
}

func TestFlag(t *testing.T) {
	var up atomic.Bool
	chk := Flag("ssh.listener", "listener_down", up.Load)
	if r := runCheck(t, chk); r.Status != CheckFailed || r.Error != "listener_down" {
		t.Errorf("down: %+v", r)
	}
	up.Store(true)
	if r := runCheck(t, chk); r.Status != CheckOK {
		t.Errorf("up: %+v", r)
	}
}

func TestErrorType(t *testing.T) {
	base := errors.New("cause")
	e := Fail("x_code", base)
	if e.Error() != "x_code: cause" || !errors.Is(e, base) {
		t.Errorf("Fail: %v", e)
	}
	if Fail("only", nil).Error() != "only" {
		t.Error("nil cause")
	}
}

// Readiness endpoint over a real server: JSON decodes and HEAD/GET work end to end.
func TestReadinessOverHTTP(t *testing.T) {
	c := newReady(t, Options{}, Check{Name: "store", Func: ok})
	mux := http.NewServeMux()
	mux.Handle("GET /readyz", c.ReadinessHandler())
	mux.Handle("GET /healthz", c.LivenessHandler())
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, p := range []string{"/readyz", "/healthz"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !json.Valid(b) {
			t.Errorf("%s: %d %s", p, resp.StatusCode, b)
		}
	}
}
