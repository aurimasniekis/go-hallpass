// Package health implements /healthz (liveness) and /readyz (readiness) for HallPass (HP-OPS-001, PLAN §4.5).
//
// Readiness is the aggregate of named checks, each run with its own timeout. A failing check either fails
// readiness (Critical) or degrades it (Degrading). Results are cached for a short TTL so the unauthenticated
// endpoint cannot be used to amplify load on the store or filesystem. Public responses carry only short,
// stable error codes; error details (which may name paths) are exposed only through DetailHandler, which the
// caller mounts behind admin authentication, or when Options.ExposeDetails is set (development).
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"
)

// Severity is the impact of a failing check on overall readiness.
type Severity int

// Severities.
const (
	// Critical failures make the gateway not ready (HTTP 503).
	Critical Severity = iota
	// Degrading failures make the gateway degraded: it keeps serving, but new sessions may be refused.
	Degrading
)

// CheckStatus is the state of one check.
type CheckStatus string

// Check states.
const (
	CheckOK       CheckStatus = "ok"
	CheckDegraded CheckStatus = "degraded"
	CheckFailed   CheckStatus = "failed"
)

// Status is the overall readiness state.
type Status string

// Readiness states.
const (
	// StatusStarting: startup (PLAN §3.4 steps 1–8) has not finished.
	StatusStarting Status = "starting"
	// StatusReady: every check passed.
	StatusReady Status = "ready"
	// StatusDegraded: no critical failure, at least one degrading failure.
	StatusDegraded Status = "degraded"
	// StatusFailed: at least one critical check failed.
	StatusFailed Status = "failed"
	// StatusStopping: graceful shutdown has begun.
	StatusStopping Status = "stopping"
)

// Default tuning.
const (
	DefaultTimeout  = 2 * time.Second
	DefaultCacheTTL = time.Second
)

// Error codes used by the built-in checks and by the aggregator.
const (
	CodeCheckFailed = "check_failed" // a check returned an error without a code
	CodeTimeout     = "timeout"      // a check did not finish within its timeout
	CodePanic       = "panic"        // a check panicked
)

// Error is a check failure with a short public code. Codes are lowercase identifiers and never contain paths
// or error text; Err holds the detail.
type Error struct {
	Code string
	// Degraded forces the failure to degrade rather than fail readiness, regardless of the check's severity.
	Degraded bool
	Err      error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Fail returns a check error with a public code.
func Fail(code string, err error) error { return &Error{Code: code, Err: err} }

// Degrade returns a check error that only degrades readiness.
func Degrade(code string, err error) error { return &Error{Code: code, Degraded: true, Err: err} }

// Check is a named readiness check.
type Check struct {
	// Name is a stable lowercase identifier ("store", "disk.data"). It is public and used as a metric label.
	Name     string
	Severity Severity
	// Timeout bounds the check; zero uses Options.DefaultTimeout.
	Timeout time.Duration
	// Func returns nil when healthy. It must honor ctx.
	Func func(ctx context.Context) error
}

// CheckResult is the outcome of one check.
type CheckResult struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	// Error is a short public code, empty when ok.
	Error string `json:"error,omitempty"`
	// Detail is the error text; only present in detailed reports.
	Detail     string  `json:"detail,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
}

// Report is the readiness response body.
type Report struct {
	Status    Status        `json:"status"`
	Checks    []CheckResult `json:"checks"`
	CheckedAt time.Time     `json:"checked_at,omitzero"`
}

// Options configures a Checker.
type Options struct {
	// ExposeDetails includes error details in public /readyz responses. Leave false in production.
	ExposeDetails bool
	// CacheTTL is how long a readiness evaluation is reused; zero uses DefaultCacheTTL, negative disables caching.
	CacheTTL time.Duration
	// DefaultTimeout applies to checks without their own timeout; zero uses DefaultTimeout.
	DefaultTimeout time.Duration
	// DegradedStatusCode is the HTTP status for a degraded gateway; zero uses 200 so a degraded gateway stays
	// reachable for operators (set 503 to take a degraded instance out of a load balancer).
	DegradedStatusCode int
}

// Checker aggregates readiness checks and tracks the process lifecycle.
type Checker struct {
	opts Options

	mu     sync.Mutex
	checks []Check
	life   Status // starting, ready (serving) or stopping

	evalMu sync.Mutex // serializes evaluations
	cache  *Report
	cached time.Time
	now    func() time.Time
}

var reName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)
var reCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// New returns a Checker in the starting state.
func New(opts Options) *Checker {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	if opts.DefaultTimeout <= 0 {
		opts.DefaultTimeout = DefaultTimeout
	}
	if opts.DegradedStatusCode == 0 {
		opts.DegradedStatusCode = http.StatusOK
	}
	return &Checker{opts: opts, life: StatusStarting, now: time.Now}
}

// Register adds a check. Names must be unique lowercase dotted identifiers of at most 48 bytes.
func (c *Checker) Register(chk Check) error {
	if len(chk.Name) > 48 || !reName.MatchString(chk.Name) {
		return fmt.Errorf("health: invalid check name %q", chk.Name)
	}
	if chk.Func == nil {
		return fmt.Errorf("health: check %q has no func", chk.Name)
	}
	c.mu.Lock()
	if slices.ContainsFunc(c.checks, func(x Check) bool { return x.Name == chk.Name }) {
		c.mu.Unlock()
		return fmt.Errorf("health: duplicate check %q", chk.Name)
	}
	c.checks = append(c.checks, chk)
	c.mu.Unlock()
	// Lock order is evalMu → mu (run reads checks under mu while holding evalMu), so mu is released first.
	c.evalMu.Lock()
	c.cache = nil
	c.evalMu.Unlock()
	return nil
}

// MustRegister is Register that panics on error (programming errors at startup).
func (c *Checker) MustRegister(chks ...Check) {
	for _, chk := range chks {
		if err := c.Register(chk); err != nil {
			panic(err)
		}
	}
}

// MarkReady records that startup completed (PLAN §3.4 step 9); readiness now follows the checks.
func (c *Checker) MarkReady() { c.setLife(StatusReady) }

// MarkStopping records that graceful shutdown began; readiness reports stopping (503) from now on.
func (c *Checker) MarkStopping() { c.setLife(StatusStopping) }

func (c *Checker) setLife(s Status) {
	c.mu.Lock()
	c.life = s
	c.mu.Unlock()
}

func (c *Checker) lifecycle() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.life
}

// Evaluate returns the current readiness report, reusing a cached evaluation within CacheTTL. Lifecycle state
// (starting, stopping) applies immediately and skips the checks.
func (c *Checker) Evaluate(ctx context.Context) Report {
	if life := c.lifecycle(); life != StatusReady {
		return Report{Status: life, Checks: []CheckResult{}}
	}
	c.evalMu.Lock()
	defer c.evalMu.Unlock()
	if c.cache != nil && c.opts.CacheTTL > 0 && c.now().Sub(c.cached) < c.opts.CacheTTL {
		return cloneReport(*c.cache)
	}
	r := c.run(ctx)
	c.cache, c.cached = &r, c.now()
	return cloneReport(r)
}

// Refresh evaluates the checks now, bypassing the cache.
func (c *Checker) Refresh(ctx context.Context) Report {
	c.evalMu.Lock()
	c.cache = nil
	c.evalMu.Unlock()
	return c.Evaluate(ctx)
}

// Last returns the most recent cached evaluation without running checks; ok is false when there is none.
func (c *Checker) Last() (r Report, ok bool) {
	if life := c.lifecycle(); life != StatusReady {
		return Report{Status: life, Checks: []CheckResult{}}, true
	}
	c.evalMu.Lock()
	defer c.evalMu.Unlock()
	if c.cache == nil {
		return Report{}, false
	}
	return cloneReport(*c.cache), true
}

// Run refreshes readiness every interval until ctx is canceled, so metrics and alerts stay current even when
// nobody polls /readyz.
func (c *Checker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if c.lifecycle() == StatusReady {
			c.Refresh(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Checker) run(ctx context.Context) Report {
	c.mu.Lock()
	checks := slices.Clone(c.checks)
	c.mu.Unlock()
	results := make([]CheckResult, len(checks))
	var wg sync.WaitGroup
	for i, chk := range checks {
		wg.Go(func() { results[i] = c.runOne(ctx, chk) })
	}
	wg.Wait()

	status := StatusReady
	for _, r := range results {
		switch r.Status {
		case CheckFailed:
			status = StatusFailed
		case CheckDegraded:
			if status == StatusReady {
				status = StatusDegraded
			}
		case CheckOK:
		}
	}
	return Report{Status: status, Checks: results, CheckedAt: c.now().UTC()}
}

type outcome struct {
	err   error
	panic bool
}

func (c *Checker) runOne(ctx context.Context, chk Check) CheckResult {
	timeout := chk.Timeout
	if timeout <= 0 {
		timeout = c.opts.DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	done := make(chan outcome, 1) // buffered: a check that ignores ctx must not leak a blocked sender
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- outcome{err: fmt.Errorf("panic: %v", p), panic: true}
			}
		}()
		done <- outcome{err: chk.Func(cctx)}
	}()
	var o outcome
	select {
	case o = <-done:
	case <-cctx.Done():
		o = outcome{err: Fail(CodeTimeout, cctx.Err())}
	}
	res := CheckResult{Name: chk.Name, Status: CheckOK, DurationMS: float64(time.Since(start).Microseconds()) / 1000}
	if o.err == nil {
		return res
	}
	code, degraded := CodeCheckFailed, chk.Severity == Degrading
	var he *Error
	switch {
	case o.panic:
		code = CodePanic
	case errors.As(o.err, &he):
		if reCode.MatchString(he.Code) {
			code = he.Code
		}
		degraded = degraded || he.Degraded
	case errors.Is(o.err, context.DeadlineExceeded):
		code = CodeTimeout
	}
	res.Status = CheckFailed
	if degraded {
		res.Status = CheckDegraded
	}
	res.Error = code
	res.Detail = o.err.Error()
	return res
}

func cloneReport(r Report) Report {
	r.Checks = slices.Clone(r.Checks)
	if r.Checks == nil {
		r.Checks = []CheckResult{}
	}
	return r
}

// public strips details from a report.
func public(r Report) Report {
	for i := range r.Checks {
		r.Checks[i].Detail = ""
	}
	return r
}

// HTTPStatus maps a readiness state to the response code.
func (c *Checker) HTTPStatus(s Status) int {
	switch s {
	case StatusReady:
		return http.StatusOK
	case StatusDegraded:
		return c.opts.DegradedStatusCode
	default:
		return http.StatusServiceUnavailable
	}
}

// LivenessHandler serves /healthz: 200 {"status":"ok"} while the process can serve HTTP. It runs no checks,
// so a degraded dependency never causes a restart loop.
func (c *Checker) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})
}

// ReadinessHandler serves /readyz: 200 when ready (or degraded, by default), 503 otherwise. Check errors are
// reported as short codes only, unless Options.ExposeDetails is set.
func (c *Checker) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rep := c.Evaluate(r.Context())
		if !c.opts.ExposeDetails {
			rep = public(rep)
		}
		writeJSON(w, r, c.HTTPStatus(rep.Status), rep)
	})
}

// DetailHandler serves the readiness report including error details. Mount it only behind authenticated
// admin access (HP-OPS-001: degraded detail is visible to authenticated admins only).
func (c *Checker) DetailHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rep := c.Evaluate(r.Context())
		writeJSON(w, r, c.HTTPStatus(rep.Status), rep)
	})
}

func writeJSON(w http.ResponseWriter, r *http.Request, code int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}
