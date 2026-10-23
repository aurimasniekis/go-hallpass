package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
)

// Storage error classes. Errors returned by the store wrap one of these when the cause is known.
var (
	ErrBusy       = errors.New("storage busy")
	ErrFull       = errors.New("storage full")
	ErrIO         = errors.New("storage I/O error")
	ErrCorrupt    = errors.New("storage corrupt")
	ErrConstraint = errors.New("constraint violation")
	ErrConflict   = errors.New("state conflict")
	ErrNotFound   = errors.New("not found")
)

// sqliteCode returns the primary SQLite result code of err, or 0.
func sqliteCode(err error) int {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code() & 0xff
	}
	return 0
}

// classify wraps err with its storage class (if any).
func classify(err error) error {
	if err == nil {
		return nil
	}
	switch sqliteCode(err) {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return fmt.Errorf("%w: %w", ErrBusy, err)
	case sqlite3.SQLITE_FULL:
		return fmt.Errorf("%w: %w", ErrFull, err)
	case sqlite3.SQLITE_IOERR, sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_READONLY:
		return fmt.Errorf("%w: %w", ErrIO, err)
	case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	case sqlite3.SQLITE_CONSTRAINT:
		return fmt.Errorf("%w: %w", ErrConstraint, err)
	}
	return err
}

// IsConstraint reports whether err is a constraint violation (unique, check, foreign key).
func IsConstraint(err error) bool {
	return errors.Is(err, ErrConstraint) || sqliteCode(err) == sqlite3.SQLITE_CONSTRAINT
}

// HealthState is the storage health level used for readiness (HP-DB-009).
type HealthState string

// Health states.
const (
	HealthOK       HealthState = "ok"
	HealthDegraded HealthState = "degraded"
	HealthFailed   HealthState = "failed"
)

// HealthStatus is a snapshot of storage health.
type HealthStatus struct {
	State  HealthState `json:"state"`
	Reason string      `json:"reason,omitempty"`
	Since  time.Time   `json:"since"`
}

// Health tracks storage failures. Disk-full and I/O errors degrade; repeated I/O errors or corruption fail.
// Busy errors degrade only when sustained longer than BusyDegradeAfter.
//
// Each degradation clears only through evidence for its own cause: busy and I/O states clear on the next successful
// transaction, external reasons (Degrade) clear through Recover, and "disk full" clears only when the space probe
// commits a write that allocates new pages. An empty or small transaction proves nothing about free space
// (HP-DB-009).
type Health struct {
	mu        sync.Mutex
	clock     clock.Clock
	status    HealthStatus
	cause     degradeCause
	busySince time.Time
	ioErrors  int

	// probe commits a page-allocating write (set by the store once the writer exists); one runs at a time.
	probe   func(context.Context) error
	probing bool
}

type degradeCause int

const (
	causeNone degradeCause = iota
	causeBusy
	causeIO
	causeFull
	causeExternal
)

// BusyDegradeAfter is how long the writer may be continuously busy before readiness degrades.
const BusyDegradeAfter = 30 * time.Second

// ioFailThreshold consecutive I/O errors move health to failed.
const ioFailThreshold = 3

func newHealth(c clock.Clock) *Health {
	return &Health{clock: c, status: HealthStatus{State: HealthOK, Since: c.Now()}}
}

// Status returns the current health.
func (h *Health) Status() HealthStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

func (h *Health) set(state HealthState, cause degradeCause, reason string) {
	if h.status.State == HealthFailed && state != HealthFailed {
		return // failed is sticky until restart or explicit Reset
	}
	h.cause = cause
	if h.status.State != state || h.status.Reason != reason {
		h.status = HealthStatus{State: state, Reason: reason, Since: h.clock.Now()}
	}
}

// Observe records the outcome of a storage operation.
func (h *Health) Observe(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.clock.Now()
	switch {
	case err == nil:
		h.busySince = time.Time{}
		h.ioErrors = 0
		if h.status.State == HealthDegraded && (h.cause == causeBusy || h.cause == causeIO) {
			h.set(HealthOK, causeNone, "")
		}
	case errors.Is(err, ErrBusy):
		if h.busySince.IsZero() {
			h.busySince = now
		} else if now.Sub(h.busySince) > BusyDegradeAfter && h.cause != causeFull && h.cause != causeExternal {
			h.set(HealthDegraded, causeBusy, "database writer busy for more than "+BusyDegradeAfter.String())
		}
	case errors.Is(err, ErrFull):
		h.set(HealthDegraded, causeFull, "database disk full")
	case errors.Is(err, ErrIO):
		h.ioErrors++
		if h.ioErrors >= ioFailThreshold {
			h.set(HealthFailed, causeIO, "repeated database I/O errors")
		} else if h.cause != causeFull && h.cause != causeExternal {
			h.set(HealthDegraded, causeIO, "database I/O error")
		}
	case errors.Is(err, ErrCorrupt):
		h.set(HealthFailed, causeNone, "database corruption detected")
	}
}

// Degrade marks storage degraded for an external reason (e.g. free space below reserve).
func (h *Health) Degrade(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.set(HealthDegraded, causeExternal, reason)
}

// Recover clears a degraded state set via Degrade when its condition no longer holds.
func (h *Health) Recover(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.status.State == HealthDegraded && h.cause == causeExternal && h.status.Reason == reason {
		h.set(HealthOK, causeNone, "")
	}
}

// ProbeSpace runs the disk-full recovery probe when storage is degraded because the database was full (one probe
// at a time; a failing probe is a cheap rolled-back transaction) and clears that state when the probe commits. It
// must not be called inside a transaction.
func (h *Health) ProbeSpace(ctx context.Context) {
	h.mu.Lock()
	if h.cause != causeFull || h.status.State != HealthDegraded || h.probe == nil || h.probing {
		h.mu.Unlock()
		return
	}
	h.probing = true
	probe := h.probe
	h.mu.Unlock()
	err := probe(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.probing = false
	if err == nil && h.cause == causeFull && h.status.State == HealthDegraded {
		h.set(HealthOK, causeNone, "")
	}
}

// AcceptsWrites reports whether new access may be granted (fail closed when not OK). While the database is
// degraded as full it first runs the rate-limited space probe, so access resumes once space returns.
func (h *Health) AcceptsWrites() bool {
	h.ProbeSpace(context.Background())
	return h.Status().State == HealthOK
}
