// Package clock provides an injectable time source. Persisted times are UTC microseconds (ADR-0010).
package clock

import (
	"sync"
	"time"
)

// Clock is a time source.
type Clock interface {
	Now() time.Time
}

// System is the real clock.
type System struct{}

// Now returns the current time.
func (System) Now() time.Time { return time.Now() }

// Fake is a manually advanced clock for tests.
type Fake struct {
	mu sync.Mutex
	t  time.Time
}

// NewFake returns a fake clock set to t.
func NewFake(t time.Time) *Fake { return &Fake{t: t} }

// Now returns the fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

// Advance moves the fake time forward.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

// Set sets the fake time.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	f.t = t
	f.mu.Unlock()
}

// Micros converts t to Unix microseconds (the persisted representation).
func Micros(t time.Time) int64 { return t.UnixMicro() }

// FromMicros converts persisted Unix microseconds to a UTC time.
func FromMicros(us int64) time.Time { return time.UnixMicro(us).UTC() }
