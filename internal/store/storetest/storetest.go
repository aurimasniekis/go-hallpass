// Package storetest opens throwaway stores for tests and enforces the short-transaction rule (HP-DB-004).
package storetest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// MaxTxDuration is the longest a write transaction may take in tests (HP-DB-004).
// HALLPASS_TEST_TX_MAX overrides it for slow CI runners; the default matches the requirement.
var MaxTxDuration = func() time.Duration {
	if v, err := time.ParseDuration(os.Getenv("HALLPASS_TEST_TX_MAX")); err == nil && v > 0 {
		return v
	}
	return 100 * time.Millisecond
}()

// Option customizes Open.
type Option func(*store.Options)

// WithClock sets the store clock.
func WithClock(c clock.Clock) Option { return func(o *store.Options) { o.Clock = c } }

// WithDir uses dir as the data directory instead of a fresh temp dir.
func WithDir(dir string) Option { return func(o *store.Options) { o.DataDir = dir } }

// Open opens a store in a new temporary data directory and closes it at test cleanup. Any successful write
// transaction slower than MaxTxDuration fails the test.
func Open(t testing.TB, opts ...Option) *store.Store {
	t.Helper()
	var mu sync.Mutex
	o := store.Options{
		DataDir: filepath.Join(t.TempDir(), "data"),
		TxObserver: func(name string, d time.Duration, err error) {
			if err == nil && d > MaxTxDuration {
				mu.Lock()
				defer mu.Unlock()
				t.Errorf("write transaction %q took %s (> %s, HP-DB-004)", name, d, MaxTxDuration)
			}
		},
	}
	for _, opt := range opts {
		opt(&o)
	}
	s, err := store.Open(context.Background(), o)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
