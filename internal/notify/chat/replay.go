package chat

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
)

// ReplayCache remembers inbound request fingerprints. The production implementation is a DB table so that it survives
// restarts (PLAN §10.4); MemoryReplayCache is for tests and single-process development.
type ReplayCache interface {
	// Remember atomically records key until expiresAt. It returns true if the key was newly recorded and false if it
	// was already present (a replay). Implementations must be safe for concurrent use. Callers fail closed on error.
	Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error)
}

// ErrReplayCacheFull is returned by MemoryReplayCache when it is at capacity with no expired entries.
var ErrReplayCacheFull = errors.New("chat: replay cache full")

// MemoryReplayCache is a bounded in-memory ReplayCache.
type MemoryReplayCache struct {
	mu      sync.Mutex
	clock   clock.Clock
	max     int
	entries map[string]time.Time
}

// NewMemoryReplayCache returns a cache holding at most maxEntries live keys (default 100000 if <= 0).
func NewMemoryReplayCache(c clock.Clock, maxEntries int) *MemoryReplayCache {
	if c == nil {
		c = clock.System{}
	}
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	return &MemoryReplayCache{clock: c, max: maxEntries, entries: map[string]time.Time{}}
}

// Remember implements ReplayCache.
func (m *MemoryReplayCache) Remember(_ context.Context, key string, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	if exp, ok := m.entries[key]; ok && now.Before(exp) {
		return false, nil
	}
	if len(m.entries) >= m.max {
		for k, exp := range m.entries {
			if !now.Before(exp) {
				delete(m.entries, k)
			}
		}
		if len(m.entries) >= m.max {
			return false, ErrReplayCacheFull
		}
	}
	m.entries[key] = expiresAt
	return true, nil
}

// Len returns the number of stored keys (including expired ones not yet evicted).
func (m *MemoryReplayCache) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}
