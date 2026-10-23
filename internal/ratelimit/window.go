// Package ratelimit provides a fixed-window limiter keyed by request attributes that may be attacker-chosen
// (webhook path IDs, client addresses). Memory is bounded: expired windows are pruned, and when the key table is
// full, unseen keys share one overflow window so a key flood cannot grow memory or bypass the limit.
package ratelimit

import (
	"sync"
	"time"
)

const overflowKey = "\x00overflow"

// Window allows Limit events per Period for each key.
type Window struct {
	Limit   int
	Period  time.Duration
	MaxKeys int // default 4096

	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	start time.Time
	n     int
}

// Allow records an event for key at now and reports whether it is within the limit.
func (w *Window) Allow(key string, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.windows == nil {
		w.windows = map[string]*window{}
	}
	maxKeys := w.MaxKeys
	if maxKeys <= 0 {
		maxKeys = 4096
	}
	win := w.windows[key]
	if win == nil && len(w.windows) >= maxKeys {
		w.prune(now)
		if len(w.windows) >= maxKeys {
			key = overflowKey
			win = w.windows[key]
		}
	}
	if win == nil || now.Sub(win.start) >= w.Period {
		win = &window{start: now}
		w.windows[key] = win
	}
	win.n++
	return win.n <= w.Limit
}

func (w *Window) prune(now time.Time) {
	for k, win := range w.windows {
		if now.Sub(win.start) >= w.Period {
			delete(w.windows, k)
		}
	}
}

// Len returns the number of tracked keys (tests).
func (w *Window) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.windows)
}
