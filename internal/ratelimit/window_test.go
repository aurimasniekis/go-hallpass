package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestWindowLimitsPerKey(t *testing.T) {
	w := &Window{Limit: 2, Period: time.Second}
	now := time.Unix(1000, 0)
	for i, want := range []bool{true, true, false} {
		if got := w.Allow("a", now); got != want {
			t.Fatalf("event %d: allowed=%v", i+1, got)
		}
	}
	if !w.Allow("b", now) {
		t.Fatal("keys are not independent")
	}
	if !w.Allow("a", now.Add(time.Second)) {
		t.Fatal("window did not reset")
	}
}

// A flood of distinct keys must not grow memory without bound or escape the limit.
func TestWindowBoundedKeys(t *testing.T) {
	w := &Window{Limit: 1, Period: time.Second, MaxKeys: 8}
	now := time.Unix(1000, 0)
	allowed := 0
	for i := range 1000 {
		if w.Allow(fmt.Sprint("k", i), now) {
			allowed++
		}
	}
	if w.Len() > 9 {
		t.Fatalf("tracked %d keys", w.Len())
	}
	if allowed > 9 {
		t.Fatalf("flood allowed %d events", allowed)
	}
	later := now.Add(2 * time.Second)
	if !w.Allow("fresh", later) {
		t.Fatal("expired windows were not pruned")
	}
}
