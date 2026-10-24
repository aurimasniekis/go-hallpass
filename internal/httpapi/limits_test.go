package httpapi

import (
	"fmt"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
)

// SR-30: IPv6 sources share one bucket per /64, and the limiter table is bounded.
func TestReviewSR30LimiterKeysAndCap(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:1:2::1": "2001:db8:1:2::/64", "2001:db8:1:2:ffff::9": "2001:db8:1:2::/64", "::ffff:192.0.2.1": "192.0.2.1",
		"192.0.2.1": "192.0.2.1", "": "",
	} {
		if got := sourceKey(in); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", in, got, want)
		}
	}

	clk := clock.NewFake(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	l := newLimiters(clk)
	l.maxKeys = 10
	for i := range 3 {
		if !l.allowKey("anon:"+sourceKey(fmt.Sprintf("2001:db8::%x", i+1)), 3, true) {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.allowKey("anon:"+sourceKey("2001:db8::ffff"), 3, true) {
		t.Fatal("addresses in one /64 are limited separately")
	}
	for i := range 20 {
		l.allowKey(fmt.Sprintf("anon:k%d", i), 3, true)
	}
	if len(l.m) > l.maxKeys {
		t.Fatalf("table grew to %d keys (cap %d)", len(l.m), l.maxKeys)
	}
	if l.allowKey("anon:new", 3, true) {
		t.Fatal("full table admitted a new unauthenticated key")
	}
	if !l.allowKey("ses:new", 3, false) {
		t.Fatal("full table refused a fail-open key")
	}
	// Expired windows make room again.
	clk.Advance(time.Minute + time.Second)
	if !l.allowKey("anon:new", 3, true) {
		t.Fatal("expired windows not reclaimed")
	}
}
