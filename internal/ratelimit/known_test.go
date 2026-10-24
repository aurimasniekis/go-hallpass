package ratelimit

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// SR-19: KnownSet answers from a cached set, reloads at most once per MissReload for misses, and keeps the last
// good set on load errors.
func TestKnownSet(t *testing.T) {
	loads, keys, fail := 0, []string{"a"}, false
	k := &KnownSet{Load: func(context.Context) ([]string, error) {
		loads++
		if fail {
			return nil, errors.New("db down")
		}
		return keys, nil
	}}
	now := time.Unix(1000, 0)
	if !k.Contains(context.Background(), "a", now) || loads != 1 {
		t.Fatalf("first lookup: loads %d", loads)
	}
	for i := range 1000 {
		if k.Contains(context.Background(), string(rune('b'+i%20)), now) {
			t.Fatal("unknown key reported known")
		}
	}
	if loads != 1 {
		t.Fatalf("misses within MissReload reloaded %d times", loads-1)
	}
	keys = []string{"a", "new"}
	if !k.Contains(context.Background(), "new", now.Add(time.Second)) {
		t.Fatal("new key not picked up after MissReload")
	}
	fail = true
	if !k.Contains(context.Background(), "a", now.Add(time.Minute)) {
		t.Fatal("load error dropped the known set")
	}
	k.Invalidate()
	fail = false
	keys = []string{"z"}
	if !k.Contains(context.Background(), "z", now.Add(time.Minute)) || k.Contains(context.Background(), "a", now.Add(time.Minute)) {
		t.Fatal("invalidate did not reload")
	}
}

func TestSourceKey(t *testing.T) {
	a := SourceKeyOf("[2001:db8:1:2:aaaa::1]:443")
	b := SourceKeyOf("[2001:db8:1:2:bbbb::9]:80")
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 /64 keys %q %q", a, b)
	}
	if SourceKeyOf("192.0.2.1:5") != "192.0.2.1" || SourceKey(netip.MustParseAddr("::ffff:192.0.2.1")) != "192.0.2.1" {
		t.Fatal("IPv4 key")
	}
	if SourceKeyOf("garbage") != "invalid" {
		t.Fatal("invalid key")
	}
}
