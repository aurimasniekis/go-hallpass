package ratelimit

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// KnownSet caches the set of keys that exist (integration or collector IDs). Callers consult it before a per-key
// Window, so attacker-chosen unknown keys never enter the Window's table: a flood of random IDs can then neither
// evict real keys nor push them into the shared overflow window (security review SR-19).
//
// The set reloads every TTL; a miss may trigger an early reload at most once per MissReload, so a newly created key
// is usable within about a second while a flood of unknown keys costs at most one load per MissReload.
type KnownSet struct {
	Load       func(ctx context.Context) ([]string, error)
	TTL        time.Duration // default 10s
	MissReload time.Duration // default 1s

	mu       sync.Mutex
	set      map[string]struct{}
	loadedAt time.Time
}

// Contains reports whether key is known at now. Load errors keep the previous set (empty, so fail closed, when
// nothing was loaded yet).
func (k *KnownSet) Contains(ctx context.Context, key string, now time.Time) bool {
	ttl, miss := k.TTL, k.MissReload
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	if miss <= 0 {
		miss = time.Second
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.set == nil || now.Sub(k.loadedAt) >= ttl {
		k.reload(ctx, now)
	}
	if _, ok := k.set[key]; ok {
		return true
	}
	if now.Sub(k.loadedAt) >= miss {
		k.reload(ctx, now)
		_, ok := k.set[key]
		return ok
	}
	return false
}

// Invalidate forces a reload on the next Contains (call it after the key set changes).
func (k *KnownSet) Invalidate() {
	k.mu.Lock()
	k.set = nil
	k.mu.Unlock()
}

func (k *KnownSet) reload(ctx context.Context, now time.Time) {
	keys, err := k.Load(ctx)
	if err != nil {
		if k.set == nil {
			k.set = map[string]struct{}{}
		}
		k.loadedAt = now // retry after MissReload, not on every call
		return
	}
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[key] = struct{}{}
	}
	k.set, k.loadedAt = set, now
}

// SourceKey is the rate-limit key for a client address: the IPv4 address, or the IPv6 /64 a single host or
// subscriber typically controls. Invalid addresses share one key.
func SourceKey(addr netip.Addr) string {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return "invalid"
	}
	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return p.String()
	}
	return addr.String()
}

// SourceKeyOf parses a host:port remote address (http.Request.RemoteAddr) into SourceKey.
func SourceKeyOf(remoteAddr string) string {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		a, err := netip.ParseAddr(remoteAddr)
		if err != nil {
			return "invalid"
		}
		return SourceKey(a)
	}
	return SourceKey(ap.Addr())
}
