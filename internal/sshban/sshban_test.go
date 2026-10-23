package sshban

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
)

var cfg = config.SSHBanConfig{Enabled: true, MaxFailures: 3, Window: config.Duration(time.Minute), Duration: config.Duration(10 * time.Minute),
	MaxDuration: config.Duration(30 * time.Minute), AllowCIDRs: []string{"192.0.2.0/24"}}

type fx struct {
	s   *store.Store
	clk *clock.Fake
	aw  *audit.Writer
}

func newFx(t *testing.T) *fx {
	t.Helper()
	clk := clock.NewFake(time.Unix(1_900_000_000, 0))
	s := storetest.Open(t, storetest.WithClock(clk))
	return &fx{s: s, clk: clk, aw: audit.NewWriter(keyringtest.Load(t, s))}
}

func (f *fx) svc(t *testing.T, c config.SSHBanConfig) *Service {
	t.Helper()
	svc, err := New(context.Background(), f.s, f.aw, f.clk, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// HP-SSH-026: a source is banned after max_failures within the window, for the configured duration, and the ban
// persists across restarts and doubles for repeat offenders.
func TestBanLifecycle(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	svc := f.svc(t, cfg)
	a := ip("203.0.113.7")
	svc.Failed(ctx, a, "x")
	svc.Failed(ctx, a, "x")
	f.clk.Advance(2 * time.Minute) // outside the window: the count restarts
	svc.Failed(ctx, a, "x")
	if svc.Banned(a) {
		t.Fatal("banned below the threshold within the window")
	}
	svc.Failed(ctx, a, "x")
	svc.Failed(ctx, a, "x")
	if !svc.Banned(a) || svc.Banned(ip("203.0.113.8")) {
		t.Fatal("ban not applied to exactly the failing source")
	}
	// Persisted: a new service (restart) still refuses the source.
	if again := f.svc(t, cfg); !again.Banned(a) {
		t.Fatal("ban lost on restart")
	}
	bans, err := svc.List(ctx)
	if err != nil || len(bans) != 1 || bans[0].Offense != 1 || bans[0].ExpiresAt.Sub(bans[0].BannedAt) != 10*time.Minute {
		t.Fatalf("bans %+v %v", bans, err)
	}
	f.clk.Advance(10 * time.Minute)
	if svc.Banned(a) {
		t.Fatal("ban did not expire")
	}
	for range 3 {
		svc.Failed(ctx, a, "x")
	}
	bans, _ = svc.List(ctx)
	if len(bans) != 1 || bans[0].Offense != 2 || bans[0].ExpiresAt.Sub(bans[0].BannedAt) != 20*time.Minute {
		t.Fatalf("repeat offense %+v", bans)
	}
	if err := svc.Lift(ctx, audit.Actor{Type: audit.ActorOperator, ID: "opr_x"}, bans[0].ID); err != nil || svc.Banned(a) {
		t.Fatalf("lift: %v banned=%v", err, svc.Banned(a))
	}
	if err := svc.Lift(ctx, audit.Actor{Type: audit.ActorOperator, ID: "opr_x"}, bans[0].ID); err == nil {
		t.Fatal("lifting twice succeeded")
	}
	f.clk.Advance(2 * time.Minute) // third offense: 40 min capped at max_duration 30 min
	for range 3 {
		svc.Failed(ctx, a, "x")
	}
	bans, _ = svc.List(ctx)
	if len(bans) != 1 || bans[0].Offense != 3 || bans[0].ExpiresAt.Sub(bans[0].BannedAt) != 30*time.Minute {
		t.Fatalf("capped duration %+v", bans)
	}
}

func TestIPv6PrefixAllowlistAndDisabled(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	svc := f.svc(t, cfg)
	for i := range 3 { // different addresses in one /64 count as one source
		svc.Failed(ctx, ip(fmt.Sprintf("2001:db8:1:2::%x", i+1)), "x")
	}
	if !svc.Banned(ip("2001:db8:1:2::ffff")) || svc.Banned(ip("2001:db8:1:3::1")) {
		t.Fatal("IPv6 /64 grouping")
	}
	if Source(ip("::ffff:203.0.113.1")) != "203.0.113.1" {
		t.Fatal("IPv4-mapped address not normalized")
	}
	for range 10 {
		svc.Failed(ctx, ip("192.0.2.9"), "x")
	}
	if svc.Banned(ip("192.0.2.9")) {
		t.Fatal("allowlisted source banned")
	}
	off := cfg
	off.Enabled = false
	d := f.svc(t, off)
	for range 10 {
		d.Failed(ctx, ip("198.51.100.1"), "x")
	}
	if d.Banned(ip("198.51.100.1")) {
		t.Fatal("disabled service banned")
	}
}

// A flood of distinct failing sources cannot grow the failure table beyond its bound.
func TestFailureTableBounded(t *testing.T) {
	f := newFx(t)
	svc := f.svc(t, config.SSHBanConfig{Enabled: true, MaxFailures: 1000, Window: config.Duration(time.Minute), Duration: config.Duration(time.Minute),
		MaxDuration: config.Duration(time.Minute)})
	for i := range maxTracked + 500 {
		svc.Failed(context.Background(), netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), "x")
	}
	if n := len(svc.failures); n > maxTracked {
		t.Fatalf("tracked %d sources", n)
	}
}
