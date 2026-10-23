package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// HP-SRV-009: anti-SSRF policy table.
func TestAllowedAddr(t *testing.T) {
	g, err := New([]string{"10.0.0.0/8", "0.0.0.0/0", "::/0"}, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	denied := []string{
		"127.0.0.1", "127.255.0.1", "169.254.169.254", "169.254.1.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "ff02::1", "fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
		"100.100.100.200", "64:ff9b::7f00:1", "2002:7f00:1::", "64:ff9b:1::7f00:1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
	}
	for _, s := range denied {
		if err := g.AllowedAddr(netip.MustParseAddr(s)); !errors.Is(err, ErrDenied) {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"10.1.2.3", "8.8.8.8", "2001:db8::1", "::ffff:10.0.0.1"} {
		if err := g.AllowedAddr(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s denied: %v", s, err)
		}
	}
	narrow, _ := New([]string{"10.0.0.0/8"}, nil, nil, 0)
	if err := narrow.AllowedAddr(netip.MustParseAddr("192.168.1.1")); !errors.Is(err, ErrDenied) {
		t.Fatal("address outside allow_cidrs accepted")
	}
	empty, _ := New(nil, nil, nil, 0)
	if err := empty.AllowedAddr(netip.MustParseAddr("10.0.0.1")); !errors.Is(err, ErrDenied) {
		t.Fatal("empty allow list must deny everything")
	}
	special, _ := New([]string{"127.0.0.0/8"}, []string{"127.0.0.1/32"}, nil, 0)
	if err := special.AllowedAddr(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatalf("explicit special re-allow ignored: %v", err)
	}
	if err := special.AllowedAddr(netip.MustParseAddr("127.0.0.2")); err == nil {
		t.Fatal("special re-allow too broad")
	}
}

func TestValidateDestination(t *testing.T) {
	g, _ := New([]string{"10.0.0.0/8"}, nil, nil, 0)
	for _, ok := range []struct {
		h string
		p int
	}{{"10.0.0.5", 22}, {"db1.internal.example", 2222}, {"[10.0.0.6]", 22}} {
		if err := g.ValidateDestination(ok.h, ok.p); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range []struct {
		h string
		p int
	}{{"127.0.0.1", 22}, {"10.0.0.5", 0}, {"10.0.0.5", 70000}, {"bad_host!", 22}, {"localhost", 22}, {"-x.example", 22}} {
		if err := g.ValidateDestination(bad.h, bad.p); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// DNS answers that include any forbidden address are refused (anti-rebinding).
func TestResolve(t *testing.T) {
	r := fakeResolver{
		"good.example":  addrs("10.0.0.7", "10.0.0.8"),
		"mixed.example": addrs("10.0.0.7", "169.254.169.254"),
		"meta.example":  addrs("169.254.169.254"),
		"v6map.example": addrs("::ffff:127.0.0.1"),
	}
	g, _ := New([]string{"10.0.0.0/8"}, nil, r, 0)
	ctx := context.Background()
	ap, err := g.Resolve(ctx, "good.example", 22)
	if err != nil || ap.String() != "10.0.0.7:22" {
		t.Fatalf("%v %v", ap, err)
	}
	for _, h := range []string{"mixed.example", "meta.example", "v6map.example", "missing.example"} {
		if _, err := g.Resolve(ctx, h, 22); err == nil {
			t.Errorf("%s resolved", h)
		}
	}
}

func TestDialEnforcesPolicy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	deny, _ := New([]string{"0.0.0.0/0"}, nil, nil, 0)
	if _, err := deny.Dial(ctx, "127.0.0.1", port); !errors.Is(err, ErrDenied) {
		t.Fatalf("loopback dialed without special allowance: %v", err)
	}
	allow, _ := New([]string{"127.0.0.0/8"}, []string{"127.0.0.1/32"}, nil, 0)
	c, err := allow.Dial(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = strconv.Itoa(port)
}
