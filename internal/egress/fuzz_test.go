package egress

import (
	"net/netip"
	"strings"
	"testing"
)

// HP-TST-002, HP-SRV-009: with an allow-everything policy, no special-purpose address (loopback, link-local,
// metadata, multicast, NAT64/6to4, …) is ever permitted, in any textual form, and names are syntactically valid and
// never "localhost".
func FuzzValidateDestination(f *testing.F) {
	for _, h := range []string{"127.0.0.1", "[::1]", "::ffff:127.0.0.1", "169.254.169.254", "0.0.0.0", "fe80::1%eth0", "64:ff9b::7f00:1",
		"2002:7f00:1::", "web1.example", "localhost.", "LOCALHOST", "2130706433", "0x7f.1", "-bad.example", "a..b", "10.0.0.1",
		"[fd00:ec2::254]", "100.100.100.200"} {
		f.Add(h, 22)
	}
	g, err := New([]string{"0.0.0.0/0", "::/0"}, nil, nil, 0)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, host string, port int) {
		if g.ValidateDestination(host, port) != nil {
			return
		}
		if port < 1 || port > 65535 {
			t.Fatalf("port %d accepted", port)
		}
		if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			ip = ip.Unmap().WithZone("")
			for _, d := range DefaultDenied {
				if d.Contains(ip) {
					t.Fatalf("special-purpose address %q (%s in %s) accepted", host, ip, d)
				}
			}
			return
		}
		if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") || len(host) > 253 || !hostnameRE.MatchString(host) {
			t.Fatalf("invalid host name %q accepted", host)
		}
	})
}

// HP-TST-002, HP-SRV-009: AllowedAddr permits an address only inside the allow ranges and outside every
// default-denied range not explicitly re-allowed.
func FuzzAllowedAddr(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{10, 1, 2, 3})
	f.Add(netip.MustParseAddr("::ffff:169.254.169.254").AsSlice())
	f.Add(netip.MustParseAddr("64:ff9b::a01:203").AsSlice())
	g, err := New([]string{"10.0.0.0/8", "127.0.0.0/8", "64:ff9b::/96", "2001:db8::/32"}, []string{"127.0.0.1/32"}, nil, 0)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ip, ok := netip.AddrFromSlice(b)
		if !ok || g.AllowedAddr(ip) != nil {
			return
		}
		u := ip.Unmap()
		if !containedIn(g.allow, u) {
			t.Fatalf("%s outside allow ranges accepted", ip)
		}
		for _, d := range DefaultDenied {
			if d.Contains(u) && !containedIn(g.special, u) {
				t.Fatalf("%s in denied %s accepted", ip, d)
			}
		}
	})
}
