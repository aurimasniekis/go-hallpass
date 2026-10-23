// Package egress restricts outbound destination connections (HP-SRV-009, ADR-0021).
//
// A destination may be dialed only when every address its name resolves to lies inside the operator's
// allow ranges and outside the default-denied special ranges (loopback, link-local, metadata, multicast, …) unless
// a special range is explicitly re-allowed. The connection goes to the validated IP, so a second DNS answer cannot
// redirect it (no DNS rebinding), and the dialer re-checks the peer address at connect time.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrDenied is returned when a destination is outside the egress policy.
var ErrDenied = errors.New("destination not permitted by egress policy")

// DefaultDenied are special-purpose ranges never dialed unless listed in allow_special_cidrs.
var DefaultDenied = mustPrefixes(
	"0.0.0.0/8",          // "this" network
	"127.0.0.0/8",        // loopback
	"169.254.0.0/16",     // link-local, includes cloud metadata 169.254.169.254
	"100.100.100.200/32", // Alibaba Cloud metadata
	"224.0.0.0/4",        // multicast
	"240.0.0.0/4",        // reserved, includes broadcast
	"::/128",             // unspecified
	"::1/128",            // loopback
	"fe80::/10",          // link-local
	"ff00::/8",           // multicast
	"fd00:ec2::254/128",  // AWS IPv6 metadata
	"64:ff9b::/96",       // NAT64 well-known prefix (can reach arbitrary IPv4)
	"2002::/16",          // 6to4 (embeds arbitrary IPv4)
	"64:ff9b:1::/48",     // local-use NAT64 (RFC 8215, can reach arbitrary IPv4)
	"2001::/32",          // Teredo (embeds arbitrary IPv4)
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Resolver resolves host names (net.DefaultResolver in production).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Guard enforces the egress policy.
type Guard struct {
	allow    []netip.Prefix
	special  []netip.Prefix
	resolver Resolver
	timeout  time.Duration
}

// New builds a guard from CIDR strings.
func New(allowCIDRs, allowSpecial []string, r Resolver, dialTimeout time.Duration) (*Guard, error) {
	g := &Guard{resolver: r, timeout: dialTimeout}
	if g.resolver == nil {
		g.resolver = net.DefaultResolver
	}
	if g.timeout <= 0 {
		g.timeout = 10 * time.Second
	}
	for _, c := range allowCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("egress allow cidr %q: %w", c, err)
		}
		g.allow = append(g.allow, p.Masked())
	}
	for _, c := range allowSpecial {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("egress special cidr %q: %w", c, err)
		}
		g.special = append(g.special, p.Masked())
	}
	return g, nil
}

// AllowedAddr reports whether ip may be dialed.
func (g *Guard) AllowedAddr(ip netip.Addr) error {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrDenied)
	}
	inAllow := false
	for _, p := range g.allow {
		if p.Contains(ip) {
			inAllow = true
			break
		}
	}
	if !inAllow {
		return fmt.Errorf("%w: %s is outside egress.allow_cidrs", ErrDenied, ip)
	}
	for _, d := range DefaultDenied {
		if d.Contains(ip) && !containedIn(g.special, ip) {
			return fmt.Errorf("%w: %s is in special-purpose range %s (re-allow with egress.allow_special_cidrs)", ErrDenied, ip, d)
		}
	}
	return nil
}

func containedIn(ps []netip.Prefix, ip netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var hostnameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

// ValidateDestination checks a stored destination address at save time: an IP must satisfy the policy; a host name
// must be syntactically valid (it is re-checked after resolution at dial time).
func (g *Guard) ValidateDestination(host string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: invalid port %d", ErrDenied, port)
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return g.AllowedAddr(ip)
	}
	if len(host) > 253 || !hostnameRE.MatchString(host) {
		return fmt.Errorf("%w: %q is neither an IP address nor a valid host name", ErrDenied, host)
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return fmt.Errorf("%w: localhost is not a valid destination name", ErrDenied)
	}
	return nil
}

// Resolve returns the address to dial. Every resolved address must be permitted; mixed answers are refused.
func (g *Guard) Resolve(ctx context.Context, host string, port int) (netip.AddrPort, error) {
	if err := g.ValidateDestination(host, port); err != nil {
		return netip.AddrPort{}, err
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil //nolint:gosec // validated range
	}
	addrs, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, a := range addrs {
		if err := g.AllowedAddr(a); err != nil {
			return netip.AddrPort{}, fmt.Errorf("%s resolved to a forbidden address: %w", host, err)
		}
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil //nolint:gosec // validated range
}

// Dial resolves host through the policy and connects to the validated address. The dialer's Control hook
// re-validates the socket's peer address as a second line of defense.
func (g *Guard) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	ap, err := g.Resolve(ctx, host, port)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{
		Timeout: g.timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			h, p, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(h)
			if err != nil {
				return fmt.Errorf("%w: unparsable peer %q", ErrDenied, address)
			}
			if pn, _ := strconv.Atoi(p); pn != port {
				return fmt.Errorf("%w: unexpected port %s", ErrDenied, p)
			}
			return g.AllowedAddr(ip)
		},
	}
	return d.DialContext(ctx, "tcp", ap.String())
}
