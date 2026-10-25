package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ValidationError aggregates every configuration problem found.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Validate checks the configuration, including production-mode restrictions.
func (c *Config) Validate() error {
	v := &validator{}
	switch c.Mode {
	case ModeProduction, ModeDevelopment:
	default:
		v.add("mode must be %q or %q, got %q", ModeProduction, ModeDevelopment, c.Mode)
	}
	prod := c.IsProduction()

	if !filepath.IsAbs(c.DataDir) {
		v.add("data_dir must be an absolute path")
	}
	c.validatePublicURL(v, prod)
	c.validateKEK(v, prod)

	v.listen("ssh.listen", c.SSH.Listen)
	if a := strings.TrimSpace(c.SSH.PublicAddress); a != "" {
		h, p := a, "22"
		if strings.Contains(a, ":") {
			var err error
			if h, p, err = net.SplitHostPort(a); err != nil {
				v.add("ssh.public_address must be host or host:port, got %q", a)
			}
		}
		if n, err := strconv.Atoi(p); h == "" || strings.ContainsAny(h, "/ @") || err != nil || n < 1 || n > 65535 {
			v.add("ssh.public_address must be host or host:port, got %q", a)
		}
	}
	v.listen("http.listen", c.HTTP.Listen)
	if c.HTTP.MetricsListen != "" {
		v.listen("http.metrics_listen", c.HTTP.MetricsListen)
	}
	if (c.HTTP.TLSCertFile == "") != (c.HTTP.TLSKeyFile == "") {
		v.add("http.tls_cert_file and http.tls_key_file must be set together")
	}
	for _, p := range c.HTTP.TrustedProxies {
		v.prefix("http.trusted_proxies", p)
	}

	v.positive("ssh.max_unauthenticated", c.SSH.MaxUnauthenticated)
	v.positive("ssh.max_unauthenticated_per_ip", c.SSH.MaxUnauthenticatedPerIP)
	v.positive("ssh.max_auth_tries", c.SSH.MaxAuthTries)
	v.positive("ssh.max_connections_per_agent", c.SSH.MaxConnectionsPerAgent)
	v.positive("ssh.max_channels_per_connection", c.SSH.MaxChannelsPerConn)
	v.positive("ssh.keepalive_max_missed", c.SSH.KeepaliveMaxMissed)
	v.durationRange("ssh.handshake_timeout", c.SSH.HandshakeTimeout, time.Second, 2*time.Minute)
	v.durationRange("ssh.keepalive_interval", c.SSH.KeepaliveInterval, time.Second, 10*time.Minute)
	v.durationRange("ssh.idle_timeout", c.SSH.IdleTimeout, time.Minute, 24*time.Hour)
	v.durationRange("ssh.dial_timeout", c.SSH.DialTimeout, time.Second, 2*time.Minute)
	if b := c.SSH.Ban; b.Enabled {
		if b.MaxFailures < 3 || b.MaxFailures > 10000 {
			v.add("ssh.ban.max_failures must be between 3 and 10000")
		}
		v.durationRange("ssh.ban.window", b.Window, time.Minute, 24*time.Hour)
		v.durationRange("ssh.ban.duration", b.Duration, time.Minute, 30*24*time.Hour)
		v.durationRange("ssh.ban.max_duration", b.MaxDuration, b.Duration.D(), 30*24*time.Hour)
	}
	for _, p := range c.SSH.Ban.AllowCIDRs {
		v.prefix("ssh.ban.allow_cidrs", p)
	}
	for _, e := range c.SSH.EnvAllow {
		if e == "" || strings.ContainsAny(e, "= ") || (strings.Contains(e, "*") && !strings.HasSuffix(e, "*")) {
			v.add("ssh.env_allow entry %q must be a variable name or a trailing-* prefix", e)
		}
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		v.add("log.level must be debug, info, warn or error")
	}
	switch c.Log.Format {
	case "json":
	case "text":
		if prod {
			v.add("log.format text is development-only; production logs are JSON")
		}
	default:
		v.add("log.format must be json or text")
	}

	if c.Storage.MinFreeBytes < 0 || c.Storage.MinFreePercent < 0 || c.Storage.MinFreePercent > 50 {
		v.add("storage.min_free_bytes must be >= 0 and storage.min_free_percent within 0..50")
	}
	if c.Storage.AllowNetworkFS && prod {
		v.add("storage.allow_network_fs is not allowed in production (HP-DB-007)")
	}
	v.positive("storage.pre_migration_snapshots", c.Storage.PreMigrationSnapshots)

	switch c.Recording.Durability {
	case "group", "strict":
	default:
		v.add("recording.durability must be group or strict")
	}
	v.durationRange("recording.flush_interval", c.Recording.FlushInterval, 10*time.Millisecond, 250*time.Millisecond)
	if c.Recording.SegmentMaxBytes < 1<<20 {
		v.add("recording.segment_max_bytes must be at least 1 MiB")
	}
	v.durationRange("recording.segment_max_age", c.Recording.SegmentMaxAge, time.Minute, 24*time.Hour)
	v.positive("recording.queue_records", c.Recording.QueueRecords)
	if c.Recording.QueueBytes < 64<<10 { // one maximum-size HPREC1 record (64 KiB frame) must fit, or every large write stalls
		v.add("recording.queue_bytes must be at least 65536 (one maximum-size record)")
	}
	v.durationRange("recording.block_timeout", c.Recording.BlockTimeout, time.Second, time.Minute)
	v.durationRange("recording.default_retention", c.Recording.DefaultRetention, 24*time.Hour, 10*365*24*time.Hour)
	for _, e := range c.Recording.RetentionClasses {
		name, val, ok := strings.Cut(e, "=")
		d, err := time.ParseDuration(strings.TrimSpace(val))
		if !ok || strings.TrimSpace(name) == "" || err != nil || d < 24*time.Hour || d > 10*365*24*time.Hour {
			v.add("recording.retention_classes: entries must be class=duration with 24h <= duration <= 10y (got %q)", e)
		}
	}

	for _, p := range c.Egress.AllowCIDRs {
		v.prefix("egress.allow_cidrs", p)
	}
	for _, p := range c.Egress.AllowSpecialCIDRs {
		v.prefix("egress.allow_special_cidrs", p)
	}
	for _, p := range c.Egress.SourceAddresses {
		if _, err := netip.ParseAddr(p); err != nil {
			v.prefix("egress.source_addresses", p)
		}
	}

	c.validateAccess(v)

	v.durationRange("auth.session_idle_timeout", c.Auth.SessionIdleTimeout, time.Minute, 24*time.Hour)
	v.durationRange("auth.session_absolute_timeout", c.Auth.SessionAbsoluteTimeout, 10*time.Minute, 30*24*time.Hour)
	if c.Auth.SessionIdleTimeout > c.Auth.SessionAbsoluteTimeout {
		v.add("auth.session_idle_timeout must not exceed auth.session_absolute_timeout")
	}
	v.durationRange("auth.reauth_window", c.Auth.ReauthWindow, 30*time.Second, time.Hour)
	if c.Auth.PasswordMinBytes < 8 || c.Auth.PasswordMinBytes > 128 {
		v.add("auth.password_min_bytes must be within 8..128")
	}

	if c.Telemetry.OTLPEndpoint != "" {
		if u, err := url.Parse(c.Telemetry.OTLPEndpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			v.add("telemetry.otlp_endpoint must be an http(s) URL")
		}
	}
	v.durationRange("shutdown.drain_timeout", c.Shutdown.DrainTimeout, 0, 10*time.Minute)

	if prod {
		if c.Dev.InsecureHTTP {
			v.add("dev.insecure_http is development-only")
		}
		if c.Dev.Auth {
			v.add("dev.auth is development-only (HP-AUTH-017)")
		}
		if c.Dev.SeedFile != "" {
			v.add("dev.seed_file is development-only")
		}
	}
	return v.err()
}

func (c *Config) validatePublicURL(v *validator, prod bool) {
	if c.PublicURL == "" {
		v.add("public_url is required (the externally reachable https URL of the web console)")
		return
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		v.add("public_url must be an absolute URL without credentials, query or fragment")
		return
	}
	if u.Path != "" && u.Path != "/" {
		v.add("public_url must not contain a path (serve HallPass at the origin root)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if prod {
			v.add("public_url must use https in production")
		} else if !IsLoopbackHost(u.Hostname()) {
			v.add("public_url may use http only for localhost in development mode")
		}
	default:
		v.add("public_url scheme must be https")
	}
}

func (c *Config) validateKEK(v *validator, prod bool) {
	switch c.KEK.Source {
	case "file":
		if c.KEK.File == "" {
			if prod {
				v.add("kek.file is required in production (HP-CRY-001)")
			}
			return
		}
		if !filepath.IsAbs(c.KEK.File) {
			v.add("kek.file must be an absolute path")
			return
		}
		if prod && isWithin(c.KEK.File, c.DataDir) {
			v.add("kek.file must be stored outside data_dir in production")
		}
	case "env":
	default:
		v.add("kek.source must be file or env")
	}
}

func (c *Config) validateAccess(v *validator) {
	a := c.Access
	v.durationRange("access.wait_timeout_max", a.WaitTimeoutMax, time.Second, 15*time.Minute)
	v.durationRange("access.wait_timeout_default", a.WaitTimeoutDefault, 0, a.WaitTimeoutMax.D())
	v.durationRange("access.pending_expiry", a.PendingExpiry, time.Minute, 24*time.Hour)
	v.durationRange("access.max_grant_duration", a.MaxGrantDuration, time.Minute, 7*24*time.Hour)
	v.durationRange("access.enforcement_tick", a.EnforcementTick, 100*time.Millisecond, 2*time.Second)
	v.durationRange("access.min_remaining_to_connect", a.MinRemainingToConnect, 0, time.Minute)
	v.positive("access.requests_per_agent_hour", a.RequestsPerAgentHour)
	v.positive("access.max_pending_per_agent", a.MaxPendingPerAgent)
	if len(a.DurationPresets) == 0 {
		v.add("access.duration_presets must not be empty")
	}
	if !slices.IsSortedFunc(a.DurationPresets, func(x, y Duration) int { return int(x - y) }) {
		v.add("access.duration_presets must be in ascending order")
	}
	for _, p := range a.DurationPresets {
		if p.D() < time.Minute || p > a.MaxGrantDuration {
			v.add("access.duration_presets entry %s must be within 1m..max_grant_duration", p.D())
		}
	}
}

// IsLoopbackHost reports whether host is localhost or a loopback IP.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

type validator struct{ problems []string }

func (v *validator) add(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func (v *validator) positive(name string, n int) {
	if n <= 0 {
		v.add("%s must be positive", name)
	}
}

func (v *validator) durationRange(name string, d Duration, lo, hi time.Duration) {
	if d.D() < lo || d.D() > hi {
		v.add("%s must be within %s..%s, got %s", name, lo, hi, d.D())
	}
}

func (v *validator) listen(name, addr string) {
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		v.add("%s must be host:port, got %q", name, addr)
	}
}

func (v *validator) prefix(name, s string) {
	if _, err := netip.ParsePrefix(s); err != nil {
		v.add("%s entry %q is not a CIDR prefix", name, s)
	}
}

func (v *validator) err() error {
	if len(v.problems) == 0 {
		return nil
	}
	return &ValidationError{Problems: v.problems}
}
