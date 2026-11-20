package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hallpass.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalProd = "public_url: https://hp.example.com\n"

func problems(t *testing.T, err error) []string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %v", err)
	}
	return ve.Problems
}

func hasProblem(ps []string, substr string) bool {
	return slices.ContainsFunc(ps, func(p string) bool { return strings.Contains(p, substr) })
}

func TestExampleConfigValid(t *testing.T) {
	cfg, err := Load("../../deploy/examples/hallpass.example.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsProduction() || cfg.SSH.Listen != ":2222" {
		t.Fatalf("unexpected: %+v", cfg)
	}
}

func TestDefaultsRequirePublicURL(t *testing.T) {
	_, err := Load("", nil)
	if !hasProblem(problems(t, err), "public_url is required") {
		t.Fatal(err)
	}
}

func TestMinimalProduction(t *testing.T) {
	cfg, err := Load(writeFile(t, minimalProd), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeProduction || cfg.Access.WaitTimeoutDefault.D() != 120*time.Second {
		t.Fatalf("defaults not applied: %+v", cfg.Access)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, err := Load(writeFile(t, minimalProd+"sssh:\n  listen: x\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "sssh") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestMultipleDocumentsRejected(t *testing.T) {
	if _, err := Load(writeFile(t, minimalProd+"---\nmode: development\n"), nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestProductionRejectsDevFeatures(t *testing.T) {
	cases := map[string]string{
		"http public url":   "public_url: http://hp.example.com\n",
		"http localhost":    "public_url: http://localhost:8080\n",
		"dev auth":          minimalProd + "dev:\n  auth: true\n",
		"dev seed":          minimalProd + "dev:\n  seed_file: /tmp/x\n",
		"insecure http":     minimalProd + "dev:\n  insecure_http: true\n",
		"text logs":         minimalProd + "log:\n  format: text\n",
		"network fs":        minimalProd + "storage:\n  allow_network_fs: true\n",
		"kek in data dir":   minimalProd + "data_dir: /srv/hp\nkek:\n  file: /srv/hp/kek\n",
		"missing kek file":  minimalProd + "kek:\n  file: \"\"\n",
		"relative kek file": minimalProd + "kek:\n  file: kek\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeFile(t, content), nil); err == nil {
				t.Fatal("expected production validation error")
			}
		})
	}
}

func TestDevelopmentAllowsLocalhostAndDevFeatures(t *testing.T) {
	content := "mode: development\npublic_url: http://localhost:8080\nkek:\n  file: \"\"\nlog:\n  format: text\ndev:\n  auth: true\n"
	if _, err := Load(writeFile(t, content), nil); err != nil {
		t.Fatal(err)
	}
	content = "mode: development\npublic_url: http://hp.example.com\n"
	if _, err := Load(writeFile(t, content), nil); err == nil {
		t.Fatal("dev mode must still restrict http to localhost")
	}
}

func TestEnvOverrides(t *testing.T) {
	env := []string{
		"HALLPASS_SSH_LISTEN=:22",
		"HALLPASS_ACCESS_WAIT_TIMEOUT_DEFAULT=30s",
		"HALLPASS_EGRESS_ALLOW_CIDRS=10.0.0.0/8, 192.168.0.0/16",
		"HALLPASS_ACCESS_DURATION_PRESETS=5m,1h",
		"HALLPASS_STORAGE_MIN_FREE_BYTES=1024",
		"HALLPASS_KEK=Zm9v", // not a config key; allowed
		"PATH=/bin",
	}
	cfg, err := Load(writeFile(t, minimalProd), env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSH.Listen != ":22" || cfg.Access.WaitTimeoutDefault.D() != 30*time.Second ||
		len(cfg.Egress.AllowCIDRs) != 2 || len(cfg.Access.DurationPresets) != 2 || cfg.Storage.MinFreeBytes != 1024 {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
}

func TestUnknownEnvRejected(t *testing.T) {
	_, err := Load(writeFile(t, minimalProd), []string{"HALLPASS_SSH_LISTN=:22"})
	if err == nil || !strings.Contains(err.Error(), "HALLPASS_SSH_LISTN") {
		t.Fatalf("expected unknown env error, got %v", err)
	}
}

func TestBadEnvValue(t *testing.T) {
	if _, err := Load(writeFile(t, minimalProd), []string{"HALLPASS_SSH_IDLE_TIMEOUT=forever"}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestRangeValidation(t *testing.T) {
	_, err := Load(writeFile(t, minimalProd+"access:\n  wait_timeout_max: 1h\n  duration_presets: [1h, 5m]\nrecording:\n  flush_interval: 2s\n"), nil)
	ps := problems(t, err)
	for _, want := range []string{"access.wait_timeout_max", "ascending", "recording.flush_interval"} {
		if !hasProblem(ps, want) {
			t.Errorf("missing problem %q in %v", want, ps)
		}
	}
}

func TestEnvKeysCoverConfig(t *testing.T) {
	keys := EnvKeys()
	for _, want := range []string{"HALLPASS_MODE", "HALLPASS_DATA_DIR", "HALLPASS_KEK_FILE", "HALLPASS_SSH_LISTEN", "HALLPASS_DEV_AUTH"} {
		if !slices.Contains(keys, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestIsWithin(t *testing.T) {
	if !isWithin("/a/b/c", "/a/b") || isWithin("/a/bc", "/a/b") || isWithin("/x", "/a") {
		t.Fatal("isWithin broken")
	}
}

func TestAgentSSHAddress(t *testing.T) {
	for _, tc := range []struct {
		public, listen, addr string
		host                 string
		port                 int
	}{
		{"https://hallpass.example.com", ":2222", "", "hallpass.example.com", 2222},
		{"https://hallpass.example.com:8443", "0.0.0.0:22", "", "hallpass.example.com", 22},
		{"https://hallpass.example.com", ":2222", "ssh.example.com", "ssh.example.com", 22},
		{"https://hallpass.example.com", ":2222", "ssh.example.com:2200", "ssh.example.com", 2200},
		{"https://hallpass.example.com", ":2222", "[2001:db8::1]:22", "2001:db8::1", 22},
	} {
		c := Default()
		c.PublicURL, c.SSH.Listen, c.SSH.PublicAddress = tc.public, tc.listen, tc.addr
		if h, p := c.AgentSSHAddress(); h != tc.host || p != tc.port {
			t.Errorf("%+v: got %s %d", tc, h, p)
		}
	}
	for _, bad := range []string{"host:0", "host:99999", "user@host", ":22", "a/b"} {
		c := Default()
		c.Mode, c.PublicURL, c.KEK.File, c.SSH.PublicAddress = ModeDevelopment, "http://localhost:8080", "", bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ssh.public_address") {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

func TestPulseEvents(t *testing.T) {
	ok := minimalProd + "events:\n  pulse:\n    enabled: true\n    url: tls://events.example.com:4222\n    creds_file: /etc/hallpass/pulse.creds\n"
	cfg, err := Load(writeFile(t, ok), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Events.Pulse; !p.Enabled || p.Source != "hallpass" {
		t.Fatalf("pulse config %+v", p)
	}
	cases := map[string]struct{ content, problem string }{
		"plain nats in production": {minimalProd + "events:\n  pulse:\n    enabled: true\n    url: nats://events.example.com:4222\n    creds_file: /c\n", "must use tls://"},
		"not a nats url":           {minimalProd + "events:\n  pulse:\n    enabled: true\n    url: https://events.example.com\n    creds_file: /c\n", "tls:// or nats://"},
		"no creds":                 {minimalProd + "events:\n  pulse:\n    enabled: true\n    url: tls://events.example.com:4222\n", "creds_file is required"},
		"empty source":             {ok + "    source: \" \"\n", "source must not be empty"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeFile(t, c.content), nil)
			if ps := problems(t, err); !hasProblem(ps, c.problem) {
				t.Fatalf("problems %v, want %q", ps, c.problem)
			}
		})
	}
	dev := "mode: development\npublic_url: http://localhost:8080\nkek:\n  file: \"\"\nevents:\n  pulse:\n    enabled: true\n    url: nats://127.0.0.1:4222\n    creds_file: /c\n"
	if _, err := Load(writeFile(t, dev), nil); err != nil {
		t.Fatalf("development allows nats://: %v", err)
	}
	if _, err := Load(writeFile(t, minimalProd+"events:\n  pulse:\n    url: nats://x\n"), nil); err != nil {
		t.Fatalf("disabled pulse is not validated: %v", err)
	}
}

func TestThinPushBasesDefaults(t *testing.T) {
	cfg, err := Load(writeFile(t, minimalProd), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := ThinPushBasesConfig{Enabled: true, MaxBases: 256, MaxFetchBytes: 8 << 20, Timeout: Duration(20 * time.Second), MaxConcurrent: 4, MaxConcurrentPerAgent: 1}
	if got := cfg.Git.ThinPushBases; got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
}

func TestThinPushBasesYAML(t *testing.T) {
	cfg, err := Load(writeFile(t, minimalProd+"git:\n  thin_push_bases:\n    enabled: false\n    max_bases: 16\n    max_fetch_bytes: 1048576\n    timeout: 45s\n    max_concurrent: 8\n    max_concurrent_per_agent: 2\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Git.ThinPushBases
	if got.Enabled || got.MaxBases != 16 || got.MaxFetchBytes != 1<<20 || got.Timeout.D() != 45*time.Second ||
		got.MaxConcurrent != 8 || got.MaxConcurrentPerAgent != 2 {
		t.Fatalf("yaml not applied: %+v", got)
	}
	if _, err := Load(writeFile(t, minimalProd+"git:\n  thin_push_bases:\n    enable: true\n"), nil); err == nil {
		t.Fatal("unknown key under git.thin_push_bases must be rejected")
	}
}

func TestThinPushBasesBounds(t *testing.T) {
	ok := func(field, value string) string {
		return minimalProd + "git:\n  thin_push_bases:\n    " + field + ": " + value + "\n"
	}
	// Each bound is checked at both ends: the value just inside is accepted, the value just outside is refused.
	cases := []struct {
		name, content, problem string
		valid                  bool
	}{
		{"max_bases 0", ok("max_bases", "0"), "git.thin_push_bases.max_bases must be within 1..256, got 0", false},
		{"max_bases 257", ok("max_bases", "257"), "git.thin_push_bases.max_bases must be within 1..256, got 257", false},
		{"max_bases 1", ok("max_bases", "1"), "", true},
		{"max_bases 256", ok("max_bases", "256"), "", true},
		{"max_fetch_bytes below", ok("max_fetch_bytes", "65535"), "max_fetch_bytes must be within 65536..67108864", false},
		{"max_fetch_bytes above", ok("max_fetch_bytes", "67108865"), "max_fetch_bytes must be within 65536..67108864", false},
		{"max_fetch_bytes min", ok("max_fetch_bytes", "65536"), "", true},
		{"max_fetch_bytes max", ok("max_fetch_bytes", "67108864"), "", true},
		{"timeout below", ok("timeout", "500ms"), "git.thin_push_bases.timeout must be within 1s..2m0s", false},
		{"timeout above", ok("timeout", "121s"), "git.thin_push_bases.timeout must be within 1s..2m0s", false},
		{"timeout min", ok("timeout", "1s"), "", true},
		{"timeout max", ok("timeout", "120s"), "", true},
		{"max_concurrent 0", ok("max_concurrent", "0"), "git.thin_push_bases.max_concurrent must be within 1..64, got 0", false},
		{"max_concurrent 65", ok("max_concurrent", "65"), "git.thin_push_bases.max_concurrent must be within 1..64, got 65", false},
		{"max_concurrent 1", minimalProd + "git:\n  thin_push_bases:\n    max_concurrent: 1\n    max_concurrent_per_agent: 1\n", "", true},
		{"max_concurrent 64", ok("max_concurrent", "64"), "", true},
		{"max_concurrent_per_agent 0", ok("max_concurrent_per_agent", "0"), "max_concurrent_per_agent must be within 1..4, got 0", false},
		{"max_concurrent_per_agent 5", ok("max_concurrent_per_agent", "5"), "max_concurrent_per_agent must be within 1..4, got 5", false},
		{"max_concurrent_per_agent 4", minimalProd + "git:\n  thin_push_bases:\n    max_concurrent: 4\n    max_concurrent_per_agent: 4\n", "", true},
		{"per agent above global", minimalProd + "git:\n  thin_push_bases:\n    max_concurrent: 1\n    max_concurrent_per_agent: 2\n", "must not exceed git.thin_push_bases.max_concurrent", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeFile(t, c.content), nil)
			if c.valid {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if ps := problems(t, err); !hasProblem(ps, c.problem) {
				t.Fatalf("problems %v, want %q", ps, c.problem)
			}
		})
	}
}

func TestThinPushBasesValidatedWhileDisabled(t *testing.T) {
	// Bounds are checked even with the switch off, so a later enable cannot start from an invalid value.
	content := minimalProd + "git:\n  thin_push_bases:\n    enabled: false\n    max_bases: 0\n"
	if _, err := Load(writeFile(t, content), nil); !hasProblem(problems(t, err), "max_bases") {
		t.Fatalf("expected max_bases problem, got %v", err)
	}
}

func TestThinPushBasesEnvOverrides(t *testing.T) {
	env := []string{
		"HALLPASS_GIT_THIN_PUSH_BASES_ENABLED=false",
		"HALLPASS_GIT_THIN_PUSH_BASES_MAX_BASES=12",
		"HALLPASS_GIT_THIN_PUSH_BASES_MAX_FETCH_BYTES=1048576",
		"HALLPASS_GIT_THIN_PUSH_BASES_TIMEOUT=45s",
		"HALLPASS_GIT_THIN_PUSH_BASES_MAX_CONCURRENT=8",
		"HALLPASS_GIT_THIN_PUSH_BASES_MAX_CONCURRENT_PER_AGENT=2",
	}
	cfg, err := Load(writeFile(t, minimalProd), env)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Git.ThinPushBases
	if got.Enabled || got.MaxBases != 12 || got.MaxFetchBytes != 1<<20 || got.Timeout.D() != 45*time.Second ||
		got.MaxConcurrent != 8 || got.MaxConcurrentPerAgent != 2 {
		t.Fatalf("overrides not applied: %+v", got)
	}
	if _, err := Load(writeFile(t, minimalProd), []string{"HALLPASS_GIT_THIN_PUSH_BASES_MAX_BASES=257"}); !hasProblem(problems(t, err), "max_bases") {
		t.Fatalf("env value 257 must be refused, got %v", err)
	}
	if _, err := Load(writeFile(t, minimalProd), []string{"HALLPASS_GIT_THIN_PUSH_BASES_ENABLED=maybe"}); err == nil {
		t.Fatal("expected parse error for a non-boolean enabled override")
	}
}
