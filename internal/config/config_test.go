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
