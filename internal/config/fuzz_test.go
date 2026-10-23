package config

import (
	"bytes"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// HP-TST-002, HP-OPS-005: the config loader never panics on hostile YAML or environment overrides, and a production
// configuration that validates never carries development-only settings or an in-data-dir KEK.
func FuzzConfigLoad(f *testing.F) {
	keys := EnvKeys()
	seeds := []string{
		"",
		"mode: production\npublic_url: https://hallpass.example\ndata_dir: /var/lib/hallpass\nkek:\n  file: /etc/hallpass/kek\n",
		"mode: development\npublic_url: http://localhost:8080\ndata_dir: /tmp/hp\nkek:\n  file: ''\ndev:\n  auth: true\n",
		"mode: production\npublic_url: https://h.example\ndata_dir: /d\nkek:\n  file: /d/../d/kek\n",
		"mode: production\npublic_url: https://h.example\ndata_dir: /d\nkek: {source: env}\nstorage: {allow_network_fs: true}\n",
		"ssh:\n  idle_timeout: 1ns\n",
		"bogus: 1\n",
		"a: &a [*a, *a]\n",
		"---\n---\n",
		"recording:\n  flush_interval: 1h\n",
	}
	for i, s := range seeds {
		f.Add([]byte(s), uint16(i), "x")
	}
	f.Add([]byte(seeds[1]), uint16(0), "true")
	f.Fuzz(func(t *testing.T, data []byte, envIdx uint16, envVal string) {
		cfg := Default()
		if err := decode(bytes.NewReader(data), cfg); err != nil {
			return
		}
		environ := []string{keys[int(envIdx)%len(keys)] + "=" + envVal}
		if err := applyEnv(cfg, environ); err != nil {
			return
		}
		if cfg.Validate() != nil {
			return
		}
		if cfg.Mode != ModeProduction && cfg.Mode != ModeDevelopment {
			t.Fatalf("invalid mode %q validated", cfg.Mode)
		}
		if !filepath.IsAbs(cfg.DataDir) {
			t.Fatalf("relative data_dir %q validated", cfg.DataDir)
		}
		if fi := cfg.Recording.FlushInterval.D(); fi <= 0 || fi > 250*time.Millisecond {
			t.Fatalf("flush interval %s validated (HP-REC-008 bound)", fi)
		}
		if !cfg.IsProduction() {
			return
		}
		if cfg.Dev.Auth || cfg.Dev.InsecureHTTP || cfg.Dev.SeedFile != "" || cfg.Storage.AllowNetworkFS || cfg.Log.Format != "json" {
			t.Fatalf("development-only setting in a valid production config: %+v %+v", cfg.Dev, cfg.Storage)
		}
		u, err := url.Parse(cfg.PublicURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Fatalf("non-https public_url %q in production", cfg.PublicURL)
		}
		if cfg.KEK.Source == "file" {
			k, d := filepath.Clean(cfg.KEK.File), filepath.Clean(cfg.DataDir)
			if cfg.KEK.File == "" || !filepath.IsAbs(k) || k == d || strings.HasPrefix(k, strings.TrimSuffix(d, "/")+"/") {
				t.Fatalf("production KEK file %q validated with data_dir %q", cfg.KEK.File, cfg.DataDir)
			}
		}
	})
}
