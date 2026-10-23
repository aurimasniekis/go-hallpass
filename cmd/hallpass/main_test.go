package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "hallpass ") {
		t.Fatalf("unexpected output %q", out.String())
	}
}

func TestVersionJSON(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"version", "--json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v["version"] == "" {
		t.Fatal("missing version")
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"nope"}, &out, &errb); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestConfigCheckExample(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"config", "check", "--config", "../../deploy/examples/hallpass.example.yaml"}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "configuration ok") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
}

func TestConfigCheckInvalid(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"config", "check", "--config", "/nonexistent.yaml"}, &out, &errb); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

func TestMigrateCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "hp.yaml")
	content := "mode: development\npublic_url: http://localhost:8080\nkek:\n  file: \"\"\ndata_dir: " + filepath.Join(dir, "data") + "\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"migrate", "--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "database schema at version") {
		t.Fatalf("unexpected output %q", out.String())
	}
}

func TestKeysLifecycle(t *testing.T) {
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	kek2 := filepath.Join(dir, "kek2")
	ctx := context.Background()
	var out, errb bytes.Buffer
	for _, p := range []string{kek, kek2} {
		if code := run(ctx, []string{"keys", "init-kek", "--out", p}, &out, &errb); code != 0 {
			t.Fatalf("init-kek exit %d: %s", code, errb.String())
		}
	}
	cfg := filepath.Join(dir, "hp.yaml")
	write := func(k string) {
		content := "public_url: https://hp.example.com\nkek:\n  file: " + k + "\ndata_dir: " + filepath.Join(dir, "data") + "\n"
		if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(kek)
	for _, args := range [][]string{
		{"keys", "status", "--config", cfg},
		{"keys", "rotate", "--config", cfg, "--purpose", "field"},
		{"keys", "rotate-kek", "--config", cfg, "--new", kek2},
	} {
		out.Reset()
		errb.Reset()
		if code := run(ctx, args, &out, &errb); code != 0 {
			t.Fatalf("%v exit %d: %s", args, code, errb.String())
		}
	}
	if code := run(ctx, []string{"keys", "status", "--config", cfg}, &out, &errb); code != 1 {
		t.Fatalf("old KEK should be rejected after rotation, exit %d", code)
	}
	write(kek2)
	out.Reset()
	if code := run(ctx, []string{"keys", "status", "--config", cfg, "--json"}, &out, &errb); code != 0 || !strings.Contains(out.String(), `"active_version":2`) {
		t.Fatalf("status with new KEK: exit %d %s %s", code, out.String(), errb.String())
	}
}
