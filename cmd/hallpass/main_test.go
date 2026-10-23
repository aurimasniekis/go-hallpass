package main

import (
	"bytes"
	"context"
	"encoding/json"
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
