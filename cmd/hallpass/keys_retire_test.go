package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/app"
)

// HP-CRY-002: an old key version can be retired only after background re-encryption moved its data.
func TestKeysRetireGuard(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hp.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: development\npublic_url: http://localhost:8080\nkek:\n  file: \"\"\ndata_dir: "+filepath.Join(dir, "data")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	runOK := func(args ...string) string {
		t.Helper()
		var out, errb bytes.Buffer
		if code := run(ctx, append(args, "--config", cfgPath), &out, &errb); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errb.String())
		}
		return out.String()
	}
	runOK("migrate")
	runOK("hostkey", "show") // creates the gateway host key (credential-sealed, v1)
	runOK("keys", "rotate", "--purpose", "credential")
	var out, errb bytes.Buffer
	if code := run(ctx, []string{"keys", "retire", "--purpose", "credential", "--version", "1", "--config", cfgPath}, &out, &errb); code == 0 ||
		!strings.Contains(errb.String(), "still protects") {
		t.Fatalf("retire while in use: %d %s", code, errb.String())
	}
	if code := run(ctx, []string{"keys", "retire", "--purpose", "manifest", "--version", "1", "--config", cfgPath}, &out, &errb); code == 0 {
		t.Fatal("manifest key retired")
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(ctx, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Keyring.ResealColumns(ctx, a.Store, app.SealedColumns(), 1000); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	if got := runOK("keys", "retire", "--purpose", "credential", "--version", "1"); !strings.Contains(got, "retired") {
		t.Fatalf("retire: %s", got)
	}
}
