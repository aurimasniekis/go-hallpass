package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/backup"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// opsEnv is a development configuration with a KEK file outside the data directory (generated at test time).
type opsEnv struct {
	t       *testing.T
	dir     string
	kek     string
	cfgPath string
	data    string
}

func newOpsEnv(t *testing.T) *opsEnv {
	t.Helper()
	e := &opsEnv{t: t, dir: t.TempDir()}
	k, err := keyring.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	e.kek = filepath.Join(e.dir, "kek")
	if err := keyring.WriteKEKFile(e.kek, k); err != nil {
		t.Fatal(err)
	}
	e.data = filepath.Join(e.dir, "data")
	e.cfgPath = e.writeConfig("hp.yaml", e.data, e.kek)
	return e
}

func (e *opsEnv) writeConfig(name, data, kek string) string {
	e.t.Helper()
	p := filepath.Join(e.dir, name)
	content := "mode: development\npublic_url: http://localhost:8080\nkek:\n  file: \"" + kek + "\"\ndata_dir: " + data + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

// call runs a subcommand function directly and returns stdout, stderr and the exit code it maps to.
func call(t *testing.T, fn func(ctx context.Context, args []string, stdout, stderr io.Writer) error, args ...string) (string, string, int, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := fn(context.Background(), args, &out, &errb)
	code := 0
	if err != nil {
		code = 1
		var ee *exitError
		if errors.As(err, &ee) {
			code = ee.code
		}
	}
	return out.String(), errb.String(), code, err
}

// seed initializes the data directory (keyring, host key) by opening the app once.
func (e *opsEnv) seed() {
	e.t.Helper()
	a, err := openApp(context.Background(), e.cfgPath)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		e.t.Fatal(err)
	}
}

// HP-OPS-003/004: backup create → backup verify → restore into a new directory → hallpass verify.
func TestBackupRestoreCommands(t *testing.T) {
	e := newOpsEnv(t)
	e.seed()
	out := filepath.Join(e.dir, "backup-1")

	if _, _, code, err := call(t, runBackupCreate, "--config", e.cfgPath); code != 2 {
		t.Fatalf("missing --out: %d %v", code, err)
	}
	stdout, stderr, code, err := call(t, runBackupCreate, "--config", e.cfgPath, "--out", out)
	if code != 0 || !strings.Contains(stdout, "KEK is NOT in this backup") {
		t.Fatalf("create: %d %v %q %q", code, err, stdout, stderr)
	}
	if _, _, code, _ := call(t, runBackupCreate, "--config", e.cfgPath, "--out", out); code != 1 {
		t.Fatalf("existing --out: %d", code)
	}
	stdout, _, code, err = call(t, runBackupVerify, out)
	if code != 0 || !strings.Contains(stdout, "backup: ok") {
		t.Fatalf("verify: %d %v %q", code, err, stdout)
	}
	stdout, _, code, _ = call(t, runBackupVerify, "--json", out)
	if code != 0 || !strings.Contains(stdout, `"ok":true`) {
		t.Fatalf("verify json: %d %q", code, stdout)
	}
	if _, _, code, _ := call(t, runBackupVerify); code != 2 {
		t.Fatalf("verify without DIR: %d", code)
	}

	// The configured data directory still holds data: refused.
	if _, _, code, err := call(t, runRestore, "--config", e.cfgPath, out); code != 1 || !errors.Is(err, backup.ErrNotEmpty) {
		t.Fatalf("restore over live data: %d %v", code, err)
	}
	// Flags may follow the positional argument.
	target := filepath.Join(e.dir, "restored")
	stdout, _, code, err = call(t, runRestore, "--config", e.cfgPath, out, "--data", target)
	if code != 0 || !strings.Contains(stdout, "unlocks the keyring") || !strings.Contains(stdout, "next: hallpass verify") {
		t.Fatalf("restore: %d %v %q", code, err, stdout)
	}
	cfg2 := e.writeConfig("hp2.yaml", target, e.kek)
	stdout, _, code, err = call(t, runVerify, "--config", cfg2)
	if code != 0 || !strings.Contains(stdout, "integrity chain: ok") {
		t.Fatalf("verify restored: %d %v %q", code, err, stdout)
	}
	// Forced restore moves the restored data aside.
	stdout, _, code, err = call(t, runRestore, "--force", "--config", cfg2, out)
	if code != 0 || !strings.Contains(stdout, "previous data moved to") {
		t.Fatalf("forced restore: %d %v %q", code, err, stdout)
	}

	// A tampered backup is refused with exit code 3.
	if err := os.WriteFile(filepath.Join(out, "extra"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if stdout, _, code, _ := call(t, runBackupVerify, out); code != 3 || !strings.Contains(stdout, "PROBLEM") {
		t.Fatalf("tampered verify: %d %q", code, stdout)
	}
	if _, _, code, _ := call(t, runRestore, "--config", e.cfgPath, "--data", filepath.Join(e.dir, "r3"), out); code != 3 {
		t.Fatalf("tampered restore: %d", code)
	}
}

// HP-CRY-007, ADR-0023: restore needs the KEK the backup was made with, supplied separately.
func TestRestoreRequiresMatchingKEK(t *testing.T) {
	e := newOpsEnv(t)
	e.seed()
	out := filepath.Join(e.dir, "b")
	if _, _, code, err := call(t, runBackupCreate, "--config", e.cfgPath, "--out", out); code != 0 {
		t.Fatal(err)
	}
	noKEK := e.writeConfig("nokek.yaml", filepath.Join(e.dir, "r1"), "")
	if _, _, code, err := call(t, runRestore, "--config", noKEK, out); code != 1 || !strings.Contains(err.Error(), "needs the KEK") {
		t.Fatalf("no KEK: %d %v", code, err)
	}
	other, err := keyring.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(e.dir, "other-kek")
	if err := keyring.WriteKEKFile(otherPath, other); err != nil {
		t.Fatal(err)
	}
	wrong := e.writeConfig("wrong.yaml", filepath.Join(e.dir, "r2"), otherPath)
	if _, _, code, err := call(t, runRestore, "--config", wrong, out); code != 1 || !errors.Is(err, backup.ErrKEKMismatch) {
		t.Fatalf("wrong KEK: %d %v", code, err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "r2", store.DBFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused restore wrote a database")
	}
}

// HP-CRY-008: anchors export and verify through the CLI.
func TestAnchorsCommands(t *testing.T) {
	e := newOpsEnv(t)
	e.seed()
	stdout, stderr, code, err := call(t, runAnchorsExport, "--config", e.cfgPath)
	if code != 0 || stdout != "" || !strings.Contains(stderr, "exported 0 anchors") {
		t.Fatalf("export: %d %v %q %q", code, err, stdout, stderr)
	}
	file := filepath.Join(e.dir, "anchors.jsonl")
	if _, _, code, err := call(t, runAnchorsExport, "--config", e.cfgPath, "--since", "0", "--out", file); code != 0 {
		t.Fatal(err)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("anchors file: %v %v", fi, err)
	}
	// An anchor for history that does not exist locally means history was removed.
	forged := filepath.Join(e.dir, "forged.jsonl")
	line := `{"seq":1,"hash":"` + strings.Repeat("ab", 32) + `","at":"2026-10-23T00:00:00Z"}` + "\n"
	if err := os.WriteFile(forged, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, code, _ = call(t, runAnchorsVerify, forged, "--config", e.cfgPath)
	if code != 3 || !strings.Contains(stdout, "not in the local chain") {
		t.Fatalf("verify: %d %q", code, stdout)
	}
	if stdout, _, code, _ := call(t, runAnchorsVerify, "--json", "--config", e.cfgPath, forged); code != 3 || !strings.Contains(stdout, `"ok":false`) {
		t.Fatalf("verify json: %d %q", code, stdout)
	}
	if _, _, code, _ := call(t, runAnchorsVerify, "--config", e.cfgPath, file); code != 1 {
		t.Fatalf("empty anchors file: %d", code)
	}
}

var tokenRE = regexp.MustCompile(`token: (\S+)`)

// HP-AUTH-001/016: bootstrap and break-glass recovery run offline with the lock and the KEK, and are audited.
func TestAdminCommands(t *testing.T) {
	e := newOpsEnv(t)
	ctx := context.Background()
	stdout, _, code, err := call(t, runAdminBootstrap, "--config", e.cfgPath)
	m := tokenRE.FindStringSubmatch(stdout)
	if code != 0 || m == nil || !strings.Contains(stdout, "http://localhost:8080/setup?token=") {
		t.Fatalf("bootstrap: %d %v %q", code, err, stdout)
	}
	a, err := openApp(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authService(a).Bootstrap(ctx, opauth.BootstrapInput{Token: m[1], Email: "Admin@Example.com", Password: "correct horse battery staple"}); err != nil {
		t.Fatal(err)
	}
	// While another process (here: this test) holds the lock, break-glass is refused.
	if _, _, code, err := call(t, runAdminRecover, "--config", e.cfgPath, "--email", "admin@example.com"); code != 1 || !errors.Is(err, store.ErrLocked) {
		t.Fatalf("recover with lock held: %d %v", code, err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, code, _ := call(t, runAdminBootstrap, "--config", e.cfgPath); code != 1 {
		t.Fatalf("second bootstrap: %d", code)
	}
	if _, _, code, _ := call(t, runAdminRecover, "--config", e.cfgPath); code != 2 {
		t.Fatalf("missing --email: %d", code)
	}
	if _, _, code, _ := call(t, runAdminRecover, "--config", e.cfgPath, "--email", "not-an-email"); code != 2 {
		t.Fatalf("invalid email: %d", code)
	}
	if _, _, code, err := call(t, runAdminRecover, "--config", e.cfgPath, "--email", "nobody@example.com"); code != 1 || !strings.Contains(err.Error(), "--new-admin") {
		t.Fatalf("unknown operator: %d %v", code, err)
	}
	stdout, _, code, err = call(t, runAdminRecover, "--config", e.cfgPath, "--email", "ADMIN@example.com")
	m = tokenRE.FindStringSubmatch(stdout)
	if code != 0 || m == nil || !strings.Contains(stdout, "BREAK-GLASS") || !strings.Contains(stdout, "/recover?token=") {
		t.Fatalf("recover: %d %v %q", code, err, stdout)
	}
	stdout, _, code, err = call(t, runAdminRecover, "--config", e.cfgPath, "--email", "second@example.com", "--new-admin")
	if code != 0 || !strings.Contains(stdout, "second@example.com") {
		t.Fatalf("recover new admin: %d %v %q", code, err, stdout)
	}

	a, err = openApp(ctx, e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var n int
	if err := a.Store.ReadDB().QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE action = 'breakglass.used' AND actor_type = 'cli'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("breakglass.used audit events: %d", n)
	}
	// The printed token is a working single-use recovery login.
	if _, err := authService(a).RecoveryLogin(ctx, m[1], opauth.SessionMeta{IP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := authService(a).RecoveryLogin(ctx, m[1], opauth.SessionMeta{IP: "127.0.0.1"}); err == nil {
		t.Fatal("recovery token reused")
	}
	var email sql.NullString
	if err := a.Store.ReadDB().QueryRowContext(ctx, "SELECT email FROM operators WHERE provisioned_via = 'recovery'").Scan(&email); err != nil || email.String != "second@example.com" {
		t.Fatalf("new admin: %v %v", email, err)
	}
}

// HP-AUTH-016: break-glass needs the KEK.
func TestAdminRecoverNeedsKEK(t *testing.T) {
	e := newOpsEnv(t)
	e.seed()
	missing := e.writeConfig("missing.yaml", e.data, filepath.Join(e.dir, "no-such-kek"))
	if _, _, code, err := call(t, runAdminRecover, "--config", missing, "--email", "admin@example.com", "--new-admin"); code != 1 || !errors.Is(err, keyring.ErrNoKEK) {
		t.Fatalf("missing KEK: %d %v", code, err)
	}
	other, err := keyring.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(e.dir, "other")
	if err := keyring.WriteKEKFile(otherPath, other); err != nil {
		t.Fatal(err)
	}
	wrong := e.writeConfig("wrong.yaml", e.data, otherPath)
	if _, _, code, err := call(t, runAdminRecover, "--config", wrong, "--email", "admin@example.com", "--new-admin"); code != 1 || !errors.Is(err, keyring.ErrWrongKEK) {
		t.Fatalf("wrong KEK: %d %v", code, err)
	}
}

// The WP23 command constructors dispatch to their subcommands (registered in rootCommands separately).
func TestOpsCommandTree(t *testing.T) {
	cmds := []*command{backupCommands(), restoreCommand(), anchorsCommands(), adminCommands()}
	want := map[string][]string{"backup": {"create", "verify"}, "restore": nil, "anchors": {"export", "verify"}, "admin": {"bootstrap", "recover"}}
	for _, c := range cmds {
		subs, ok := want[c.name]
		if !ok || c.summary == "" {
			t.Fatalf("unexpected command %q", c.name)
		}
		if len(c.sub) != len(subs) || (subs == nil) != (c.run != nil) {
			t.Fatalf("%s: unexpected shape", c.name)
		}
		for i, s := range c.sub {
			if s.name != subs[i] || s.run == nil || s.summary == "" {
				t.Fatalf("%s %s: unexpected subcommand", c.name, s.name)
			}
		}
	}
	var out, errb bytes.Buffer
	if err := cmds[0].sub[1].run(context.Background(), []string{filepath.Join(t.TempDir(), "none")}, &out, &errb); err == nil {
		t.Fatal("verify of a missing backup succeeded")
	}
	if !strings.Contains(out.String(), "backup: FAILED") {
		t.Fatalf("output %q", out.String())
	}
}
