package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
)

// devApp writes a development config with its own data directory and opens the app on it.
func devApp(t *testing.T) (*app.App, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hp.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: development\npublic_url: http://localhost:8080\nkek:\n  file: \"\"\ndata_dir: "+filepath.Join(dir, "data")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(context.Background(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, cfgPath
}

func execNoFK(t *testing.T, a *app.App, q string, args ...any) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []struct {
		q    string
		args []any
	}{{"PRAGMA foreign_keys = OFF", nil}, {q, args}, {"PRAGMA foreign_keys = ON", nil}} {
		if err := a.Store.W().Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
}

// SR-37 (HP-CRY-002, HP-REC-012): sealed destination-audit exec details are re-sealed after a field-key rotation, and
// the old field key cannot be retired while they still use it.
func TestRetireGuardDestauditDetails(t *testing.T) {
	a, _ := devApp(t)
	ctx := context.Background()
	aad := keyring.FieldAAD("destaudit_records", "details_enc", "dar_test")
	sealed, err := a.Keyring.Seal(keyring.PurposeField, aad, []byte(`{"argv":["id"]}`))
	if err != nil {
		t.Fatal(err)
	}
	execNoFK(t, a, `INSERT INTO destaudit_records (id, collector_id, record_ref, batch_seq, access_session_id, timeline_event_id, correlation,
		confidence, after_session_end, reported_at, received_at, details_enc) VALUES ('dar_test', 'dac_x', 'r1', 1, 'ses_x', 'tle_x', 'x', 'high', 0, 1, 1, ?)`, sealed)
	if _, err := a.Keyring.Rotate(ctx, a.Store, keyring.PurposeField); err != nil {
		t.Fatal(err)
	}
	if err := retireGuard(ctx, a.Store, keyring.PurposeField, 1); err == nil || !strings.Contains(err.Error(), "still protects") {
		t.Fatalf("field v1 retirable while destination-audit details use it: %v", err)
	}
	if _, err := a.Keyring.ResealColumns(ctx, a.Store, app.SealedColumns(), 1000); err != nil {
		t.Fatal(err)
	}
	var got []byte
	if err := a.Store.ReadDB().QueryRowContext(ctx, `SELECT details_enc FROM destaudit_records WHERE id = 'dar_test'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if v, err := keyring.SealedVersion(got); err != nil || v != 2 {
		t.Fatalf("details not re-sealed: v%d %v", v, err)
	}
	if err := retireGuard(ctx, a.Store, keyring.PurposeField, 1); err != nil {
		t.Fatalf("after re-seal: %v", err)
	}
	if err := a.Keyring.Retire(ctx, a.Store, keyring.PurposeField, 1); err != nil {
		t.Fatal(err)
	}
	if pt, err := a.Keyring.Open(keyring.PurposeField, aad, got); err != nil || !strings.Contains(string(pt), "argv") {
		t.Fatalf("details unreadable after retirement: %v", err)
	}
}

// SR-36 (HP-CRY-002, HP-AUTH-007): a token key version cannot be retired while recovery codes or unexpired one-time
// tokens created under it may still be presented.
func TestRetireGuardTokenKey(t *testing.T) {
	a, _ := devApp(t)
	ctx := context.Background()
	now := time.Now().UnixMicro()
	execNoFK(t, a, `INSERT INTO recovery_codes (operator_id, code_hash, created_at) VALUES ('opr_x', x'01', ?)`, now)
	execNoFK(t, a, `INSERT INTO one_time_tokens (hash, kind, expires_at, created_at, created_by) VALUES (x'02', 'invite', ?, ?, 'cli')`,
		time.Now().Add(time.Hour).UnixMicro(), now)
	if err := retireGuard(ctx, a.Store, keyring.PurposeToken, 1); err == nil {
		t.Fatal("the active token key passed the guard")
	}
	time.Sleep(2 * time.Millisecond) // the rotation must be strictly later than the rows above
	if _, err := a.Keyring.Rotate(ctx, a.Store, keyring.PurposeToken); err != nil {
		t.Fatal(err)
	}
	if err := retireGuard(ctx, a.Store, keyring.PurposeToken, 1); err == nil || !strings.Contains(err.Error(), "recovery codes") {
		t.Fatalf("token v1 retirable with unused recovery codes: %v", err)
	}
	if err := a.Store.W().Exec(ctx, `UPDATE recovery_codes SET used_at = ?`, now); err != nil {
		t.Fatal(err)
	}
	if err := retireGuard(ctx, a.Store, keyring.PurposeToken, 1); err == nil || !strings.Contains(err.Error(), "invitation") {
		t.Fatalf("token v1 retirable with a pending invitation: %v", err)
	}
	if err := a.Store.W().Exec(ctx, `UPDATE one_time_tokens SET expires_at = ?`, now); err != nil {
		t.Fatal(err)
	}
	if err := retireGuard(ctx, a.Store, keyring.PurposeToken, 1); err != nil {
		t.Fatalf("after use and expiry: %v", err)
	}
}

// SR-02: `hallpass verify --adopt-chain-head` refuses an empty chain (and is otherwise covered by the recording tests).
func TestVerifyAdoptChainHeadEmpty(t *testing.T) {
	a, cfgPath := devApp(t)
	_ = a.Close()
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"verify", "--adopt-chain-head", "--config", cfgPath}, &out, &errb); code != 3 ||
		!strings.Contains(errb.String(), "empty") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
}
