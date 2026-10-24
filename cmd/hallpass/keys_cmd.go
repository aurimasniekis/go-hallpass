package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/app"

	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

func keysCommands() *command {
	return &command{
		name:    "keys",
		summary: "master key (KEK) and keyring management",
		sub: []*command{
			{name: "init-kek", summary: "generate a new master key file (0400)", run: runKeysInitKEK},
			{name: "status", summary: "show keyring status (offline; takes the data-directory lock)", run: runKeysStatus},
			{name: "rotate", summary: "rotate a purpose key (offline; takes the data-directory lock)", run: runKeysRotate},
			{name: "retire", summary: "retire an old purpose-key version once nothing uses it (offline; takes the data-directory lock)", run: runKeysRetire},
			{name: "rotate-kek", summary: "rewrap all keys under a new KEK (offline; back up first)", run: runKeysRotateKEK},
		},
	}
}

func runKeysInitKEK(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys init-kek", stderr)
	out := fs.String("out", "", "path of the new KEK file (must not exist)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return &exitError{code: 2, err: errors.New("--out is required")}
	}
	k, err := keyring.GenerateKEK()
	if err != nil {
		return err
	}
	if err := keyring.WriteKEKFile(*out, k); err != nil {
		return &exitError{code: 1, err: err}
	}
	_, err = fmt.Fprintf(stdout, "wrote KEK %s to %s (mode 0400)\nBack it up separately from data backups: without it, encrypted data is unrecoverable.\n",
		keyring.KEKID(k), *out)
	return err
}

// openKeyring opens the store (taking the lock) and loads the keyring with the configured KEK.
func openKeyring(ctx context.Context, cfg *config.Config) (*store.Store, *keyring.Keyring, *keyring.LocalKEK, error) {
	logger, _ := obs.NewLogger(os.Stderr, cfg.Log)
	w, err := keyring.LoadKEK(keyring.Source{
		Kind: cfg.KEK.Source, File: cfg.KEK.File, Production: cfg.IsProduction(), DataDir: cfg.DataDir, Environ: os.Environ(),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := store.Open(ctx, store.Options{
		DataDir: cfg.DataDir, AllowNetworkFS: cfg.Storage.AllowNetworkFS,
		PreMigrationSnapshots: cfg.Storage.PreMigrationSnapshots, Logger: logger,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	kr, err := keyring.Load(ctx, s, w)
	if err != nil {
		_ = s.Close()
		return nil, nil, nil, err
	}
	return s, kr, w, nil
}

func runKeysStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys status", stderr)
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	s, kr, _, err := openKeyring(ctx, cfg)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer s.Close()
	if *asJSON {
		return json.NewEncoder(stdout).Encode(map[string]any{"kek_id": kr.KEKID(), "purposes": kr.Status()})
	}
	fmt.Fprintf(stdout, "KEK id: %s\n", kr.KEKID())
	for _, st := range kr.Status() {
		fmt.Fprintf(stdout, "  %-10s active v%d, loaded versions %v\n", st.Purpose, st.ActiveVersion, st.Versions)
	}
	return nil
}

func runKeysRotate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys rotate", stderr)
	path := configFlag(fs)
	purpose := fs.String("purpose", "", "purpose to rotate: field, credential, recording, manifest, token")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	s, kr, _, err := openKeyring(ctx, cfg)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer s.Close()
	v, err := kr.Rotate(ctx, s, keyring.Purpose(*purpose))
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	_, err = fmt.Fprintf(stdout, "%s key rotated to v%d; existing data is re-encrypted in the background by the server\n", *purpose, v)
	return err
}

func runKeysRotateKEK(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys rotate-kek", stderr)
	path := configFlag(fs)
	newFile := fs.String("new", "", "path of the new KEK file (create it with `hallpass keys init-kek`)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *newFile == "" {
		return &exitError{code: 2, err: errors.New("--new is required")}
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	newW, err := keyring.LoadKEK(keyring.Source{Kind: "file", File: *newFile, Production: true})
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	s, _, oldW, err := openKeyring(ctx, cfg)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer s.Close()
	n, err := keyring.RotateKEK(ctx, s, oldW, newW)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	_, err = fmt.Fprintf(stdout, "rewrapped %d keys from KEK %s to %s\nUpdate kek.file to %s, take a backup, and keep the old KEK until backups made with it expire.\n",
		n, oldW.ID(), newW.ID(), *newFile)
	return err
}

func runKeysRetire(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys retire", stderr)
	path := configFlag(fs)
	purpose := fs.String("purpose", "", "purpose: field, credential, recording, token")
	version := fs.Uint("version", 0, "decrypt-only version to retire")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *purpose == "" || *version == 0 {
		return &exitError{code: 2, err: errors.New("--purpose and --version are required")}
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	s, kr, _, err := openKeyring(ctx, cfg)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer s.Close()
	if err := retireGuard(ctx, s, keyring.Purpose(*purpose), uint32(*version)); err != nil { //nolint:gosec // versions are small
		return &exitError{code: 1, err: err}
	}
	if err := kr.Retire(ctx, s, keyring.Purpose(*purpose), uint32(*version)); err != nil { //nolint:gosec // versions are small
		return &exitError{code: 1, err: err}
	}
	_, err = fmt.Fprintf(stdout, "%s key v%d retired\n", *purpose, *version)
	return err
}

// retireGuard refuses to retire a version that still protects data (HP-CRY-002): sealed columns, audit details (whose
// ciphertext the audit chain covers), live recording segments, token MACs that may still be presented, and the
// integrity-chain MAC key.
func retireGuard(ctx context.Context, s *store.Store, p keyring.Purpose, v uint32) error {
	switch p {
	case keyring.PurposeManifest:
		return errors.New("manifest keys authenticate the integrity chain and are never retired")
	case keyring.PurposeRecording:
		var n int
		if err := s.ReadDB().QueryRowContext(ctx, `SELECT count(*) FROM recording_segments WHERE key_id = ? AND state != 'deleted'`,
			fmt.Sprintf("recording:v%d", v)).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%d recording segments still use recording v%d (the server's recording.rewrap job moves them to the active key; "+
				"missing segments keep it until retention deletes them)", n, v)
		}
		return nil
	case keyring.PurposeToken:
		if err := tokenRetireGuard(ctx, s, v, time.Now()); err != nil {
			return err
		}
	}
	cols := append(app.SealedColumns(), keyring.FieldColumn("audit_events", "id", "details_enc", keyring.PurposeField),
		// Short-lived OIDC PKCE verifiers are not re-sealed (they expire), but they must not lose their key early.
		keyring.Column{Table: "oidc_auth_states", IDColumn: "state_hash", BlobColumn: "verifier_enc", Purpose: keyring.PurposeToken})
	inUse, err := keyring.VersionInUse(ctx, s, cols, p, v)
	if err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("%s v%d still protects stored data; wait for background re-encryption (audit details keep their version)", p, v)
	}
	return nil
}

// tokenRetireGuard refuses to retire token key version v while a value MAC'd with it may still be presented (SR-36):
// an unused recovery code, or an unused and unexpired one-time token, chat link code or approval action token created
// before v+1 became active. A MAC does not record its key version, so creation time is the only evidence; after
// retirement such values would silently stop working.
func tokenRetireGuard(ctx context.Context, s *store.Store, v uint32, now time.Time) error {
	var supersededAt int64
	err := s.ReadDB().QueryRowContext(ctx, `SELECT created_at FROM keyring_keys WHERE purpose = 'token' AND version = ?`, int64(v)+1).Scan(&supersededAt)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("token v%d is the newest version", v)
	}
	if err != nil {
		return err
	}
	nowUs := now.UnixMicro()
	for _, c := range []struct{ what, q string }{
		{"unused recovery codes", `SELECT count(*) FROM recovery_codes WHERE used_at IS NULL AND created_at < ?1`},
		{"pending invitation, reset or setup tokens", `SELECT count(*) FROM one_time_tokens WHERE used_at IS NULL AND created_at < ?1 AND expires_at > ?2`},
		{"pending chat link codes", `SELECT count(*) FROM provider_link_codes WHERE used_at IS NULL AND created_at < ?1 AND expires_at > ?2`},
		{"pending approval action tokens", `SELECT count(*) FROM action_tokens WHERE used_at IS NULL AND created_at < ?1 AND expires_at > ?2`},
	} {
		var n int
		if err := s.ReadDB().QueryRowContext(ctx, c.q, supersededAt, nowUs).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("token v%d may still verify %d %s; wait until they are used or expire, or regenerate recovery codes", v, n, c.what)
		}
	}
	return nil
}
