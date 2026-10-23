package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

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
