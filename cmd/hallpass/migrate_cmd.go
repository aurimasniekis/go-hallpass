package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

func runMigrate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("migrate", stderr)
	path := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	logger, _ := obs.NewLogger(os.Stderr, cfg.Log)
	s, err := store.Open(ctx, store.Options{
		DataDir:               cfg.DataDir,
		AllowNetworkFS:        cfg.Storage.AllowNetworkFS,
		PreMigrationSnapshots: cfg.Storage.PreMigrationSnapshots,
		Logger:                logger,
	})
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer s.Close()
	cur, latest, err := store.SchemaVersions(ctx, s.ReadDB(), store.EmbeddedMigrations())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "database schema at version %d (binary supports %d)\n", cur, latest)
	return err
}
