package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/backup"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

func backupCommands() *command {
	return &command{
		name:    "backup",
		summary: "create or verify consistent backups (online; safe while the server runs)",
		sub: []*command{
			{name: "create", summary: "write a backup (database snapshot, recording segments, manifest) to a new directory", run: runBackupCreate},
			{name: "verify", summary: "check a backup directory (hashes, database integrity, segments) without restoring it", run: runBackupVerify},
			{name: "remote-list", summary: "list the backups the server stored in object storage", run: runBackupRemoteList},
			{name: "remote-download", summary: "download a remote backup into a backup directory for verify and restore (needs the KEK)", run: runBackupRemoteDownload},
		},
	}
}

func restoreCommand() *command {
	return &command{name: "restore", summary: "restore a backup into an empty data directory (offline; takes the data-directory lock; needs the KEK)", run: runRestore}
}

// parsePositional parses flags that may appear before or after exactly n positional arguments.
func parsePositional(fs *flag.FlagSet, args []string, n int, usage string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errHelp
			}
			return nil, &exitError{code: 2, err: err}
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != n {
		return nil, &exitError{code: 2, err: fmt.Errorf("usage: %s", usage)}
	}
	return pos, nil
}

func runBackupCreate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup create", stderr)
	path := configFlag(fs)
	out := fs.String("out", "", "new directory to write the backup to (must not exist; use a separate volume)")
	asJSON := fs.Bool("json", false, "print the manifest as JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return &exitError{code: 2, err: errors.New("--out is required")}
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	src, err := backup.OpenReadOnly(ctx, cfg.DataDir)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer src.Close()
	res, err := backup.Create(ctx, src, *out, backup.Options{})
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	m := res.Manifest
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(m); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(stdout, "backup written to %s\n", res.Dir)
		fmt.Fprintf(stdout, "  schema version %d, %d files, %d bytes\n", m.SchemaVersion, len(m.Files), res.Bytes)
		fmt.Fprintf(stdout, "  segments: %d copied (%d open at snapshot), %d without a file by design, %d missing\n",
			m.Segments.Copied, m.Segments.OpenAtSnapshot, m.Segments.Skipped, len(m.Segments.Missing))
		fmt.Fprintf(stdout, "  integrity chain head: seq %d %s\n", m.ChainHead.Seq, m.ChainHead.Hash)
		fmt.Fprintf(stdout, "  kek_id %s: the KEK is NOT in this backup; keep it backed up separately (losing it loses the data)\n", m.KEKID)
	}
	for _, w := range m.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	for _, p := range res.Problems {
		fmt.Fprintf(stderr, "problem: %s\n", p)
	}
	if len(res.Problems) > 0 {
		return &exitError{code: 3, err: errors.New("backup written, but some segment files did not match the database (see hallpass verify)")}
	}
	return nil
}

func runBackupVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup verify", stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parsePositional(fs, args, 1, "hallpass backup verify [--json] DIR")
	if err != nil {
		return err
	}
	rep, verr := backup.Verify(ctx, pos[0])
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(rep); err != nil {
			return err
		}
	} else {
		printVerifyReport(stdout, rep)
	}
	if verr != nil {
		return &exitError{code: 3, err: verr}
	}
	return nil
}

func printVerifyReport(w io.Writer, rep *backup.Report) {
	if m := rep.Manifest; m != nil {
		fmt.Fprintf(w, "backup created %s by hallpass %s, schema %d (binary supports %d), kek_id %s\n",
			m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), m.HallpassVersion, m.SchemaVersion, rep.BinarySchema, m.KEKID)
		fmt.Fprintf(w, "integrity chain: %d entries link correctly, head seq %d %s\n", rep.ChainLength, m.ChainHead.Seq, m.ChainHead.Hash)
	}
	fmt.Fprintf(w, "files: %d verified, %d bytes\n", rep.Files, rep.Bytes)
	for _, s := range rep.Warnings {
		fmt.Fprintf(w, "warning: %s\n", s)
	}
	for _, s := range rep.Problems {
		fmt.Fprintf(w, "PROBLEM: %s\n", s)
	}
	if rep.OK {
		fmt.Fprintln(w, "backup: ok")
	} else {
		fmt.Fprintln(w, "backup: FAILED")
	}
}

func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("restore", stderr)
	path := configFlag(fs)
	data := fs.String("data", "", "data directory to restore into (default: data_dir from the configuration)")
	force := fs.Bool("force", false, "move existing data in the target aside (to backups/pre-restore-*) instead of refusing")
	pos, err := parsePositional(fs, args, 1, "hallpass restore [--config FILE] [--data DIR] [--force] BACKUP_DIR")
	if err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	if *data != "" {
		cfg.DataDir = *data
	}
	if cfg.KEK.Source != "env" && cfg.KEK.File == "" {
		return &exitError{code: 1, err: errors.New("restore needs the KEK the backup was made with: set kek.file (or kek.source=env with HALLPASS_KEK); " +
			"a development KEK inside the data directory is never part of a backup")}
	}
	kek, err := keyring.LoadKEK(keyring.Source{Kind: cfg.KEK.Source, File: cfg.KEK.File, Production: true, Environ: os.Environ()})
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	res, err := backup.Restore(ctx, pos[0], cfg.DataDir, backup.RestoreOptions{Force: *force, KEKID: kek.ID(), AllowNetworkFS: cfg.Storage.AllowNetworkFS})
	if err != nil {
		code := 1
		if errors.Is(err, backup.ErrInvalid) {
			code = 3
		}
		return &exitError{code: code, err: err}
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	// Prove that the supplied KEK unlocks the restored keyring (canary check) before telling the operator to start.
	if err := checkRestoredKeyring(ctx, cfg.DataDir, cfg.Storage.AllowNetworkFS, kek); err != nil {
		return &exitError{code: 1, err: fmt.Errorf("restored into %s, but the KEK does not unlock it: %w", res.DataDir, err)}
	}
	m := res.Manifest
	fmt.Fprintf(stdout, "restored %d files (%d bytes) from %s into %s\n", res.Files, res.Bytes, pos[0], res.DataDir)
	fmt.Fprintf(stdout, "  backup created %s, schema %d, chain head seq %d %s, KEK %s unlocks the keyring\n",
		m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), m.SchemaVersion, m.ChainHead.Seq, m.ChainHead.Hash, kek.ID())
	if res.MovedAside != "" {
		fmt.Fprintf(stdout, "  previous data moved to %s\n", res.MovedAside)
	}
	next := []string{"hallpass verify" + configArg(*path)}
	if m.Segments.OpenAtSnapshot > 0 {
		next = append(next, fmt.Sprintf("start hallpass serve; startup reconciliation marks the %d segment(s) open at snapshot time as interrupted", m.Segments.OpenAtSnapshot))
	} else {
		next = append(next, "start hallpass serve")
	}
	next = append(next, "compare the chain head with your external anchors (hallpass anchors verify FILE)")
	fmt.Fprintf(stdout, "next: %s\n", strings.Join(next, "; then "))
	return nil
}

func configArg(path string) string {
	if path == "" {
		return ""
	}
	return " --config " + path
}

func checkRestoredKeyring(ctx context.Context, dataDir string, allowNetFS bool, kek keyring.KeyWrapper) error {
	s, err := store.Open(ctx, store.Options{DataDir: dataDir, AllowNetworkFS: allowNetFS, SkipMigrate: true, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = keyring.Load(ctx, s, kek)
	return err
}
