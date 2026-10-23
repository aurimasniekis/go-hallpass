package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aurimasniekis/go-hallpass/internal/backup"
)

func anchorsCommands() *command {
	return &command{
		name:    "anchors",
		summary: "export integrity-chain anchors for external append-only storage, or verify the chain against them",
		sub: []*command{
			{name: "export", summary: "print chain heads after --since as JSON lines (read-only; safe while the server runs)", run: runAnchorsExport},
			{name: "verify", summary: "compare previously exported anchors (FILE or - for stdin) with the local chain", run: runAnchorsVerify},
		},
	}
}

func runAnchorsExport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("anchors export", stderr)
	path := configFlag(fs)
	since := fs.Int64("since", 0, "export only entries with seq greater than this (the last seq you already shipped)")
	out := fs.String("out", "", "write to this new file (mode 0600) instead of stdout")
	if err := parseFlags(fs, args); err != nil {
		return err
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
	w := stdout
	var f *os.File
	if *out != "" {
		f, err = os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen output path
		if err != nil {
			return &exitError{code: 1, err: err}
		}
		w = f
	}
	n, err := backup.ExportAnchors(ctx, src.DB(), *since, w)
	if f != nil {
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	fmt.Fprintf(stderr, "exported %d anchors; ship them to append-only storage (object lock/WORM) now\n", n)
	return nil
}

func runAnchorsVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("anchors verify", stderr)
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parsePositional(fs, args, 1, "hallpass anchors verify [--config FILE] [--json] FILE|-")
	if err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	var in io.Reader = os.Stdin
	if pos[0] != "-" {
		f, err := os.Open(pos[0]) //nolint:gosec // G703: operator-supplied anchors file, read only
		if err != nil {
			return &exitError{code: 1, err: err}
		}
		defer f.Close()
		in = f
	}
	src, err := backup.OpenReadOnly(ctx, cfg.DataDir)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer src.Close()
	rep, err := backup.VerifyAnchors(ctx, src.DB(), in)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(rep); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(stdout, "anchors: %d checked, %d matched; latest anchor seq %d, local head seq %d\n",
			rep.Anchors, rep.Matched, rep.LastAnchorSeq, rep.LocalHeadSeq)
		for _, p := range rep.Problems {
			fmt.Fprintf(stdout, "PROBLEM: %s\n", p)
		}
		if rep.OK {
			fmt.Fprintf(stdout, "history up to seq %d matches the anchors; entries after it are not protected by them\n", rep.LastAnchorSeq)
		}
	}
	if !rep.OK {
		return &exitError{code: 3, err: errors.New("the local integrity chain does not match the anchors")}
	}
	return nil
}
