package main

import (
	"context"
	"io"
)

func serveCommand() *command {
	return &command{name: "serve", summary: "run the gateway (SSH front end, data plane, background workers)", run: runServe}
}

func runServe(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := newFlagSet("serve", stderr)
	path := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer a.Close()
	if err := a.Serve(ctx, nil); err != nil {
		return &exitError{code: 1, err: err}
	}
	return nil
}
