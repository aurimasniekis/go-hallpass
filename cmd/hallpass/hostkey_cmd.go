package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
)

func hostkeyCommands() *command {
	return &command{
		name:    "hostkey",
		summary: "show or rotate the gateway SSH host key (offline; takes the data-directory lock)",
		sub: []*command{
			{name: "show", summary: "print gateway host key fingerprints and known_hosts lines", run: runHostkeyShow},
			{name: "stage", summary: "generate the next host key (different algorithm) to serve alongside the active one", run: runHostkeyStage},
			{name: "promote", summary: "make the staged host key active", run: runHostkeyPromote},
		},
	}
}

func openApp(ctx context.Context, path string) (*app.App, error) {
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, err
	}
	logger, _ := obs.NewLogger(os.Stderr, cfg.Log)
	return app.New(ctx, cfg, logger)
}

func runHostkeyShow(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("hostkey show", stderr)
	path := configFlag(fs)
	host := fs.String("host", "center", "host alias or name to use in the known_hosts lines")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer a.Close()
	keys, err := a.Credentials.GatewayHostKeys(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(stdout).Encode(keys)
	}
	for _, k := range keys {
		fmt.Fprintf(stdout, "%-8s %s %s\n  known_hosts: %s %s\n", k.State, k.Fingerprint, k.Algorithm, *host, k.PublicKey)
	}
	return nil
}

func runHostkeyStage(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("hostkey stage", stderr)
	path := configFlag(fs)
	alg := fs.String("algorithm", "ecdsa-sha2-nistp256", "algorithm of the new key (ssh-ed25519 or ecdsa-sha2-nistp256); must differ from the active key")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer a.Close()
	if err := a.Credentials.StageGatewayHostKey(ctx, audit.Actor{Type: audit.ActorCLI, ID: "hostkey"}, *alg); err != nil {
		return &exitError{code: 1, err: err}
	}
	_, err = fmt.Fprintln(stdout, "staged; distribute the new fingerprint (hallpass hostkey show) to agents before promoting")
	return err
}

func runHostkeyPromote(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("hostkey promote", stderr)
	path := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer a.Close()
	if err := a.Credentials.PromoteGatewayHostKey(ctx, audit.Actor{Type: audit.ActorCLI, ID: "hostkey"}); err != nil {
		return &exitError{code: 1, err: err}
	}
	_, err = fmt.Fprintln(stdout, "promoted; the previous key is no longer served")
	return err
}
