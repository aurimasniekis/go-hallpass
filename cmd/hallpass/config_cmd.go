package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/config"
)

func configCommands() *command {
	return &command{
		name:    "config",
		summary: "validate configuration and list environment overrides",
		sub: []*command{
			{name: "check", summary: "load and validate the configuration", run: runConfigCheck},
			{name: "env", summary: "list supported HALLPASS_* environment overrides", run: runConfigEnv},
		},
	}
}

// configFlag registers the shared --config flag (default from HALLPASS_CONFIG).
func configFlag(fs interface {
	String(name, value, usage string) *string
}) *string {
	return fs.String("config", os.Getenv("HALLPASS_CONFIG"), "path to the YAML configuration file (env HALLPASS_CONFIG)")
}

func loadConfig(path string) (*config.Config, error) {
	return config.Load(path, os.Environ())
}

func runConfigCheck(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("config check", stderr)
	path := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	_, err = fmt.Fprintf(stdout, "configuration ok (mode=%s, data_dir=%s)\n", cfg.Mode, cfg.DataDir)
	return err
}

func runConfigEnv(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("config env", stderr)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, strings.Join(config.EnvKeys(), "\n"))
	return err
}
