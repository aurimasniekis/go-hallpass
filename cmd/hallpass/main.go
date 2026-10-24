// Command hallpass is the HallPass SSH access gateway for AI agents.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// exitError carries a specific process exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := dispatch(ctx, args, stdout, stderr); err != nil {
		if errors.Is(err, errHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "hallpass: %v\n", err)
		var ee *exitError
		if errors.As(err, &ee) {
			return ee.code
		}
		return 1
	}
	return 0
}
