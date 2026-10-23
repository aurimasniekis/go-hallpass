package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestRegisterResult(t *testing.T) {
	for err, want := range map[error]metrics.ChannelResult{
		access.ErrConcurrencyLimit:    metrics.ChannelLimited,
		access.ErrLockdown:            metrics.ChannelLockdown,
		access.ErrStorageUnavailable:  metrics.ChannelNoStorage,
		access.ErrAccessEnded:         metrics.ChannelDenied,
		access.ErrCapability:          metrics.ChannelDenied,
		access.ErrNotFoundOrForbidden: metrics.ChannelDenied,
		errors.New("db down"):         metrics.ChannelFailed,
	} {
		if got := registerResult(err); got != want {
			t.Errorf("registerResult(%v) = %s, want %s", err, got, want)
		}
	}
}

func TestDialResult(t *testing.T) {
	for err, want := range map[error]metrics.DialResult{
		nil:                                   metrics.DialOK,
		fmt.Errorf("x: %w", egress.ErrDenied): metrics.DialEgressDenied,
		fmt.Errorf("h: %w", context.DeadlineExceeded): metrics.DialTimeout,
		timeoutErr{}: metrics.DialTimeout,
		errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]"): metrics.DialAuthFailed,
		&inventory.HostKeyError{Reason: "mismatch"}:                                                          metrics.DialHostKey,
		errors.New("connection refused"):                                                                     metrics.DialError,
	} {
		if got := dialResult(err); got != want {
			t.Errorf("dialResult(%v) = %s, want %s", err, got, want)
		}
	}
}
