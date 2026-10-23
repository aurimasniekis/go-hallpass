package chat

import (
	"errors"
	"fmt"
	"time"
)

// ErrPermanent marks an outbound failure that must not be retried (invalid destination, revoked token, rejected
// payload). The core maps it to outbox.ErrPermanent.
var ErrPermanent = errors.New("chat: permanent delivery failure")

// ErrRateLimited marks a provider rate-limit response. It is retryable; see RetryAfter.
var ErrRateLimited = errors.New("chat: rate limited")

// RateLimitError carries the provider-requested back-off.
type RateLimitError struct {
	Provider string
	Method   string
	After    time.Duration // zero if the provider did not say
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s: %s: rate limited, retry after %s", e.Provider, e.Method, e.After)
}

func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// RetryAfter returns the provider-requested back-off of a rate-limit error.
func RetryAfter(err error) (time.Duration, bool) {
	if rl, ok := errors.AsType[*RateLimitError](err); ok {
		return rl.After, true
	}
	return 0, false
}

// IsPermanent reports whether err must not be retried.
func IsPermanent(err error) bool { return errors.Is(err, ErrPermanent) }
