// Package fsstat reports filesystem capacity for disk-space readiness checks and metrics (HP-OPS-006).
package fsstat

import (
	"errors"
	"fmt"
)

// ErrUnsupported is returned on platforms without a statfs implementation.
var ErrUnsupported = errors.New("filesystem statistics are not supported on this platform")

// Usage is the capacity of the filesystem holding a path.
type Usage struct {
	// Total is the filesystem size in bytes.
	Total uint64
	// Avail is the space available to the (unprivileged) process in bytes.
	Avail uint64
}

// UsedPercent returns the used share of the filesystem as seen by the process (0..100).
func (u Usage) UsedPercent() float64 {
	if u.Total == 0 {
		return 0
	}
	used := float64(u.Total) - float64(u.Avail)
	if used < 0 {
		return 0
	}
	return used / float64(u.Total) * 100
}

// Reserve is the free-space reserve: the larger of minFreeBytes and minFreePercent of Total, so the reserve is
// breached when free space falls below either threshold (fail closed). Non-positive thresholds are ignored.
func (u Usage) Reserve(minFreeBytes int64, minFreePercent int) uint64 {
	var r uint64
	if minFreeBytes > 0 {
		r = uint64(minFreeBytes)
	}
	if minFreePercent > 0 {
		if p := u.Total / 100 * uint64(minFreePercent); p > r {
			r = p
		}
	}
	return r
}

// BelowReserve reports whether available space is below the reserve.
func (u Usage) BelowReserve(minFreeBytes int64, minFreePercent int) bool {
	return u.Avail < u.Reserve(minFreeBytes, minFreePercent)
}

// Stat returns the capacity of the filesystem containing path.
func Stat(path string) (Usage, error) { return stat(path) }

// ErrBelowReserve reports free space below the configured reserve (HP-OPS-006).
var ErrBelowReserve = errors.New("free space below the storage reserve")

// ReserveCheck returns a check for access.Options.StorageReserve: it fails with ErrBelowReserve when the filesystem
// holding path has less free space than the reserve, and with the stat error when the filesystem cannot be read
// (fail closed).
func ReserveCheck(path string, minFreeBytes int64, minFreePercent int) func() error {
	return func() error {
		u, err := Stat(path)
		if err != nil {
			return err
		}
		if u.BelowReserve(minFreeBytes, minFreePercent) {
			return fmt.Errorf("%w: %d bytes available, reserve %d bytes", ErrBelowReserve, u.Avail, u.Reserve(minFreeBytes, minFreePercent))
		}
		return nil
	}
}
