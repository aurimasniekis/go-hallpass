//go:build unix

package store

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// ErrLocked means another process owns the data directory (HP-DB-006).
var ErrLocked = errors.New("another hallpass process owns this data directory")

// Lock is an exclusive advisory lock (flock) held for the life of the process.
type Lock struct{ f *os.File }

// AcquireLock takes a non-blocking exclusive flock on path, writing the PID for diagnostics.
func AcquireLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // path inside the data dir
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // fd fits int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s)", ErrLocked, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return &Lock{f: f}, nil
}

// Release unlocks and closes the lock file.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) //nolint:gosec // fd fits int
	err := l.f.Close()
	l.f = nil
	return err
}
