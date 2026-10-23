package health

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/aurimasniekis/go-hallpass/internal/obs/fsstat"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Codes used by the built-in checks.
const (
	CodeStorageDegraded = "storage_degraded"
	CodeStorageFailed   = "storage_failed"
	CodeStorageBusy     = "storage_busy"
	CodeNotWritable     = "not_writable"
	CodeDiskFull        = "disk_full"
	CodeDiskReserve     = "disk_reserve"
	CodeDiskStat        = "disk_stat"
	CodeUnavailable     = "unavailable"
)

// StoreStatus reports storage health (implemented by *store.Health).
type StoreStatus interface {
	Status() store.HealthStatus
}

// StoreHealth maps the store's health tracker (HP-DB-009) to a check: degraded storage degrades readiness and
// failed storage (corruption, repeated I/O errors) fails it.
func StoreHealth(name string, h StoreStatus) Check {
	return Check{Name: name, Severity: Critical, Func: func(context.Context) error {
		st := h.Status()
		switch st.State {
		case store.HealthOK:
			return nil
		case store.HealthDegraded:
			return Degrade(CodeStorageDegraded, errors.New(st.Reason))
		default:
			return Fail(CodeStorageFailed, errors.New(st.Reason))
		}
	}}
}

// TxRunner runs a named write transaction (implemented by *store.Writer).
type TxRunner interface {
	TxNamed(ctx context.Context, name string, fn func(tx *store.Tx) error) error
}

// StoreWritable runs an empty BEGIN IMMEDIATE transaction on the writer: it proves the single writer can take
// the write lock within the check timeout. Busy degrades; other errors fail.
func StoreWritable(name string, w TxRunner) Check {
	return Check{Name: name, Severity: Critical, Func: func(ctx context.Context) error {
		err := w.TxNamed(ctx, "health.store_writable", func(*store.Tx) error { return nil })
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrBusy):
			return Degrade(CodeStorageBusy, err)
		case errors.Is(err, store.ErrFull):
			return Degrade(CodeDiskFull, err)
		case errors.Is(err, context.DeadlineExceeded):
			return Fail(CodeTimeout, err)
		default:
			return Fail(CodeNotWritable, err)
		}
	}}
}

// DirWritable creates, writes, fsyncs and removes a probe file in dir (e.g. the recording directory). A full
// disk degrades readiness; any other failure fails it.
func DirWritable(name, dir string) Check {
	return Check{Name: name, Severity: Critical, Func: func(context.Context) error {
		f, err := os.CreateTemp(dir, ".hallpass-ready-*")
		if err != nil {
			return writeErr(err)
		}
		path := f.Name()
		_, werr := f.Write([]byte("ok"))
		serr := f.Sync()
		cerr := f.Close()
		rerr := os.Remove(path)
		if err := errors.Join(werr, serr, cerr, rerr); err != nil {
			return writeErr(err)
		}
		return nil
	}}
}

func writeErr(err error) error {
	if errors.Is(err, syscall.ENOSPC) {
		return Degrade(CodeDiskFull, err)
	}
	return Fail(CodeNotWritable, err)
}

// DiskSpace degrades readiness when free space on the filesystem holding path is below the reserve: the larger
// of minFreeBytes and minFreePercent of the filesystem (config storage.min_free_bytes / min_free_percent,
// HP-OPS-006). Usage alerts at 80/90% are Prometheus rules on the filesystem metrics.
func DiskSpace(name, path string, minFreeBytes int64, minFreePercent int) Check {
	return Check{Name: name, Severity: Degrading, Func: func(context.Context) error {
		u, err := fsstat.Stat(path)
		if err != nil {
			return Degrade(CodeDiskStat, err)
		}
		if u.BelowReserve(minFreeBytes, minFreePercent) {
			return Degrade(CodeDiskReserve, fmt.Errorf("%d bytes available, reserve %d bytes",
				u.Avail, u.Reserve(minFreeBytes, minFreePercent)))
		}
		return nil
	}}
}

// Flag fails readiness with code when ok returns false (e.g. "keyring loaded", "ssh listener up").
func Flag(name, code string, ok func() bool) Check {
	return Check{Name: name, Severity: Critical, Func: func(context.Context) error {
		if ok() {
			return nil
		}
		return Fail(code, nil)
	}}
}
