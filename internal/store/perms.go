package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// PrepareDataDir creates dir (0700) with its standard subdirectories, or verifies an existing one is owned by
// this user and not accessible to group or others (HP-DB-010).
func PrepareDataDir(dir string) error {
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create data dir: %w", err)
		}
		fi, err = os.Stat(dir)
		if err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("stat data dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("data dir %s is not a directory", dir)
	}
	if err := CheckPrivate(dir, fi); err != nil {
		return err
	}
	for _, sub := range []string{BackupsDir, RecordingsDir, QuarantineDir} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return fmt.Errorf("create %s: %w", sub, err)
		}
	}
	return nil
}

// CheckPrivate verifies that path is owned by the effective user and has no group/other permission bits.
func CheckPrivate(path string, fi os.FileInfo) error {
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; it must not be accessible by group or others (chmod 0700 for directories, 0600/0400 for files)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d but hallpass runs as uid %d", path, st.Uid, os.Geteuid())
	}
	return nil
}
