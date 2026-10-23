package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Snapshot writes a consistent copy of the database to dest using VACUUM INTO (HP-DB-012). dest must not exist.
// The copy is fsynced together with its directory and has mode 0600. It is safe while the server is running.
func (s *Store) Snapshot(ctx context.Context, dest string) error {
	return snapshot(ctx, s.writer.Exec, dest)
}

func snapshot(ctx context.Context, exec func(context.Context, string, ...any) error, dest string) error {
	dest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("snapshot target %s already exists", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if strings.ContainsAny(dest, "'\x00") {
		return fmt.Errorf("snapshot path %q contains unsupported characters", dest)
	}
	if err := exec(ctx, "VACUUM INTO '"+dest+"'"); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("vacuum into %s: %w", dest, err)
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		return err
	}
	if err := fsyncFile(dest); err != nil {
		return err
	}
	return FsyncDir(filepath.Dir(dest))
}

func fsyncFile(path string) error {
	f, err := os.Open(path) //nolint:gosec // our own file
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// FsyncDir fsyncs a directory so that entries created or renamed in it are durable.
func FsyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // our own directory
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}

func statFile(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
