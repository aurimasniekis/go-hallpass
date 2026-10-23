//go:build darwin

package store

import (
	"fmt"
	"syscall"
)

var networkFS = map[string]bool{"nfs": true, "smbfs": true, "afpfs": true, "webdav": true, "cifs": true, "macfuse": true, "osxfuse": true}

// CheckLocalFilesystem refuses data directories on network or shared filesystems (HP-DB-007).
func CheckLocalFilesystem(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}
	var b []byte
	for _, c := range st.Fstypename {
		if c == 0 {
			break
		}
		b = append(b, byte(c)) //nolint:gosec // C char of a filesystem type name
	}
	if name := string(b); networkFS[name] {
		return fmt.Errorf("data directory %s is on a %s filesystem; a writable SQLite database requires local storage (HP-DB-007)", dir, name)
	}
	return nil
}
