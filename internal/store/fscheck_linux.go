//go:build linux

package store

import (
	"fmt"
	"syscall"
)

// Filesystem magic numbers (statfs f_type) for network or shared filesystems on which a writable SQLite
// database is unsupported (HP-DB-007).
var networkFS = map[int64]string{
	0x6969:     "nfs",
	0x517B:     "smb",
	0xFF534D42: "cifs",
	0xFE534D42: "smb2",
	0x65735546: "fuse",
	0x01021997: "9p",
	0x00C36400: "ceph",
	0x5346414F: "afs",
	0x73757245: "coda",
	0x01161970: "gfs2",
	0x7461636F: "ocfs2",
	0x47504653: "gpfs",
	0x013111A8: "ibrix",
	0x6B414653: "kafs",
	0x0BD00BD0: "lustre",
}

// CheckLocalFilesystem refuses data directories on network or shared filesystems.
func CheckLocalFilesystem(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", dir, err)
	}
	if name, bad := networkFS[int64(st.Type)]; bad { //nolint:unconvert // Type width differs by arch
		return fmt.Errorf("data directory %s is on a %s filesystem; a writable SQLite database requires local storage (HP-DB-007)", dir, name)
	}
	return nil
}
