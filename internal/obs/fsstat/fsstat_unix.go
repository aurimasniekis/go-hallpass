//go:build linux || darwin

package fsstat

import (
	"fmt"
	"syscall"
)

func stat(path string) (Usage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Usage{}, fmt.Errorf("statfs: %w", err)
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is a small positive value
	return Usage{Total: st.Blocks * bs, Avail: st.Bavail * bs}, nil
}
