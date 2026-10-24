//go:build unix

package app

import "syscall"

// setUmask makes every file and directory HallPass creates private to its user (HP-DB-010).
func setUmask() { syscall.Umask(0o077) }
