//go:build !linux && !darwin

package store

// CheckLocalFilesystem cannot detect network filesystems on this platform; deployments are Linux (A-5).
func CheckLocalFilesystem(string) error { return nil }
