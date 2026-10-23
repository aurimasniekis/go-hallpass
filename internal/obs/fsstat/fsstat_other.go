//go:build !linux && !darwin

package fsstat

func stat(string) (Usage, error) { return Usage{}, ErrUnsupported }
