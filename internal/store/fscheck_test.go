package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalFilesystemAccepted(t *testing.T) {
	if err := CheckLocalFilesystem(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

// HP-DB-007: set HALLPASS_TEST_NETFS_DIR to a directory on a network/FUSE filesystem (make test-netfs runs this in
// Docker, where the bind-mounted source tree is FUSE) to verify the refusal end to end.
func TestNetworkFilesystemRefused(t *testing.T) {
	base := os.Getenv("HALLPASS_TEST_NETFS_DIR")
	if base == "" {
		t.Skip("HALLPASS_TEST_NETFS_DIR not set")
	}
	dir, err := os.MkdirTemp(base, "netfs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = Open(context.Background(), Options{DataDir: filepath.Join(dir, "data")})
	if err == nil || !strings.Contains(err.Error(), "requires local storage") {
		t.Fatalf("expected network filesystem refusal, got %v", err)
	}
	s, err := Open(context.Background(), Options{DataDir: filepath.Join(dir, "data2"), AllowNetworkFS: true})
	if err != nil {
		t.Fatalf("override should allow opening: %v", err)
	}
	_ = s.Close()
}
