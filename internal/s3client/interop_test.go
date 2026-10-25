package s3client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/s3client"
)

// TestInterop runs against a real S3-compatible service when HALLPASS_TEST_S3_ENDPOINT is set (MinIO in CI, or AWS,
// R2 by hand): HALLPASS_TEST_S3_BUCKET, HALLPASS_TEST_S3_ACCESS_KEY, HALLPASS_TEST_S3_SECRET_KEY, and optionally
// HALLPASS_TEST_S3_REGION and HALLPASS_TEST_S3_PATH_STYLE=1. It proves the signatures are accepted by a real server.
func TestInterop(t *testing.T) {
	endpoint := os.Getenv("HALLPASS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("HALLPASS_TEST_S3_ENDPOINT not set")
	}
	c, err := s3client.New(s3client.Config{Endpoint: endpoint, Bucket: os.Getenv("HALLPASS_TEST_S3_BUCKET"),
		Region: os.Getenv("HALLPASS_TEST_S3_REGION"), PathStyle: os.Getenv("HALLPASS_TEST_S3_PATH_STYLE") == "1",
		AccessKeyID: os.Getenv("HALLPASS_TEST_S3_ACCESS_KEY"), SecretAccessKey: os.Getenv("HALLPASS_TEST_S3_SECRET_KEY"),
		AllowPrivateNetwork: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	prefix := "hallpass-interop/" + rand.Text() + "/"
	data := make([]byte, 3<<20)
	_, _ = rand.Read(data)
	sum := sha256.Sum256(data)
	key := prefix + "dir with space/obj+1.bin"
	if err := c.Put(ctx, key, bytes.NewReader(data), int64(len(data)), hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("put: %v", err)
	}
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })
	if n, err := c.Head(ctx, key); err != nil || n != int64(len(data)) {
		t.Fatalf("head %d %v", n, err)
	}
	rc, _, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("round trip mismatch")
	}
	objs, err := c.List(ctx, prefix)
	if err != nil || len(objs) != 1 || objs[0].Key != key {
		t.Fatalf("list %+v %v", objs, err)
	}
	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Head(ctx, key); err == nil {
		t.Fatal("object still there after delete")
	}
}
