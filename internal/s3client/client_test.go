package s3client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/s3client"
	"github.com/aurimasniekis/go-hallpass/internal/s3client/s3test"
)

func client(t *testing.T, srv *s3test.Server, mod func(*s3client.Config)) *s3client.Client {
	t.Helper()
	cfg := s3client.Config{Endpoint: srv.URL, Bucket: "hp-backups", PathStyle: true, AccessKeyID: "AKIDTEST", SecretAccessKey: "secret",
		CABundlePEM: srv.CAPEM(), AllowPrivateNetwork: true}
	if mod != nil {
		mod(&cfg)
	}
	c, err := s3client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func put(t *testing.T, c *s3client.Client, key string, data []byte) {
	t.Helper()
	sum := sha256.Sum256(data)
	if err := c.Put(context.Background(), key, bytes.NewReader(data), int64(len(data)), hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
}

func TestObjectLifecycle(t *testing.T) {
	srv := s3test.New(t, "AKIDTEST")
	c := client(t, srv, nil)
	ctx := context.Background()

	put(t, c, "hallpass/snapshots/bkp 1/db.hpbak", []byte("sealed database"))
	if got, ok := srv.Object("hp-backups", "hallpass/snapshots/bkp 1/db.hpbak"); !ok || string(got) != "sealed database" {
		t.Fatalf("stored %q %v", got, ok)
	}
	rc, n, err := c.Get(ctx, "hallpass/snapshots/bkp 1/db.hpbak")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "sealed database" || n != int64(len(b)) {
		t.Fatalf("get %q (%d)", b, n)
	}
	if size, err := c.Head(ctx, "hallpass/snapshots/bkp 1/db.hpbak"); err != nil || size != 15 {
		t.Fatalf("head %d %v", size, err)
	}
	if _, err := c.Head(ctx, "missing"); !errors.Is(err, s3client.ErrNotFound) {
		t.Fatalf("head missing: %v", err)
	}
	if _, _, err := c.Get(ctx, "missing"); !errors.Is(err, s3client.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if err := c.Delete(ctx, "hallpass/snapshots/bkp 1/db.hpbak"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "never-existed"); err != nil {
		t.Fatalf("deleting a missing key must succeed: %v", err)
	}
	if keys := srv.Keys("hp-backups"); len(keys) != 0 {
		t.Fatalf("left %v", keys)
	}
}

func TestListFollowsContinuation(t *testing.T) {
	srv := s3test.New(t, "AKIDTEST")
	srv.PageSize = 3
	c := client(t, srv, nil)
	for i := range 8 {
		put(t, c, fmt.Sprintf("p/recordings/seg%02d.hprec", i), []byte{byte(i)})
	}
	put(t, c, "other/x", []byte("x"))
	objs, err := c.List(context.Background(), "p/recordings/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 8 || objs[0].Key != "p/recordings/seg00.hprec" || objs[7].Size != 1 {
		t.Fatalf("listed %+v", objs)
	}
}

func TestPayloadHashIsChecked(t *testing.T) {
	srv := s3test.New(t, "AKIDTEST")
	c := client(t, srv, nil)
	err := c.Put(context.Background(), "k", strings.NewReader("abc"), 3, s3client.EmptySHA256)
	var e *s3client.Error
	if !errors.As(err, &e) || e.Code != "XAmzContentSHA256Mismatch" {
		t.Fatalf("mismatched payload hash: %v", err)
	}
}

func TestErrors(t *testing.T) {
	srv := s3test.New(t, "AKIDTEST")
	srv.Fail = func(r *http.Request) int {
		if r.Method == http.MethodPut {
			return http.StatusInternalServerError
		}
		return 0
	}
	c := client(t, srv, nil)
	sum := sha256.Sum256([]byte("x"))
	err := c.Put(context.Background(), "k", strings.NewReader("x"), 1, hex.EncodeToString(sum[:]))
	var e *s3client.Error
	if !errors.As(err, &e) || e.Status != 500 || e.Code != "InternalError" {
		t.Fatalf("error %v", err)
	}
	wrong := client(t, srv, func(c *s3client.Config) { c.AccessKeyID = "OTHER" })
	if _, err := wrong.List(context.Background(), ""); !errors.As(err, &e) || e.Status != http.StatusForbidden {
		t.Fatalf("wrong key: %v", err)
	}
}

// The endpoint resolves to loopback; without allow_private_network the connection is refused before any request.
func TestPrivateNetworkRefused(t *testing.T) {
	srv := s3test.New(t, "AKIDTEST")
	c := client(t, srv, func(c *s3client.Config) { c.AllowPrivateNetwork = false })
	if _, err := c.List(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("private endpoint reached: %v", err)
	}
	if srv.Requests != 0 {
		t.Fatalf("%d requests reached the server", srv.Requests)
	}
}

// TLS verification is never disabled: without the test CA the handshake fails.
func TestTLSVerified(t *testing.T) {
	srv := s3test.New(t, "AKIDTEST")
	c := client(t, srv, func(c *s3client.Config) { c.CABundlePEM = "" })
	if _, err := c.List(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := s3client.Config{Endpoint: "https://s3.example.com", Bucket: "hp-backups", AccessKeyID: "a", SecretAccessKey: "b"}
	for name, mod := range map[string]func(*s3client.Config){
		"http endpoint":  func(c *s3client.Config) { c.Endpoint = "http://s3.example.com" },
		"endpoint path":  func(c *s3client.Config) { c.Endpoint = "https://s3.example.com/bucket" },
		"endpoint creds": func(c *s3client.Config) { c.Endpoint = "https://u:p@s3.example.com" },
		"bucket case":    func(c *s3client.Config) { c.Bucket = "HP" },
		"bucket short":   func(c *s3client.Config) { c.Bucket = "hp" },
		"no secret":      func(c *s3client.Config) { c.SecretAccessKey = "" },
		"bad CA bundle":  func(c *s3client.Config) { c.CABundlePEM = "not pem" },
	} {
		cfg := base
		mod(&cfg)
		if _, err := s3client.New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := s3client.New(base); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	cfg := base
	cfg.Endpoint, cfg.AllowInsecureHTTP = "http://127.0.0.1:9000", true
	if _, err := s3client.New(cfg); err != nil {
		t.Fatalf("http with AllowInsecureHTTP: %v", err)
	}
}
