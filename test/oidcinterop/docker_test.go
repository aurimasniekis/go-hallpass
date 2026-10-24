//go:build oidcinterop

// Package oidcinterop runs HallPass's OIDC SSO against real identity providers (Keycloak and Dex in Docker), driving
// the IdP's own login form with a browser-like HTTP client (PLAN WP14 interop smoke tests, ADR-0030). Run with
// `go test -tags oidcinterop ./test/oidcinterop/` (requires Docker); see README.md.
package oidcinterop

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Images are pinned by version tag and by multi-arch index digest. Docker refuses to run them if the registry
// serves different content for the tag. Override with HALLPASS_KEYCLOAK_IMAGE / HALLPASS_DEX_IMAGE when upgrading;
// the resolved digest is logged on every run.
const (
	keycloakImage = "quay.io/keycloak/keycloak:26.7.5@sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85"
	dexImage      = "ghcr.io/dexidp/dex:v2.46.0@sha256:933fcd3f523338c847b88ef84a7145fb2fcb7b9917f08418612afeaaa2001777"
)

func imageRef(env, pinned string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return pinned
}

func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("HALLPASS_SKIP_OIDC_INTEROP") != "" {
		t.Skip("HALLPASS_SKIP_OIDC_INTEROP set")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skipf("docker daemon not reachable: %v", err)
	}
}

func dockerCmd(t testing.TB, stdin []byte, timeout time.Duration, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

func docker(t testing.TB, args ...string) string {
	t.Helper()
	return dockerCmd(t, nil, 10*time.Minute, args...)
}

// container is a running IdP container.
type container struct {
	ID     string
	Image  string
	Digest string
	Port   int // host port on 127.0.0.1
}

// file is copied into the container before it starts (no bind mounts, so it also works with remote daemons).
type file struct {
	Dir  string // existing absolute directory in the image
	Name string // path relative to Dir; missing subdirectories are created world-readable
	Data []byte
}

// startContainer pulls (by digest) and starts an image with files copied in. hostPort 0 lets Docker pick one.
func startContainer(t *testing.T, image string, containerPort, hostPort int, env []string, files []file, cmd ...string) *container {
	t.Helper()
	if !strings.Contains(image, "@sha256:") {
		t.Logf("warning: %s is not pinned by digest", image)
	}
	docker(t, "pull", "-q", image)
	digests := docker(t, "image", "inspect", "--format", "{{join .RepoDigests \" \"}}", image)
	t.Logf("image %s resolved to %s", image, digests)
	publish := fmt.Sprintf("127.0.0.1::%d", containerPort)
	if hostPort != 0 {
		publish = fmt.Sprintf("127.0.0.1:%d:%d", hostPort, containerPort)
	}
	args := []string{"create", "-p", publish, "--label", "hallpass-test=oidcinterop"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, image)
	args = append(args, cmd...)
	id := docker(t, args...)
	c := &container{ID: id, Image: image, Digest: digests}
	t.Cleanup(func() {
		if t.Failed() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, _ := exec.CommandContext(ctx, "docker", "logs", "--tail", "300", id).CombinedOutput()
			t.Logf("container %s logs:\n%s", image, out)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", "-v", id).Run()
	})
	for _, f := range files {
		dockerCmd(t, tarOf(t, f.Name, f.Data), time.Minute, "cp", "-", id+":"+f.Dir)
	}
	docker(t, "start", id)
	hp := docker(t, "port", id, fmt.Sprintf("%d/tcp", containerPort))
	_, portStr, err := net.SplitHostPort(strings.Split(hp, "\n")[0])
	if err != nil {
		t.Fatalf("docker port %q: %v", hp, err)
	}
	if c.Port, err = strconv.Atoi(portStr); err != nil {
		t.Fatal(err)
	}
	return c
}

// tarOf builds a one-file archive for `docker cp -`; entries are world-readable so non-root images can read them.
func tarOf(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/") + "/"
		if err := tw.WriteHeader(&tar.Header{Name: dir, Mode: 0o755, ModTime: time.Now(), Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: time.Now(), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// waitHTTP polls url until it returns 200.
func waitHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	hc := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := hc.Do(req)
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
			last = res.Status
		} else {
			last = err.Error()
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s not ready after %s: %s", url, timeout, last)
}

// freePort reserves and releases a loopback port (Dex needs its public port in its config before it starts).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
