//go:build openssh

// Package openssh runs HallPass against real OpenSSH: the stock `ssh` client as the agent and an OpenSSH `sshd`
// container as the destination (HP-TST-003). Run with `make test-openssh` (requires Docker).
package openssh

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const image = "hallpass-test-sshd:latest"

var buildOnce sync.Once

// Destination is a running sshd container.
type Destination struct {
	t    testing.TB
	ID   string
	Host string
	Port int
}

func docker(t testing.TB, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

// StartDestination builds (once) and starts an sshd container, waiting until it accepts SSH connections.
func StartDestination(t testing.TB) *Destination {
	t.Helper()
	buildOnce.Do(func() { docker(t, "build", "-q", "-f", "Dockerfile.sshd", "-t", image, ".") })
	id := docker(t, "run", "-d", "--rm", "-p", "127.0.0.1::22", image)
	d := &Destination{t: t, ID: id, Host: "127.0.0.1"}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("sshd logs:\n%s", docker(t, "logs", id))
		}
		_ = exec.Command("docker", "rm", "-f", id).Run() //nolint:noctx // cleanup
	})
	hp := docker(t, "port", id, "22/tcp")
	_, portStr, err := net.SplitHostPort(strings.Split(hp, "\n")[0])
	if err != nil {
		t.Fatal(err)
	}
	d.Port, _ = strconv.Atoi(portStr)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", d.Port), time.Second)
		if err == nil {
			buf := make([]byte, 4)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := c.Read(buf)
			_ = c.Close()
			if n == 4 && string(buf) == "SSH-" {
				return d
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("sshd did not become ready")
	return nil
}

// Exec runs a shell command inside the container as root.
func (d *Destination) Exec(script string) string {
	d.t.Helper()
	return docker(d.t, "exec", d.ID, "sh", "-c", script)
}

// HostKey returns the container's Ed25519 host public key line.
func (d *Destination) HostKey() string { return d.Exec("cat /etc/ssh/ssh_host_ed25519_key.pub") }

// Authorize appends an authorized_keys line for user.
func (d *Destination) Authorize(user, line string) {
	d.Exec(fmt.Sprintf("printf '%%s\\n' %q >> /home/%s/.ssh/authorized_keys", line, user))
}

// TrustUserCA installs a user CA and the principals accepted for user.
func (d *Destination) TrustUserCA(caLine, user string, principals ...string) {
	d.Exec(fmt.Sprintf("printf '%%s\\n' %q > /etc/ssh/user_ca.pub && printf '%%s\\n' %s > /etc/ssh/principals/%s",
		caLine, strings.Join(quoteAll(principals), " "), user))
}

// ReplaceHostKey generates a new Ed25519 host key and restarts sshd (host key rotation / impostor tests).
func (d *Destination) ReplaceHostKey() {
	d.Exec("rm -f /etc/ssh/ssh_host_ed25519_key* && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key && pkill -HUP sshd || true")
	time.Sleep(500 * time.Millisecond)
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strconvQuote(s)
	}
	return out
}

func strconvQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if os.Getenv("HALLPASS_SKIP_OPENSSH") != "" {
		t.Skip("HALLPASS_SKIP_OPENSSH set")
	}
}
