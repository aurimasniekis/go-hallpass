package app

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
)

// Without allow_force_push, the fast-forward proof reads commit parents the way git does: only the parent lines
// directly after the tree line count. A pushed commit with a parent line elsewhere proves nothing, so the update is
// refused and the branch on the host does not move. The host runs real git-receive-pack.
func TestGatewayGitPushRefusesParentGitDoesNotRead(t *testing.T) {
	for _, tool := range []string{"git", "ssh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	g := startGateway(t)
	host := g.gitRemote(map[string]inventory.RoleInput{
		"alice": {Capabilities: ptr([]string{inventory.CapGitRead, inventory.CapGitWrite}),
			Git: &inventory.GitRules{Repos: []string{"acme/**"}, Push: gitproto.RefRules{Branches: []string{"**"}}}},
	})
	hostRoot := t.TempDir()
	gitCmd := func(dir string, env []string, stdin io.Reader, args ...string) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
			"GIT_AUTHOR_NAME=agent", "GIT_AUTHOR_EMAIL=agent@example.test", "GIT_COMMITTER_NAME=agent",
			"GIT_COMMITTER_EMAIL=agent@example.test")
		cmd.Env = append(cmd.Env, env...)
		cmd.Stdin = stdin
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			return out.String(), ee.ExitCode()
		case err != nil:
			t.Fatalf("git %v: %v", args, err)
		}
		return out.String(), 0
	}
	if out, code := gitCmd(hostRoot, nil, nil, "init", "-q", "--bare", "-b", "main", "acme/api.git"); code != 0 {
		t.Fatalf("init host repository: %s", out)
	}
	host.Exec = func(cmd string, stdin io.Reader, stdout, stderr io.Writer) uint32 {
		c := exec.Command("sh", "-c", cmd) //nolint:gosec,noctx // the test host runs what the gateway sends, like sshd
		c.Dir, c.Stdin, c.Stdout, c.Stderr = hostRoot, stdin, stdout, stderr
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		if err := c.Run(); err != nil {
			return 1
		}
		return 0
	}
	hostRef := func(ref string) string {
		out, _ := gitCmd(filepath.Join(hostRoot, "acme/api.git"), nil, nil, "rev-parse", "--verify", "-q", ref)
		return strings.TrimSpace(out)
	}

	// The agent's ssh: its key and the pinned gateway host key.
	dir := t.TempDir()
	blk, err := ssh.MarshalPrivateKey(g.key.Private, "")
	must(t, err)
	keyFile, knownHosts := filepath.Join(dir, "key"), filepath.Join(dir, "known_hosts")
	must(t, os.WriteFile(keyFile, pem.EncodeToMemory(blk), 0o600))
	gwHost, gwPort, _ := net.SplitHostPort(g.addr)
	must(t, os.WriteFile(knownHosts, fmt.Appendf(nil, "[%s]:%s %s\n", gwHost, gwPort, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(g.hostPK)))), 0o600))
	sshEnv := []string{"GIT_SSH_COMMAND=ssh -F /dev/null -i " + keyFile + " -o IdentitiesOnly=yes -o UserKnownHostsFile=" +
		knownHosts + " -o StrictHostKeyChecking=yes -o BatchMode=yes -p " + gwPort}

	repo := filepath.Join(dir, "api")
	run := func(stdin io.Reader, args ...string) string {
		t.Helper()
		out, code := gitCmd(repo, sshEnv, stdin, args...)
		if code != 0 {
			t.Fatalf("git %v: %d %s", args, code, out)
		}
		return strings.TrimSpace(out)
	}
	must(t, os.Mkdir(repo, 0o700))
	run(nil, "init", "-q", "-b", "main")
	run(nil, "remote", "add", "origin", "agent@"+gwHost+":github/acme/api.git")
	must(t, os.WriteFile(filepath.Join(repo, "f"), []byte("one\n"), 0o600))
	run(nil, "add", "f")
	run(nil, "commit", "-q", "-m", "one")
	run(nil, "push", "-q", "origin", "main")
	run(nil, "commit", "-q", "--allow-empty", "-m", "two")
	old := run(nil, "rev-parse", "HEAD")
	run(nil, "push", "-q", "origin", "main") // a proven fast-forward goes through
	if got := hostRef("main"); got != old {
		t.Fatalf("host main = %q after a fast-forward, want %q", got, old)
	}

	// A commit with its parent line after the other headers.
	tree := run(nil, "rev-parse", "HEAD^{tree}")
	sig := "agent <agent@example.test> 1700000000 +0000"
	body := "tree " + tree + "\nauthor " + sig + "\ncommitter " + sig + "\nparent " + old + "\n\nunrelated history\n"
	u := run(strings.NewReader(body), "hash-object", "-t", "commit", "-w", "--literally", "--stdin")
	if got := run(nil, "rev-list", "--parents", "-n1", u); got != u {
		t.Fatalf("git reads the parents of %s as %q, want a root commit", u, got)
	}
	out, code := gitCmd(repo, sshEnv, nil, "push", "--force", "origin", u+":refs/heads/main")
	if code == 0 || !strings.Contains(out, "hallpass: push refused: refs/heads/main: cannot prove a fast-forward") {
		t.Fatalf("push of a commit git reads as a root: %d %s", code, out)
	}
	if got := hostRef("main"); got != old {
		t.Fatalf("refused push moved main on the host to %q", got)
	}
}
