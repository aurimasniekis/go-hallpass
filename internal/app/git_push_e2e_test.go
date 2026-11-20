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

// A fast-forward pushed with git's default thin pack after a repack with reachability bitmaps: git reuses the stored
// delta of a new commit against a commit the host already has, so HallPass cannot read the commit and cannot prove
// the fast-forward. The push is refused (never guessed), the refusal tells the agent to push with --no-thin, and that
// push is proven and lands. The host runs real git-receive-pack.
func TestGatewayGitPushThinPackAfterBitmapRepack(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available")
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
	run := func(args ...string) string {
		t.Helper()
		out, code := gitCmd(repo, sshEnv, nil, args...)
		if code != 0 {
			t.Fatalf("git %v: %d %s", args, code, out)
		}
		return strings.TrimSpace(out)
	}
	writeFile := func(name, content string) {
		must(t, os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600))
		run("add", name)
	}
	must(t, os.Mkdir(repo, 0o700))
	run("init", "-q", "-b", "main")
	run("remote", "add", "origin", "agent@"+gwHost+":github/acme/api.git")
	// Long messages make the host's commits bigger than the new ones, so the repack stores the new ones as deltas
	// against them.
	long := strings.Repeat(" with a long description", 20)
	for i := range 4 {
		writeFile("f", strings.Repeat(fmt.Sprintf("line %d\n", i), i+1))
		run("commit", "-q", "-m", fmt.Sprintf("change %d%s", i, long))
	}
	run("push", "-q", "origin", "main")
	run("checkout", "-q", "-b", "other")
	writeFile("g", "other\n")
	run("commit", "-q", "-m", "other work")
	run("push", "-q", "origin", "other")
	run("checkout", "-q", "main")
	old := run("rev-parse", "HEAD")
	if hostRef("main") != old {
		t.Fatalf("host main = %q, want %q", hostRef("main"), old)
	}
	writeFile("f", "new work\n")
	run("commit", "-q", "-m", "new work")
	run("merge", "-q", "--no-edit", "other")
	merge := run("rev-parse", "HEAD")
	run("repack", "-q", "-a", "-d", "-f", "-b")

	out, code := gitCmd(repo, sshEnv, nil, "push", "origin", "HEAD:main")
	if code == 0 || !strings.Contains(out, "hallpass: push refused: refs/heads/main: cannot prove a fast-forward") ||
		!strings.Contains(out, "push again with git push --no-thin") {
		t.Fatalf("thin push: %d %s", code, out)
	}
	if got := hostRef("main"); got != old {
		t.Fatalf("refused push moved main on the host to %q", got)
	}
	if out, code := gitCmd(repo, sshEnv, nil, "push", "--no-thin", "origin", "HEAD:main"); code != 0 {
		t.Fatalf("push --no-thin: %d %s", code, out)
	}
	if got := hostRef("main"); got != merge {
		t.Fatalf("host main = %q after push --no-thin, want %q", got, merge)
	}
}
