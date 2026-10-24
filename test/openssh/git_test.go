//go:build openssh

package openssh

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
)

// git runs the system git client with the gateway as its SSH transport.
func (g *Gateway) git(dir string, args ...string) (string, int) {
	g.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(),
		"GIT_SSH_COMMAND=ssh -F /dev/null -i "+g.keyFile+" -o IdentitiesOnly=yes -o UserKnownHostsFile="+g.knownHosts+
			" -o StrictHostKeyChecking=yes -o BatchMode=yes -p "+fmt.Sprint(g.port),
		"GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_NAME=agent", "GIT_AUTHOR_EMAIL=agent@example.test",
		"GIT_COMMITTER_NAME=agent", "GIT_COMMITTER_EMAIL=agent@example.test")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok { //nolint:errorlint // exec returns *ExitError directly
		code = ee.ExitCode()
	} else if err != nil {
		g.t.Fatalf("git %v: %v", args, err)
	}
	return out.String(), code
}

// gitProfile creates an access profile on the git remote with a working login key for the container's deploy user.
func (g *Gateway) gitProfile(host *Destination, serverID, alias string, caps []string, rules *inventory.GitRules) *inventory.Role {
	g.t.Helper()
	ctx := context.Background()
	role, err := g.A.Inventory.CreateRole(ctx, admin, serverID, inventory.RoleInput{Alias: ptr(alias), RemoteUser: ptr("deploy"),
		Capabilities: ptr(caps), Git: rules})
	must(g.t, err)
	cred, err := g.A.Credentials.Generate(ctx, admin, role.ID)
	must(g.t, err)
	host.Authorize("deploy", strings.Replace(cred.AuthorizedKeysLine, `from="`, `from="*,`, 1))
	_, err = g.A.Credentials.Probe(ctx, admin, cred.ID)
	must(g.t, err)
	_, err = g.A.Credentials.Activate(ctx, admin, cred.ID, false)
	must(g.t, err)
	return role
}

// Plain git through the gateway against a real git host (OpenSSH + git in a container): clone and fetch with a read
// profile, push to an allowed branch, and refusals for a protected branch, a branch deletion and a repository no
// profile covers. Refused pushes never reach the host.
func TestOpenSSHGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	g := startGateway(t)
	ctx := context.Background()
	host := StartDestination(t) // its own container: host keys are unique per enrolled server
	host.Exec(`su deploy -s /bin/sh -c 'set -e; mkdir -p ~/acme; for r in api secret; do git init -q --bare -b main ~/acme/$r.git; done;
		cd /tmp && git init -q -b main seed && cd seed && git -c user.name=seed -c user.email=seed@example.test commit -q --allow-empty -m init &&
		git push -q ~/acme/api.git main && git push -q ~/acme/secret.git main'`)
	remote, err := g.A.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Kind: ptr(inventory.KindGit), Alias: ptr("github"),
		Address: ptr(host.Host), Port: ptr(host.Port)})
	must(t, err)
	_, err = g.A.Inventory.AddHostIdentity(ctx, admin, remote.ID, host.HostKey())
	must(t, err)
	g.gitProfile(host, remote.ID, "acme-push", []string{inventory.CapGitRead, inventory.CapGitWrite}, &inventory.GitRules{
		Repos: []string{"acme/{api,web}"},
		Push:  gitproto.RefRules{Branches: []string{"agent/**", "main"}, ProtectedBranches: []string{"main"}},
	})

	work := t.TempDir()
	if out, code := g.git(work, "clone", "agent@127.0.0.1:github/acme/api.git", "api"); code != 0 {
		t.Fatalf("clone: %d %s", code, out)
	}
	repo := filepath.Join(work, "api")
	if out, code := g.git(repo, "log", "--oneline"); code != 0 || !strings.Contains(out, "init") {
		t.Fatalf("cloned history: %s", out)
	}
	if out, code := g.git(repo, "commit", "-q", "--allow-empty", "-m", "fix cart timeout"); code != 0 {
		t.Fatalf("commit: %s", out)
	}
	if out, code := g.git(repo, "push", "origin", "HEAD:refs/heads/agent/fix-cart"); code != 0 {
		t.Fatalf("push to agent/fix-cart: %d %s", code, out)
	}
	head, _ := g.git(repo, "rev-parse", "HEAD")
	if got := host.Exec("git --git-dir=/home/deploy/acme/api.git rev-parse agent/fix-cart"); got != strings.TrimSpace(head) {
		t.Fatalf("host has agent/fix-cart=%q, want %q", got, head)
	}
	mainBefore := host.Exec("git --git-dir=/home/deploy/acme/api.git rev-parse main")

	// A fast-forward update of an existing branch passes the pack check and lands on the host.
	if out, code := g.git(repo, "commit", "-q", "--allow-empty", "-m", "second fix"); code != 0 {
		t.Fatalf("commit: %s", out)
	}
	if out, code := g.git(repo, "push", "origin", "HEAD:refs/heads/agent/fix-cart"); code != 0 {
		t.Fatalf("fast-forward push: %d %s", code, out)
	}
	head, _ = g.git(repo, "rev-parse", "HEAD")
	if got := host.Exec("git --git-dir=/home/deploy/acme/api.git rev-parse agent/fix-cart"); got != strings.TrimSpace(head) {
		t.Fatalf("fast-forward not applied: host %q, want %q", got, head)
	}
	// Rewriting the branch and force-pushing it is refused, and the host keeps the old tip.
	if out, code := g.git(repo, "commit", "-q", "--amend", "--allow-empty", "-m", "rewritten fix"); code != 0 {
		t.Fatalf("amend: %s", out)
	}
	out, code := g.git(repo, "push", "--force", "origin", "HEAD:refs/heads/agent/fix-cart")
	if code == 0 || !strings.Contains(out, "force-push is blocked") {
		t.Fatalf("force push: %d %s", code, out)
	}
	if got := host.Exec("git --git-dir=/home/deploy/acme/api.git rev-parse agent/fix-cart"); got != strings.TrimSpace(head) {
		t.Fatalf("refused force-push changed the branch: host %q, want %q", got, head)
	}
	if out, code := g.git(repo, "reset", "-q", "--hard", "origin/agent/fix-cart"); code != 0 {
		t.Fatalf("reset: %s", out)
	}

	out, code = g.git(repo, "push", "origin", "HEAD:main")
	if code == 0 || !strings.Contains(out, "hallpass: push refused: refs/heads/main: protected branch") {
		t.Fatalf("push to main: %d %s", code, out)
	}
	if got := host.Exec("git --git-dir=/home/deploy/acme/api.git rev-parse main"); got != mainBefore {
		t.Fatal("refused push changed main on the host")
	}
	out, code = g.git(repo, "push", "origin", "--delete", "agent/fix-cart")
	if code == 0 || !strings.Contains(out, "deleting branches is not allowed") {
		t.Fatalf("branch delete: %d %s", code, out)
	}
	if got := host.Exec("git --git-dir=/home/deploy/acme/api.git rev-parse agent/fix-cart"); got != strings.TrimSpace(head) {
		t.Fatal("refused delete removed the branch on the host")
	}
	for _, path := range []string{"github/acme/secret.git", "github/acme/nope.git", "nosuchremote/acme/api.git", "web1/acme/api.git"} {
		out, code := g.git(work, "clone", "agent@127.0.0.1:"+path, "x-"+strings.ReplaceAll(path, "/", "-"))
		if code == 0 || !strings.Contains(out, "hallpass: repository not found or not permitted") {
			t.Fatalf("clone %s: %d %s", path, code, out)
		}
	}
	if _, stderr, code := g.Run("exec github -- id"); code != 81 || !strings.Contains(stderr, "is a git remote") {
		t.Fatalf("exec on a git remote: %d %s", code, stderr)
	}

	for typ, want := range map[string]int{"git.requested": 6, "git.push": 2, "git.push_refused": 3, "git.transferred": 6} {
		var n int
		must(t, g.A.Store.ReadDB().QueryRowContext(ctx, `SELECT count(*) FROM timeline_events WHERE type = ?`, typ).Scan(&n))
		if n != want {
			t.Errorf("%s events = %d, want %d", typ, n, want)
		}
	}
	var service, repoName string
	must(t, g.A.Store.ReadDB().QueryRowContext(ctx,
		`SELECT git_service, git_repo FROM ssh_channels WHERE git_service = 'git-receive-pack' LIMIT 1`).Scan(&service, &repoName))
	if repoName != "acme/api" {
		t.Errorf("channel repo = %q", repoName)
	}
}
