package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshtest"
)

// runAs is run with another SSH user name (the agent is still identified by its key).
func (g *gw) runAs(user, cmd string) (string, string, int) {
	g.t.Helper()
	c, err := ssh.Dial("tcp", g.addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(g.key.Signer)},
		HostKeyCallback: ssh.FixedHostKey(g.hostPK), Timeout: 5 * time.Second})
	must(g.t, err)
	defer c.Close()
	s, err := c.NewSession()
	must(g.t, err)
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	err = s.Run(cmd)
	code := 0
	var ee *ssh.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitStatus()
	case err != nil:
		g.t.Fatalf("%s as %s: %v", cmd, user, err)
	}
	return out.String(), errb.String(), code
}

// gitRemote enrolls a git remote "github" on its own in-process host, with one auto-approved access profile per
// entry; each profile logs in as the remote user named like the profile.
func (g *gw) gitRemote(profiles map[string]inventory.RoleInput) *sshtest.Server {
	g.t.Helper()
	ctx := context.Background()
	host := sshtest.Start(g.t)
	addr, port := host.Addr()
	srv, err := g.a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Kind: ptr(inventory.KindGit), Alias: ptr("github"),
		Address: ptr(addr), Port: ptr(port)})
	must(g.t, err)
	_, err = g.a.Inventory.AddHostIdentity(ctx, admin, srv.ID, host.KnownHostsLine(0))
	must(g.t, err)
	for alias, in := range profiles {
		in.Alias, in.RemoteUser = ptr(alias), ptr(alias)
		role, err := g.a.Inventory.CreateRole(ctx, admin, srv.ID, in)
		must(g.t, err)
		cred, err := g.a.Credentials.Generate(ctx, admin, role.ID)
		must(g.t, err)
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cred.PublicKey))
		must(g.t, err)
		host.Authorize(pk)
		_, err = g.a.Credentials.Probe(ctx, admin, cred.ID)
		must(g.t, err)
		_, err = g.a.Credentials.Activate(ctx, admin, cred.ID, false)
		must(g.t, err)
	}
	return host
}

// Issue #1: "<remote>+<profile>" in the SSH user picks the git access profile, with no fallback to another profile;
// without "+" the profile is chosen as before.
func TestGatewayGitProfileFromSSHUser(t *testing.T) {
	g := startGateway(t)
	host := g.gitRemote(map[string]inventory.RoleInput{
		"alice": {Capabilities: ptr([]string{inventory.CapGitRead, inventory.CapGitWrite}),
			Git: &inventory.GitRules{Repos: []string{"acme/**"}, Push: gitproto.RefRules{Branches: []string{"**"}}}},
		"bot": {Capabilities: ptr([]string{inventory.CapGitRead}), Git: &inventory.GitRules{Repos: []string{"acme/{api,docs}"}}},
	})
	// lastLogin returns the remote user of the newest login on the git host, "" when nothing logged in since mark.
	mark := len(host.Logins())
	lastLogin := func() string {
		logins := host.Logins()
		if len(logins) == mark {
			return ""
		}
		defer func() { mark = len(logins) }()
		return logins[len(logins)-1].User
	}
	const fetch = "git-upload-pack 'github/acme/api.git'"

	// Both profiles cover the fetch; without a profile in the user the tie goes to the name, as before.
	for _, user := range []string{"agent", "github", "git"} {
		out, errOut, code := g.runAs(user, fetch)
		if code != 0 || !strings.Contains(out, "acme/api.git") || lastLogin() != "alice" {
			t.Fatalf("fetch as %s: %d %q %q", user, code, out, errOut)
		}
	}
	for user, want := range map[string]string{"github+bot": "bot", "github+alice": "alice"} {
		out, errOut, code := g.runAs(user, fetch)
		if got := lastLogin(); code != 0 || !strings.Contains(out, "acme/api.git") || got != want {
			t.Fatalf("fetch as %s: %d %q %q, logged in as %q", user, code, out, errOut, got)
		}
	}

	// A named profile that does not cover the repository or the operation fails like an unknown repository, even
	// when another profile would allow it, and nothing reaches the host.
	for _, tc := range []struct{ user, cmd string }{
		{"github+bot", "git-receive-pack 'github/acme/api.git'"}, // bot cannot push; alice could
		{"github+bot", "git-upload-pack 'github/acme/web.git'"},  // bot does not cover acme/web; alice does
		{"github+nobody", fetch},                                 // no such profile
		{"github+inspect", fetch},                                // a role of another server
	} {
		_, errOut, code := g.runAs(tc.user, tc.cmd)
		if code != 82 || !strings.Contains(errOut, "repository not found or not permitted") {
			t.Fatalf("%s as %s: %d %q", tc.cmd, tc.user, code, errOut)
		}
		if got := lastLogin(); got != "" {
			t.Fatalf("%s as %s reached the host as %q", tc.cmd, tc.user, got)
		}
	}

	// A "+" with another remote or an invalid profile name is a usage error, never ignored.
	for _, user := range []string{"gitlab+bot", "web1+bot", "github+", "+bot", "github+-bot", "github+bot+alice"} {
		_, errOut, code := g.runAs(user, fetch)
		if code != 81 || !strings.Contains(errOut, "<remote>+<profile>@<gateway>") {
			t.Fatalf("fetch as %s: %d %q", user, code, errOut)
		}
		if got := lastLogin(); got != "" {
			t.Fatalf("fetch as %s reached the host as %q", user, got)
		}
	}
}
