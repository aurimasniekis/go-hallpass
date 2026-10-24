package sshfront

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/sshfront/grammar"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
)

// errRepoNotFound is the single answer for a hidden or unknown remote, a repository no access profile covers and an
// operation no profile allows, so an agent cannot tell which repositories or remotes exist.
func errRepoNotFound() *grammar.Error {
	return grammar.NewError(grammar.ExitNotFoundOrForbidden, "repository not found or not permitted")
}

// isGitRemote reports whether the server is a git remote.
func (s *session) isGitRemote(ctx context.Context, serverID string) bool {
	if s.h.Inventory == nil {
		return false
	}
	srv, err := s.h.Inventory.GetServer(ctx, serverID)
	return err == nil && srv.Kind == inventory.KindGit
}

type accessCandidate struct {
	vr     policy.VisibleRole
	push   *gitproto.RefPolicy
	active *access.Grant
}

// rank orders candidate profiles: one with an active grant first, then auto-approved, then requestable.
func (c accessCandidate) rank() int {
	switch {
	case c.active != nil:
		return 0
	case c.vr.Decision.Level == policy.LevelAutoApprove:
		return 1
	}
	return 2
}

// gitOp serves a plain git client: `git clone <gateway>:<remote>/<repo>.git` runs git-upload-pack and `git push` runs
// git-receive-pack over this SSH session. The access profile is chosen from the repository and the operation (git
// cannot pass --role), access is reused or requested like connect, and the service runs on the git host with the
// profile's credential.
func (s *session) gitOp(ctx context.Context, gc gitproto.Command) int {
	if s.pty != nil {
		return s.fail(grammar.Usage("git operations do not use a terminal"))
	}
	tgt, err := gitproto.SplitPath(gc.Path)
	if err != nil {
		return s.fail(grammar.Usage("invalid repository path: use <remote>/<owner>/<repository>.git"))
	}
	vs, err := s.snap.ResolveServer(s.c.AgentID, tgt.Remote)
	if err != nil || !s.isGitRemote(ctx, vs.Server.ID) {
		return s.fail(errRepoNotFound())
	}
	need := inventory.CapGitRead
	if gc.Write() {
		need = inventory.CapGitWrite
	}
	active := s.activeGrants(ctx)
	var cands []accessCandidate
	for _, vr := range vs.Roles {
		role, err := s.h.Inventory.GetRole(ctx, vr.Role.ID)
		if err != nil || role.Git == nil || !role.Has(need) {
			continue
		}
		repos, push, err := role.Git.Compile()
		if err != nil || !repos.Match(tgt.Repo) {
			continue
		}
		g := active[vr.Role.ID]
		if g == nil && !vr.Decision.Requestable() {
			continue
		}
		cands = append(cands, accessCandidate{vr: vr, push: push, active: g})
	}
	if len(cands) == 0 {
		return s.fail(errRepoNotFound())
	}
	slices.SortStableFunc(cands, func(a, b accessCandidate) int {
		return cmp.Or(cmp.Compare(a.rank(), b.rank()), cmp.Compare(a.vr.Role.Name, b.vr.Role.Name))
	})
	c := cands[0]
	if c.active == nil && c.vr.Decision.RequireReason {
		// git cannot send a reason: the agent requests access first, then retries the git command.
		return s.fail(grammar.NewError(grammar.ExitInputRequired, fmt.Sprintf(
			"access to %s needs a reason: run ssh <gateway> request %s --role %s --reason '<why>' --wait, then retry",
			tgt.Repo, vs.Server.Alias, c.vr.Role.Name)))
	}
	g, code := s.obtainGrant(ctx, vs, c.vr, grammar.Opts{}, true)
	if g == nil {
		return code
	}
	op := &sshproxy.GitOp{Service: gc.Service, Repo: tgt.Repo, Forward: tgt.Forward}
	if gc.Write() {
		op.Push = c.push
	}
	return s.proxy(ctx, &sshproxy.Session{
		ConnectionID: s.c.ID, AgentID: s.c.AgentID, KeyID: s.c.KeyID, SourceIP: s.c.SourceIP.String(), Grant: g,
		Kind: access.KindExec, Env: s.env, Agent: s.ch, AgentReqs: s.reqs, Notify: s.notice, Git: op,
	})
}
