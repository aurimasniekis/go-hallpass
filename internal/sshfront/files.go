package sshfront

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/sshfront/grammar"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
)

const fileTransferUsage = "file transfer: connect as <server>@<gateway> (or <server>+<role>@<gateway>), " +
	"for example: scp build.tar web1@center:/tmp/"

// fileTransfer serves scp and sftp: the SSH user name names the server ("web1") and optionally the role
// ("web1+deploy"), because the SFTP protocol carries no target. Only roles with the file-transfer capability qualify;
// access is reused or requested like connect, and every file operation is recorded.
func (s *session) fileTransfer(ctx context.Context) int {
	alias, roleAlias, _ := strings.Cut(s.c.ClientUser, "+")
	if !inventory.ValidAlias(alias) || (roleAlias != "" && !inventory.ValidAlias(roleAlias)) {
		return s.fail(grammar.Usage(fileTransferUsage))
	}
	vs, err := s.snap.ResolveServer(s.c.AgentID, alias)
	if err != nil || s.serverKind(ctx, vs.Server.ID) != inventory.KindSSH {
		return s.fail(grammar.NotFoundOrForbidden())
	}
	active := s.activeGrants(ctx)
	var cands []accessCandidate
	for _, vr := range vs.Roles {
		if roleAlias != "" && vr.Role.Name != roleAlias {
			continue
		}
		role, err := s.h.Inventory.GetRole(ctx, vr.Role.ID)
		if err != nil || !role.Has(inventory.CapFileTransfer) {
			continue
		}
		g := active[vr.Role.ID]
		if g == nil && !vr.Decision.Requestable() {
			continue
		}
		cands = append(cands, accessCandidate{vr: vr, active: g})
	}
	if len(cands) == 0 {
		// The server is visible to this agent, so saying why does not reveal anything.
		return s.fail(grammar.NewError(grammar.ExitNotFoundOrForbidden, "no role you can use on "+alias+" allows file transfer"))
	}
	slices.SortStableFunc(cands, func(a, b accessCandidate) int {
		return cmp.Or(cmp.Compare(a.rank(), b.rank()), cmp.Compare(a.vr.Role.Name, b.vr.Role.Name))
	})
	c := cands[0]
	if c.active == nil && c.vr.Decision.RequireReason {
		return s.fail(grammar.NewError(grammar.ExitInputRequired, fmt.Sprintf(
			"file transfer on %s needs a reason: run ssh <gateway> request %s --role %s --reason '<why>' --wait, then retry",
			alias, alias, c.vr.Role.Name)))
	}
	g, code := s.obtainGrant(ctx, vs, c.vr, grammar.Opts{}, true)
	if g == nil {
		return code
	}
	s.notice(fmt.Sprintf("file transfer on %s as %s (access until %s); every file operation is recorded",
		alias, c.vr.Role.Name, g.ExpiresAt.UTC().Format(time.RFC3339)))
	return s.proxy(ctx, &sshproxy.Session{
		ConnectionID: s.c.ID, AgentID: s.c.AgentID, KeyID: s.c.KeyID, SourceIP: s.c.SourceIP.String(), Grant: g,
		Kind: access.KindExec, Agent: s.ch, AgentReqs: s.reqs, Notify: s.notice, FileTransfer: true, AgentSession: s.agentSession,
	})
}
