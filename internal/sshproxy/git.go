package sshproxy

import (
	"context"
	"errors"
	"io"
	"regexp"
	"sync/atomic"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
)

// gitProtocolRE accepts the values git sends in GIT_PROTOCOL ("version=2", optionally more ":key=value" fields).
var gitProtocolRE = regexp.MustCompile(`^[a-z0-9-]+=[a-z0-9.-]+(:[a-z0-9-]+=[a-z0-9.-]+)*$`)

// gitEnv forwards only GIT_PROTOCOL to a git host (protocol v2 negotiation); nothing else from the agent.
func gitEnv(env [][2]string) [][2]string {
	for _, kv := range env {
		if kv[0] == "GIT_PROTOCOL" && len(kv[1]) <= 256 && gitProtocolRE.MatchString(kv[1]) {
			return [][2]string{kv}
		}
	}
	return nil
}

// gitPushGate reads the push's ref-update commands from the agent before anything is sent to the git host, checks
// them against the access profile's ref rules and forwards them only when every update is allowed. A refused push
// ends the session without the host ever seeing a command, so it changes nothing there. It reports whether the
// caller should continue copying the rest of the stream (the pack).
func (p *Proxy) gitPushGate(ctx context.Context, s *Session, reg *access.ChannelReg, t *terminator, stdin io.WriteCloser, bytesIn *atomic.Int64) bool {
	pc, err := gitproto.ReadPushCommands(s.Agent)
	switch {
	case errors.Is(err, io.EOF):
		_ = stdin.Close() // the client sent nothing: let the host end the exchange
		return false
	case err != nil:
		msg := "malformed push"
		if errors.Is(err, gitproto.ErrSignedPush) {
			msg = err.Error()
		}
		s.Notify("push refused: " + msg)
		_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitPushRefused, "", map[string]any{"repo": s.Git.Repo, "error": msg})
		t.refuse("git_push_refused")
		return false
	}
	updates := make([]map[string]any, 0, len(pc.Updates))
	for _, u := range pc.Updates {
		action := "update"
		switch {
		case u.Create():
			action = "create"
		case u.Delete():
			action = "delete"
		}
		updates = append(updates, map[string]any{"ref": u.Ref, "old": u.Old, "new": u.New, "action": action})
	}
	if denied := s.Git.Push.CheckAll(pc.Updates); len(denied) > 0 {
		refused := make([]map[string]any, 0, len(denied))
		for _, d := range denied {
			s.Notify("push refused: " + d.Ref + ": " + d.Reason)
			refused = append(refused, map[string]any{"ref": d.Ref, "reason": d.Reason})
		}
		_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitPushRefused, "", map[string]any{"repo": s.Git.Repo, "updates": updates, "refused": refused})
		t.refuse("git_push_refused")
		return false
	}
	_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitPush, "", map[string]any{"repo": s.Git.Repo, "updates": updates})
	bytesIn.Add(int64(len(pc.Raw)))
	if _, err := stdin.Write(pc.Raw); err != nil {
		return false
	}
	return true
}

// countingWriter counts bytes written through it.
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}
