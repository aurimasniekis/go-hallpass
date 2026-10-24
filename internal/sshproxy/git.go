package sshproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"regexp"
	"slices"
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
// caller should continue copying the rest of the stream, and from which reader.
//
// When force-pushes are blocked and a branch is moved, the pack that follows is read as it streams to the host and
// its final checksum is withheld until every such update is proven a fast-forward. If one is not, the session ends:
// the host gets a truncated pack, rejects it and changes no ref.
func (p *Proxy) gitPushGate(ctx context.Context, s *Session, reg *access.ChannelReg, t *terminator, stdin io.WriteCloser, bytesIn *atomic.Int64) (io.Reader, bool) {
	pc, err := gitproto.ReadPushCommands(s.Agent)
	switch {
	case errors.Is(err, io.EOF):
		_ = stdin.Close() // the client sent nothing: let the host end the exchange
		return nil, false
	case err != nil:
		msg := "malformed push"
		if errors.Is(err, gitproto.ErrSignedPush) {
			msg = err.Error()
		}
		s.Notify("push refused: " + msg)
		_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitPushRefused, "", map[string]any{"repo": s.Git.Repo, "error": msg})
		t.refuse("git_push_refused")
		return nil, false
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
		return nil, false
	}
	var checks []int
	for i, u := range pc.Updates {
		if s.Git.Push.NeedsFastForward(u) {
			checks = append(checks, i)
		}
	}
	bytesIn.Add(int64(len(pc.Raw)))
	if _, err := stdin.Write(pc.Raw); err != nil {
		return nil, false
	}
	if len(checks) == 0 {
		_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitPush, "", map[string]any{"repo": s.Git.Repo, "updates": updates})
		return s.Agent, true
	}

	br := bufio.NewReaderSize(s.Agent, 64<<10)
	counted := countingWriter{w: stdin, n: bytesIn}
	if slices.Contains(pc.Capabilities, "push-options") {
		if err := gitproto.CopyPktSection(br, counted); err != nil {
			return p.refusePush(ctx, s, reg, t, updates, nil, "malformed push options")
		}
	}
	graph, trailer, err := gitproto.ScanPack(br, counted, len(pc.Updates[checks[0]].Old)/2)
	if err != nil {
		return p.refusePush(ctx, s, reg, t, updates, nil, "the pushed pack could not be read")
	}
	var refused []map[string]any
	for _, i := range checks {
		u := pc.Updates[i]
		ff := graph.AncestryOf(u.Old, u.New)
		updates[i]["fast_forward"] = ff == gitproto.FastForward
		if ff != gitproto.FastForward {
			reason := "not a fast-forward; force-push is blocked for this access profile"
			if ff == gitproto.Unknown {
				reason = "cannot prove a fast-forward from the pushed commits; force-push is blocked (push new commits on top of the branch)"
			}
			refused = append(refused, map[string]any{"ref": u.Ref, "reason": reason})
		}
	}
	if len(refused) > 0 {
		return p.refusePush(ctx, s, reg, t, updates, refused, "")
	}
	_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitPush, "", map[string]any{"repo": s.Git.Repo, "updates": updates})
	if _, err := counted.Write(trailer); err != nil {
		return nil, false
	}
	return br, true
}

// refusePush tells the agent why, records the refusal and ends the session without letting the push complete.
func (p *Proxy) refusePush(ctx context.Context, s *Session, reg *access.ChannelReg, t *terminator, updates, refused []map[string]any, msg string) (io.Reader, bool) {
	for _, r := range refused {
		s.Notify("push refused: " + r["ref"].(string) + ": " + r["reason"].(string))
	}
	data := map[string]any{"repo": s.Git.Repo, "updates": updates}
	if msg != "" {
		s.Notify("push refused: " + msg)
		data["error"] = msg
	}
	if refused != nil {
		data["refused"] = refused
	}
	_ = p.o.Access.AppendSessionEvent(ctx, reg, access.EvGitPushRefused, "", data)
	t.refuse("git_push_refused")
	return nil, false
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
