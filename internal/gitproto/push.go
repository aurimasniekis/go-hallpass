package gitproto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Limits for the command list at the start of a push. They are far above what git sends for real pushes and keep a
// hostile client from making the gateway buffer without bound before anything reaches the upstream host.
const (
	maxPktLen       = 65520
	maxCommandBytes = 1 << 20
	maxUpdates      = 10000
)

// RefUpdate is one "old new ref" command of a push.
type RefUpdate struct {
	Old, New, Ref string
}

// Create reports whether the ref does not exist yet.
func (u RefUpdate) Create() bool { return isZeroID(u.Old) }

// Delete reports whether the push removes the ref.
func (u RefUpdate) Delete() bool { return isZeroID(u.New) }

func isZeroID(id string) bool { return strings.Trim(id, "0") == "" }

// PushCommands is the parsed command list of a push and the exact bytes it occupied on the wire, which are forwarded
// unchanged once the commands are allowed.
type PushCommands struct {
	Updates      []RefUpdate
	Capabilities []string
	Raw          []byte
}

// Errors returned by ReadPushCommands.
var (
	ErrProtocol   = errors.New("malformed git push")
	ErrSignedPush = errors.New("signed pushes (push certificates) are not supported through HallPass")
)

// ReadPushCommands reads the client's side of a push up to and including the flush packet that ends the command list:
// optional "shallow" lines, then "old new ref\0capabilities" and further "old new ref" lines. It returns io.EOF when
// the client sent nothing at all. Pack data that follows is not read.
func ReadPushCommands(r io.Reader) (*PushCommands, error) {
	pc := &PushCommands{}
	var raw bytes.Buffer
	first := true
	for {
		payload, flush, err := readPkt(r, &raw)
		if err != nil {
			if errors.Is(err, io.EOF) && raw.Len() == 0 {
				return nil, io.EOF
			}
			return nil, err
		}
		if raw.Len() > maxCommandBytes {
			return nil, fmt.Errorf("%w: command list too large", ErrProtocol)
		}
		if flush {
			pc.Raw = raw.Bytes()
			return pc, nil
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if strings.HasPrefix(line, "shallow ") {
			if !first || !validObjectID(strings.TrimPrefix(line, "shallow ")) {
				return nil, fmt.Errorf("%w: unexpected shallow line", ErrProtocol)
			}
			continue
		}
		if strings.HasPrefix(line, "push-cert") {
			return nil, ErrSignedPush
		}
		cmd := line
		if first {
			var caps string
			cmd, caps, _ = strings.Cut(line, "\x00")
			pc.Capabilities = strings.Fields(caps)
			first = false
		} else if strings.Contains(line, "\x00") {
			return nil, fmt.Errorf("%w: capabilities after the first command", ErrProtocol)
		}
		parts := strings.Split(cmd, " ")
		if len(parts) != 3 || !validObjectID(parts[0]) || !validObjectID(parts[1]) || len(parts[0]) != len(parts[1]) {
			return nil, fmt.Errorf("%w: bad command", ErrProtocol)
		}
		if len(pc.Updates) == maxUpdates {
			return nil, fmt.Errorf("%w: too many ref updates", ErrProtocol)
		}
		pc.Updates = append(pc.Updates, RefUpdate{Old: parts[0], New: parts[1], Ref: parts[2]})
	}
}

// readPkt reads one pkt-line, appending its bytes to raw. flush is true for "0000".
func readPkt(r io.Reader, raw *bytes.Buffer) (payload []byte, flush bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, fmt.Errorf("%w: truncated packet", ErrProtocol)
		}
		return nil, false, err
	}
	raw.Write(hdr[:])
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil {
		return nil, false, fmt.Errorf("%w: bad packet length", ErrProtocol)
	}
	switch {
	case n == 0:
		return nil, true, nil
	case n < 4 || n > maxPktLen:
		return nil, false, fmt.Errorf("%w: bad packet length", ErrProtocol)
	}
	payload = make([]byte, n-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false, fmt.Errorf("%w: truncated packet", ErrProtocol)
	}
	raw.Write(payload)
	return payload, false, nil
}

// validObjectID accepts SHA-1 (40) and SHA-256 (64) object IDs in lower-case hex.
func validObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// RefRules say which refs a push may change. Branch and tag patterns are relative to refs/heads/ and refs/tags/.
type RefRules struct {
	// Branches may be created and updated. Empty means no branch may be pushed.
	Branches []string `json:"branches,omitempty"`
	// ProtectedBranches are never created, updated or deleted, even when Branches matches them.
	ProtectedBranches []string `json:"protected_branches,omitempty"`
	// Tags may be created. Existing tags are never moved or deleted.
	Tags []string `json:"tags,omitempty"`
	// AllowDelete permits deleting branches that Branches matches and ProtectedBranches does not.
	AllowDelete bool `json:"allow_delete,omitempty"`
}

// RefPolicy is a compiled RefRules.
type RefPolicy struct {
	branches, protected, tags PatternSet
	allowDelete               bool
}

// Compile validates and compiles the rules. Ref names are case-sensitive.
func (r RefRules) Compile() (*RefPolicy, error) {
	b, err := CompilePatterns(r.Branches, false)
	if err != nil {
		return nil, fmt.Errorf("branches: %w", err)
	}
	p, err := CompilePatterns(r.ProtectedBranches, false)
	if err != nil {
		return nil, fmt.Errorf("protected branches: %w", err)
	}
	t, err := CompilePatterns(r.Tags, false)
	if err != nil {
		return nil, fmt.Errorf("tags: %w", err)
	}
	return &RefPolicy{branches: b, protected: p, tags: t, allowDelete: r.AllowDelete}, nil
}

// RefDenied explains why one ref update is refused.
type RefDenied struct {
	Ref    string
	Reason string
}

func (e *RefDenied) Error() string { return e.Ref + ": " + e.Reason }

// Check returns a *RefDenied when the update is not allowed.
func (p *RefPolicy) Check(u RefUpdate) error {
	deny := func(reason string) error { return &RefDenied{Ref: u.Ref, Reason: reason} }
	if !validRefName(u.Ref) {
		return deny("invalid ref name")
	}
	switch {
	case strings.HasPrefix(u.Ref, "refs/heads/"):
		name := strings.TrimPrefix(u.Ref, "refs/heads/")
		switch {
		case p.protected.Match(name):
			return deny("protected branch")
		case !p.branches.Match(name):
			return deny("branch not allowed for this access profile")
		case u.Delete() && !p.allowDelete:
			return deny("deleting branches is not allowed")
		}
		return nil
	case strings.HasPrefix(u.Ref, "refs/tags/"):
		name := strings.TrimPrefix(u.Ref, "refs/tags/")
		switch {
		case !u.Create():
			return deny("tags can only be created, not moved or deleted")
		case !p.tags.Match(name):
			return deny("tag not allowed for this access profile")
		}
		return nil
	}
	return deny("only branches and tags can be pushed")
}

// CheckAll checks every update and returns all refusals, in order.
func (p *RefPolicy) CheckAll(us []RefUpdate) []*RefDenied {
	var out []*RefDenied
	for _, u := range us {
		var d *RefDenied
		if err := p.Check(u); errors.As(err, &d) {
			out = append(out, d)
		}
	}
	return out
}

// validRefName applies git's ref name rules (check-ref-format) that matter for matching: no "..", "//", "@{",
// control characters, spaces or ~^:?*[\, no component starting with '.' or ending with ".lock", no trailing '/' or '.'.
func validRefName(ref string) bool {
	if ref == "" || len(ref) > 1024 || strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.Contains(ref, "@{") ||
		strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") || ref == "@" {
		return false
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" ~^:?*[\\", r) {
			return false
		}
	}
	for c := range strings.SplitSeq(ref, "/") {
		if strings.HasPrefix(c, ".") || strings.HasSuffix(c, ".lock") {
			return false
		}
	}
	return true
}
