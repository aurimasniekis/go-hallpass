// Package gitproto understands the parts of the Git SSH transport that HallPass enforces: the service command an
// agent's git sends over SSH, the repository path it names, repository and ref patterns, and the ref-update commands
// at the start of a push. It never interprets pack data.
package gitproto

import (
	"errors"
	"strings"
)

// Git services an agent may request. Upload-pack and upload-archive read; receive-pack writes.
const (
	UploadPack    = "git-upload-pack"
	ReceivePack   = "git-receive-pack"
	UploadArchive = "git-upload-archive"
)

// MaxPathLen bounds the repository path in a git command.
const MaxPathLen = 512

// Command is a parsed git service request, e.g. `git-receive-pack 'github/acme/api.git'`.
type Command struct {
	Service string
	Path    string // unquoted, exactly as the client sent it
}

// Write reports whether the service modifies the repository.
func (c Command) Write() bool { return c.Service == ReceivePack }

// ErrInvalidCommand is returned for a git service command whose path is missing or malformed.
var ErrInvalidCommand = errors.New("invalid git command")

// ParseCommand recognizes the command git runs over SSH. ok is false when cmd is not a git service command (it is then
// handled by the gateway grammar). Both `git-upload-pack 'path'` and `git upload-pack 'path'` are accepted. The path
// may be single-quoted the way git quotes it ('\” for an embedded quote) or bare.
func ParseCommand(cmd string) (c Command, ok bool, err error) {
	rest := strings.TrimSpace(cmd)
	var service string
	for _, svc := range []string{UploadPack, ReceivePack, UploadArchive} {
		spaced := "git " + strings.TrimPrefix(svc, "git-")
		switch {
		case strings.HasPrefix(rest, svc+" "):
			service, rest = svc, rest[len(svc)+1:]
		case strings.HasPrefix(rest, spaced+" "):
			service, rest = svc, rest[len(spaced)+1:]
		case rest == svc || rest == spaced:
			return Command{}, true, ErrInvalidCommand
		}
		if service != "" {
			break
		}
	}
	if service == "" {
		return Command{}, false, nil
	}
	path, err := unquote(strings.TrimSpace(rest))
	if err != nil || path == "" || len(path) > MaxPathLen {
		return Command{}, true, ErrInvalidCommand
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return Command{}, true, ErrInvalidCommand
		}
	}
	return Command{Service: service, Path: path}, true, nil
}

// unquote reverses git's sq_quote: 'abc' with '\” for embedded quotes, possibly concatenated. A bare word without
// quotes or whitespace is accepted as is.
func unquote(s string) (string, error) {
	if !strings.HasPrefix(s, "'") {
		if strings.ContainsAny(s, " \t'\"\\") {
			return "", ErrInvalidCommand
		}
		return s, nil
	}
	var b strings.Builder
	for len(s) > 0 {
		switch {
		case s[0] == '\'':
			end := strings.IndexByte(s[1:], '\'')
			if end < 0 {
				return "", ErrInvalidCommand
			}
			b.WriteString(s[1 : 1+end])
			s = s[end+2:]
		case strings.HasPrefix(s, `\'`):
			b.WriteByte('\'')
			s = s[2:]
		default:
			return "", ErrInvalidCommand
		}
	}
	return b.String(), nil
}

// Quote quotes s for a POSIX shell the way git does, for the command sent to the upstream host.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Target is a git path split into the gateway's remote alias and the repository on that remote.
type Target struct {
	// Remote is the git remote alias (the first path segment).
	Remote string
	// Repo is the normalized repository name used for policy: no leading slash, no ".git" suffix, lower case.
	Repo string
	// Forward is the path to send to the upstream host: the client's path without the remote segment, keeping a
	// leading slash (ssh:// URLs) and the ".git" suffix if the client used them.
	Forward string
}

// ErrInvalidPath is returned for a repository path that is not a plain relative path of safe segments.
var ErrInvalidPath = errors.New("invalid repository path")

// SplitPath splits "github/acme/api.git" (scp-style remotes) or "/github/acme/api.git" (ssh:// URLs) into the remote
// alias and the repository. Segments must be non-empty and use letters, digits, '.', '_' and '-'; "." and anything
// containing ".." are refused, so the forwarded path can never climb out of the host's repository namespace.
func SplitPath(p string) (Target, error) {
	lead := ""
	if strings.HasPrefix(p, "/") {
		lead, p = "/", p[1:]
	}
	p = strings.TrimSuffix(p, "/")
	remote, rest, found := strings.Cut(p, "/")
	if !found || remote == "" || rest == "" {
		return Target{}, ErrInvalidPath
	}
	for seg := range strings.SplitSeq(p, "/") {
		if !validSegment(seg) {
			return Target{}, ErrInvalidPath
		}
	}
	repo := strings.ToLower(strings.TrimSuffix(rest, ".git"))
	if repo == "" || strings.HasSuffix(repo, "/") {
		return Target{}, ErrInvalidPath
	}
	return Target{Remote: remote, Repo: repo, Forward: lead + rest}, nil
}

func validSegment(s string) bool {
	if s == "" || s == "." || strings.Contains(s, "..") || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
