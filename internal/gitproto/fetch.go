package gitproto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// Limits for the upload-pack conversation. The host is untrusted (ADR-0064, threat 7): everything it sends is
// bounded before it is buffered.
const (
	// maxAdvertLines bounds the capability advertisement; git sends about ten lines.
	maxAdvertLines = 64
	// maxWants bounds the objects requested in one fetch.
	maxWants = 256
	// maxShallowInfoLines bounds the shallow-info section. With deepen 1 it holds at most one line per want.
	maxShallowInfoLines = 4096
	// maxSidebandProgress bounds the progress packets ignored before the pack ends. We ask for no-progress, so
	// a well-behaved host sends none.
	maxSidebandProgress = 4096
)

// Errors returned by FetchCommits. Protocol violations by the host wrap ErrProtocol.
var (
	// ErrUnsupported means the host cannot serve the request: not protocol v2, no shallow or filter support, or a
	// different object format. Nothing was requested.
	ErrUnsupported = errors.New("git host does not support a shallow filtered fetch")
	// ErrHostRefused means the host answered with an ERR packet or sideband 3. The text is deliberately not kept: it
	// comes from the host and is never shown to the agent.
	ErrHostRefused = errors.New("git host refused the fetch")
	// ErrFetchTooLarge means the response exceeded the byte limit.
	ErrFetchTooLarge = errors.New("git fetch response exceeds the byte limit")
)

// FetchCommits asks a git-upload-pack session for the commits wants, and nothing else, and returns the raw bytes of
// the pack it sends back. rw is the session's stdin and stdout; the caller must have started git-upload-pack with
// GIT_PROTOCOL=version=2 and keeps ownership of rw.
//
// The request is protocol v2: "command=fetch", the object format, "no-progress", "deepen 1", "filter tree:0", one
// "want" per ID, "done". It never sends "have", "thin-pack" or "ofs-delta". It is sent only after the host's
// advertisement listed the fetch features "shallow" and "filter" and the same object format.
//
// objectFormat is "sha1" or "sha256"; wants are lower-case hex IDs of that length. maxBytes bounds everything read
// from rw, the advertisement included. When ctx ends before the fetch does, rw is closed to unblock a pending read or
// write, so a silent host cannot hold the call past the deadline. After a completed fetch rw is left open.
//
// The returned pack is NOT verified: it may hold any objects, deltas or garbage. The caller must check it.
func FetchCommits(ctx context.Context, rw io.ReadWriteCloser, objectFormat string, wants []string, maxBytes int64) ([]byte, error) {
	idLen := 0
	switch objectFormat {
	case "sha1":
		idLen = 40
	case "sha256":
		idLen = 64
	default:
		return nil, fmt.Errorf("unknown object format %q", objectFormat)
	}
	if len(wants) == 0 || len(wants) > maxWants {
		return nil, fmt.Errorf("need between 1 and %d objects to fetch, got %d", maxWants, len(wants))
	}
	seen := make(map[string]bool, len(wants))
	uniq := make([]string, 0, len(wants))
	for _, w := range wants {
		if len(w) != idLen || !validObjectID(w) {
			return nil, fmt.Errorf("invalid object id %q for %s", w, objectFormat)
		}
		if !seen[w] {
			seen[w] = true
			uniq = append(uniq, w)
		}
	}
	if maxBytes <= 0 {
		return nil, errors.New("fetch byte limit must be positive")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// finished is set under mu once the fetch has returned, so a cancellation racing with a completed fetch never
	// closes rw.
	var mu sync.Mutex
	finished := false
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			mu.Lock()
			if !finished {
				_ = rw.Close()
			}
			mu.Unlock()
		case <-stop:
		}
	}()

	pack, err := fetchCommits(ctx, rw, objectFormat, uniq, maxBytes)
	mu.Lock()
	finished = true
	mu.Unlock()
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, err
	}
	return pack, nil
}

func fetchCommits(ctx context.Context, rw io.ReadWriter, objectFormat string, wants []string, maxBytes int64) ([]byte, error) {
	r := &pktReader{ctx: ctx, r: bufio.NewReader(&budgetReader{r: rw, left: maxBytes})}
	if err := r.checkAdvertisement(objectFormat); err != nil {
		return nil, err
	}
	if _, err := rw.Write(fetchRequest(objectFormat, wants)); err != nil {
		return nil, fmt.Errorf("sending fetch request: %w", err)
	}
	return r.readPack()
}

// fetchRequest builds the v2 fetch command.
func fetchRequest(objectFormat string, wants []string) []byte {
	var b bytes.Buffer
	line := func(s string) { fmt.Fprintf(&b, "%04x%s\n", len(s)+5, s) }
	line("command=fetch")
	line("object-format=" + objectFormat)
	b.WriteString("0001")
	line("no-progress")
	line("deepen 1")
	line("filter tree:0")
	for _, w := range wants {
		line("want " + w)
	}
	line("done")
	b.WriteString("0000")
	return b.Bytes()
}

// budgetReader fails with ErrFetchTooLarge once left bytes were consumed and more are needed.
type budgetReader struct {
	r    io.Reader
	left int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, ErrFetchTooLarge
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}

// pktKind is the type of a v2 packet.
type pktKind int

const (
	pktData pktKind = iota
	pktFlush
	pktDelim
	pktResponseEnd
)

type pktReader struct {
	ctx context.Context
	r   *bufio.Reader
}

// next reads one pkt-line of protocol v2. A stream that ends anywhere, even between packets, is an error: every
// section this client reads is terminated by a flush or a delimiter.
func (p *pktReader) next() (pktKind, []byte, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		return 0, nil, readErr(err)
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: bad packet length", ErrProtocol)
	}
	switch {
	case n == 0:
		return pktFlush, nil, nil
	case n == 1:
		return pktDelim, nil, nil
	case n == 2:
		return pktResponseEnd, nil, nil
	case n < 4 || n > maxPktLen:
		return 0, nil, fmt.Errorf("%w: bad packet length", ErrProtocol)
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(p.r, payload); err != nil {
		return 0, nil, readErr(err)
	}
	return pktData, payload, nil
}

// readErr turns a short read into a protocol error and keeps every other error (the byte limit, a closed stream).
func readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: stream ended early", ErrProtocol)
	}
	return err
}

// checkAdvertisement reads the capability advertisement up to its flush and checks that the host can serve the
// request.
func (p *pktReader) checkAdvertisement(objectFormat string) error {
	var first = true
	var fetchFeatures []string
	haveFetch, haveFormat := false, false
	format := "sha1" // git's default when the host does not advertise object-format
	for i := 0; ; i++ {
		kind, payload, err := p.next()
		if err != nil {
			return err
		}
		if kind != pktData {
			if first || kind != pktFlush {
				return fmt.Errorf("%w: unexpected packet in advertisement", ErrProtocol)
			}
			break
		}
		if i >= maxAdvertLines {
			return fmt.Errorf("%w: advertisement too long", ErrProtocol)
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if first {
			first = false
			if line != "version 2" {
				return fmt.Errorf("%w: host did not answer with protocol version 2", ErrUnsupported)
			}
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "fetch":
			if haveFetch {
				return fmt.Errorf("%w: duplicate fetch line in advertisement", ErrProtocol)
			}
			haveFetch = true
			fetchFeatures = strings.Fields(value)
		case "object-format":
			if haveFormat {
				return fmt.Errorf("%w: duplicate object-format line in advertisement", ErrProtocol)
			}
			haveFormat = true
			format = value
		}
	}
	if !haveFetch {
		return fmt.Errorf("%w: no fetch command", ErrUnsupported)
	}
	for _, need := range []string{"shallow", "filter"} {
		if !containsString(fetchFeatures, need) {
			return fmt.Errorf("%w: fetch lacks %s", ErrUnsupported, need)
		}
	}
	if format != objectFormat {
		return fmt.Errorf("%w: host object format %q, push uses %q", ErrUnsupported, format, objectFormat)
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// readPack reads the fetch response: an optional shallow-info section, then the packfile section on sideband 1.
// Sideband 2 is dropped; sideband 3 and ERR packets end the fetch.
func (p *pktReader) readPack() ([]byte, error) {
	kind, payload, err := p.next()
	if err != nil {
		return nil, err
	}
	if kind != pktData {
		return nil, fmt.Errorf("%w: empty response", ErrProtocol)
	}
	section := strings.TrimSuffix(string(payload), "\n")
	if isERR(section) {
		return nil, ErrHostRefused
	}
	if section == "shallow-info" {
		if err := p.skipShallowInfo(); err != nil {
			return nil, err
		}
		kind, payload, err = p.next()
		if err != nil {
			return nil, err
		}
		if kind != pktData {
			return nil, fmt.Errorf("%w: no packfile section", ErrProtocol)
		}
		section = strings.TrimSuffix(string(payload), "\n")
		if isERR(section) {
			return nil, ErrHostRefused
		}
	}
	if section != "packfile" {
		return nil, fmt.Errorf("%w: unexpected section %q", ErrProtocol, truncateForError(section))
	}

	var pack []byte
	progress := 0
	for {
		kind, payload, err := p.next()
		if err != nil {
			return nil, err
		}
		switch kind {
		case pktFlush:
			if len(pack) == 0 {
				return nil, fmt.Errorf("%w: empty packfile", ErrProtocol)
			}
			return pack, nil
		case pktDelim, pktResponseEnd:
			return nil, fmt.Errorf("%w: unexpected packet in packfile section", ErrProtocol)
		}
		if len(payload) == 0 {
			return nil, fmt.Errorf("%w: empty sideband packet", ErrProtocol)
		}
		switch payload[0] {
		case 1:
			pack = append(pack, payload[1:]...)
		case 2:
			if progress++; progress > maxSidebandProgress {
				return nil, fmt.Errorf("%w: too much sideband progress", ErrProtocol)
			}
		case 3:
			return nil, ErrHostRefused
		default:
			return nil, fmt.Errorf("%w: unknown sideband %d", ErrProtocol, payload[0])
		}
	}
}

// skipShallowInfo reads "shallow <id>" and "unshallow <id>" lines up to the delimiter, checking only their syntax.
func (p *pktReader) skipShallowInfo() error {
	for i := 0; ; i++ {
		kind, payload, err := p.next()
		if err != nil {
			return err
		}
		switch kind {
		case pktDelim:
			return nil
		case pktFlush, pktResponseEnd:
			return fmt.Errorf("%w: shallow-info not followed by a delimiter", ErrProtocol)
		}
		if i >= maxShallowInfoLines {
			return fmt.Errorf("%w: shallow-info too long", ErrProtocol)
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if isERR(line) {
			return ErrHostRefused
		}
		verb, id, ok := strings.Cut(line, " ")
		if !ok || (verb != "shallow" && verb != "unshallow") || !validObjectID(id) {
			return fmt.Errorf("%w: bad shallow-info line", ErrProtocol)
		}
	}
}

func isERR(line string) bool { return line == "ERR" || strings.HasPrefix(line, "ERR ") }

func truncateForError(s string) string {
	if len(s) > 32 {
		return s[:32]
	}
	return s
}
