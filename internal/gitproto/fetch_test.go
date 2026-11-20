package gitproto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// scriptedHost is the host side of a fetch: it serves canned bytes and records what the client sent.
type scriptedHost struct {
	in     *bytes.Reader
	sent   bytes.Buffer
	closed bool
}

func newScriptedHost(response string) *scriptedHost {
	return &scriptedHost{in: bytes.NewReader([]byte(response))}
}

func (h *scriptedHost) Read(p []byte) (int, error)  { return h.in.Read(p) }
func (h *scriptedHost) Write(p []byte) (int, error) { return h.sent.Write(p) }
func (h *scriptedHost) Close() error                { h.closed = true; return nil }

const (
	fetchWant1 = "3333333333333333333333333333333333333333"
	fetchWant2 = "4444444444444444444444444444444444444444"
)

func advert(fetch, format string) string {
	s := pkt("version 2\n") + pkt("agent=git/2.47.0\n") + pkt("ls-refs=unborn\n") + pkt("fetch="+fetch+"\n")
	if format != "" {
		s += pkt("object-format=" + format + "\n")
	}
	return s + "0000"
}

func band(b byte, data string) string { return pkt(string([]byte{b}) + data) }

const goodAdvert = "shallow wait-for-done filter"

func goodResponse(pack string) string {
	return pkt("shallow-info\n") + pkt("shallow "+fetchWant1+"\n") + "0001" + pkt("packfile\n") +
		band(2, "progress") + band(1, pack[:len(pack)/2]) + band(1, pack[len(pack)/2:]) + "0000"
}

func TestFetchCommits(t *testing.T) {
	const pack = "PACK-binary-\x00\x01\x02-data"
	tests := []struct {
		name     string
		response string
		format   string
		max      int64
		want     string // expected pack; empty when an error is expected
		wantErr  error
		noReq    bool // the request must not have been sent
	}{
		{name: "good response", response: advert(goodAdvert, "sha1") + goodResponse(pack), want: pack},
		{name: "no shallow-info section", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + band(1, pack) + "0000", want: pack},
		{name: "object format defaults to sha1", response: advert(goodAdvert, "") + goodResponse(pack), want: pack},
		{name: "extra features and sideband 2 only noise", response: advert("shallow wait-for-done filter ref-in-want", "sha1") + goodResponse(pack), want: pack},
		{name: "ERR instead of packfile", response: advert(goodAdvert, "sha1") + pkt("ERR upload-pack: not our ref "+fetchWant1+"\n"), wantErr: ErrHostRefused},
		{name: "ERR after shallow-info", response: advert(goodAdvert, "sha1") + pkt("shallow-info\n") + "0001" + pkt("ERR boom\n"), wantErr: ErrHostRefused},
		{name: "sideband 3", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + band(1, "PA") + band(3, "fatal") + "0000", wantErr: ErrHostRefused},
		{name: "EOF before the packfile", response: advert(goodAdvert, "sha1"), wantErr: ErrProtocol},
		{name: "EOF after shallow-info", response: advert(goodAdvert, "sha1") + pkt("shallow-info\n") + "0001", wantErr: ErrProtocol},
		{name: "EOF inside the pack", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + band(1, "PACK"), wantErr: ErrProtocol},
		{name: "flush instead of a response", response: advert(goodAdvert, "sha1") + "0000", wantErr: ErrProtocol},
		{name: "empty packfile", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + band(2, "x") + "0000", wantErr: ErrProtocol},
		{name: "unknown section", response: advert(goodAdvert, "sha1") + pkt("acknowledgments\n") + pkt("NAK\n") + "0000", wantErr: ErrProtocol},
		{name: "bad shallow-info line", response: advert(goodAdvert, "sha1") + pkt("shallow-info\n") + pkt("shallow nothex\n") + "0001", wantErr: ErrProtocol},
		{name: "unknown sideband", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + band(9, "x") + "0000", wantErr: ErrProtocol},
		{name: "empty sideband packet", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + "0005\x01" + pkt("") + "0000", wantErr: ErrProtocol},
		{name: "malformed pkt-line length", response: advert(goodAdvert, "sha1") + "zzzz", wantErr: ErrProtocol},
		{name: "pkt-line length 3", response: advert(goodAdvert, "sha1") + "0003", wantErr: ErrProtocol},
		{name: "pkt-line over the maximum", response: advert(goodAdvert, "sha1") + "fff1", wantErr: ErrProtocol},
		{name: "truncated pkt-line", response: advert(goodAdvert, "sha1") + "0010packfile", wantErr: ErrProtocol},
		{name: "malformed advertisement packet", response: pkt("version 2\n") + "00xx", wantErr: ErrProtocol, noReq: true},
		{name: "oversized response", response: advert(goodAdvert, "sha1") + goodResponse(strings.Repeat("x", 4096)), max: 1024, wantErr: ErrFetchTooLarge},
		{name: "response exactly at the limit", response: advert(goodAdvert, "sha1") + goodResponse(pack), max: int64(len(advert(goodAdvert, "sha1") + goodResponse(pack))), want: pack},
		{name: "one byte over the limit", response: advert(goodAdvert, "sha1") + goodResponse(pack), max: int64(len(advert(goodAdvert, "sha1")+goodResponse(pack))) - 1, wantErr: ErrFetchTooLarge},
		{name: "advertisement too long", response: pkt("version 2\n") + strings.Repeat(pkt("x=1\n"), maxAdvertLines) + "0000", wantErr: ErrProtocol, noReq: true},
		{name: "advertisement at the line limit", response: pkt("version 2\n") + pkt("fetch=shallow filter\n") + strings.Repeat(pkt("x=1\n"), maxAdvertLines-2) + "0000" + goodResponse(pack), want: pack},
		{name: "duplicate fetch line", response: advert(goodAdvert, "sha1")[:len(advert(goodAdvert, "sha1"))-4] + pkt("fetch=shallow filter\n") + "0000", wantErr: ErrProtocol, noReq: true},
		{name: "duplicate object-format line", response: advert(goodAdvert, "sha1")[:len(advert(goodAdvert, "sha1"))-4] + pkt("object-format=sha1\n") + "0000", wantErr: ErrProtocol, noReq: true},
		{name: "too much sideband progress", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + strings.Repeat(band(2, "p"), maxSidebandProgress+1) + band(1, pack) + "0000", wantErr: ErrProtocol},
		{name: "sideband progress at the limit", response: advert(goodAdvert, "sha1") + pkt("packfile\n") + strings.Repeat(band(2, "p"), maxSidebandProgress) + band(1, pack) + "0000", want: pack},
		{name: "shallow-info too long", response: advert(goodAdvert, "sha1") + pkt("shallow-info\n") + strings.Repeat(pkt("shallow "+fetchWant1+"\n"), maxShallowInfoLines+1) + "0001" + pkt("packfile\n") + band(1, pack) + "0000", wantErr: ErrProtocol},
		{name: "shallow-info at the line limit", response: advert(goodAdvert, "sha1") + pkt("shallow-info\n") + strings.Repeat(pkt("shallow "+fetchWant1+"\n"), maxShallowInfoLines) + "0001" + pkt("packfile\n") + band(1, pack) + "0000", want: pack},
		{name: "shallow-info line too long", response: advert(goodAdvert, "sha1") + pkt("shallow-info\n") + "fff1", wantErr: ErrProtocol},
		{name: "missing filter", response: advert("shallow wait-for-done", "sha1"), wantErr: ErrUnsupported, noReq: true},
		{name: "missing shallow", response: advert("filter", "sha1"), wantErr: ErrUnsupported, noReq: true},
		{name: "no fetch command", response: pkt("version 2\n") + pkt("ls-refs\n") + "0000", wantErr: ErrUnsupported, noReq: true},
		{name: "v0 advertisement", response: pkt(fetchWant1+" HEAD\x00multi_ack thin-pack side-band-64k ofs-delta shallow filter\n") + "0000", wantErr: ErrUnsupported, noReq: true},
		{name: "v1 advertisement", response: pkt("version 1\n") + pkt(fetchWant1+" HEAD\x00shallow filter\n") + "0000", wantErr: ErrUnsupported, noReq: true},
		{name: "object format mismatch", response: advert(goodAdvert, "sha256"), wantErr: ErrUnsupported, noReq: true},
		{name: "sha256 requested from sha1 host", response: advert(goodAdvert, "sha1"), format: "sha256", wantErr: ErrUnsupported, noReq: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, wants := tt.format, []string{fetchWant1, fetchWant2}
			if format == "" {
				format = "sha1"
			}
			if format == "sha256" {
				wants = []string{strings.Repeat("a", 64)}
			}
			limit := tt.max
			if limit == 0 {
				limit = 1 << 20
			}
			h := newScriptedHost(tt.response)
			got, err := FetchCommits(context.Background(), h, format, wants, limit)
			if tt.noReq && h.sent.Len() != 0 {
				t.Errorf("request sent after an unusable advertisement: %q", h.sent.String())
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if got != nil {
					t.Errorf("pack returned with error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("pack = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchRequestBytes(t *testing.T) {
	h := newScriptedHost(advert(goodAdvert, "sha1") + goodResponse("PACKdata"))
	// A duplicate want is sent once.
	if _, err := FetchCommits(context.Background(), h, "sha1", []string{fetchWant1, fetchWant2, fetchWant1}, 1<<20); err != nil {
		t.Fatal(err)
	}
	want := pkt("command=fetch\n") + pkt("object-format=sha1\n") + "0001" + pkt("no-progress\n") + pkt("deepen 1\n") +
		pkt("filter tree:0\n") + pkt("want "+fetchWant1+"\n") + pkt("want "+fetchWant2+"\n") + pkt("done\n") + "0000"
	if h.sent.String() != want {
		t.Errorf("request =\n%q\nwant\n%q", h.sent.String(), want)
	}
	for _, banned := range []string{"have", "thin-pack", "ofs-delta", "include-tag", "want-ref", "packfile-uris"} {
		if strings.Contains(h.sent.String(), banned) {
			t.Errorf("request contains %q", banned)
		}
	}
}

func manyWants(n int) []string {
	w := make([]string, n)
	for i := range w {
		w[i] = fmt.Sprintf("%040x", i+1)
	}
	return w
}

func TestFetchCommitsMaxWants(t *testing.T) {
	h := newScriptedHost(advert(goodAdvert, "sha1") + goodResponse("PACKdata"))
	if _, err := FetchCommits(context.Background(), h, "sha1", manyWants(maxWants), 1<<20); err != nil {
		t.Fatalf("%d wants: %v", maxWants, err)
	}
}

func TestFetchCommitsBadInput(t *testing.T) {
	ok := []string{fetchWant1}
	for name, tc := range map[string]struct {
		format string
		wants  []string
		max    int64
	}{
		"unknown format":    {"md5", ok, 1 << 10},
		"no wants":          {"sha1", nil, 1 << 10},
		"too many wants":    {"sha1", manyWants(maxWants + 1), 1 << 10},
		"short id":          {"sha1", []string{"abc"}, 1 << 10},
		"upper case id":     {"sha1", []string{strings.Repeat("A", 40)}, 1 << 10},
		"sha1 id as sha256": {"sha256", ok, 1 << 10},
		"zero limit":        {"sha1", ok, 0},
	} {
		t.Run(name, func(t *testing.T) {
			h := newScriptedHost("")
			if _, err := FetchCommits(context.Background(), h, tc.format, tc.wants, tc.max); err == nil {
				t.Fatal("accepted")
			}
			if h.sent.Len() != 0 {
				t.Errorf("wrote %q", h.sent.String())
			}
		})
	}
}

// hangingHost never answers; Close unblocks its reader like closing an SSH session does.
type hangingHost struct {
	pr     *io.PipeReader
	pw     *io.PipeWriter
	closed chan struct{}
}

func newHangingHost() *hangingHost {
	pr, pw := io.Pipe()
	return &hangingHost{pr: pr, pw: pw, closed: make(chan struct{})}
}

func (h *hangingHost) Read(p []byte) (int, error)  { return h.pr.Read(p) }
func (h *hangingHost) Write(p []byte) (int, error) { return len(p), nil }
func (h *hangingHost) Close() error {
	select {
	case <-h.closed:
	default:
		close(h.closed)
	}
	return h.pw.Close()
}

// closeSignalHost reports Close on a channel.
type closeSignalHost struct {
	*scriptedHost
	closedCh chan struct{}
}

func (h *closeSignalHost) Close() error { close(h.closedCh); return nil }

func TestFetchCommitsContext(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h := newScriptedHost(advert(goodAdvert, "sha1") + goodResponse("PACK"))
		if _, err := FetchCommits(ctx, h, "sha1", []string{fetchWant1}, 1<<20); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
		if h.sent.Len() != 0 {
			t.Error("request sent")
		}
	})
	t.Run("completed fetch leaves rw open", func(t *testing.T) {
		h := newScriptedHost(advert(goodAdvert, "sha1") + goodResponse("PACK"))
		if _, err := FetchCommits(context.Background(), h, "sha1", []string{fetchWant1}, 1<<20); err != nil {
			t.Fatal(err)
		}
		if h.closed {
			t.Error("rw closed after a successful fetch")
		}
	})
	t.Run("cancel after the response was read discards the pack", func(t *testing.T) {
		// Deterministic: the hook cancels ctx after the fetch succeeded and waits for the watcher to close rw,
		// which is the window between fetchCommits returning and FetchCommits taking its lock.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := &closeSignalHost{scriptedHost: newScriptedHost(advert(goodAdvert, "sha1") + goodResponse("PACK")), closedCh: make(chan struct{})}
		afterFetchHook = func() {
			cancel()
			<-h.closedCh
		}
		defer func() { afterFetchHook = nil }()
		pack, err := FetchCommits(ctx, h, "sha1", []string{fetchWant1}, 1<<20)
		if !errors.Is(err, context.Canceled) || pack != nil {
			t.Fatalf("pack %q, err = %v; want nil and context.Canceled", pack, err)
		}
	})
	t.Run("deadline unblocks a silent host", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		h := newHangingHost()
		done := make(chan error, 1)
		go func() {
			_, err := FetchCommits(ctx, h, "sha1", []string{fetchWant1}, 1<<20)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("FetchCommits did not return after the deadline")
		}
		<-h.closed
	})
}

// rwPair joins a process's stdout and stdin.
type rwPair struct {
	io.Reader
	io.Writer
	closers []io.Closer
}

func (p rwPair) Close() error {
	for _, c := range p.closers {
		_ = c.Close()
	}
	return nil
}

func TestFetchCommitsGitUploadPack(t *testing.T) {
	r := newGitRepo(t)
	r.commit("first")
	second := r.commit("second")
	r.commit("third")

	fetch := func(t *testing.T, ctx context.Context, wants ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "git", "-c", "uploadpack.allowFilter=true", "-c", "uploadpack.allowAnySHA1InWant=true",
			"upload-pack", r.dir)
		cmd.Env = append(cmd.Environ(), "GIT_PROTOCOL=version=2", "GIT_CONFIG_NOSYSTEM=1", "HOME="+r.dir)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pack, ferr := FetchCommits(ctx, rwPair{out, in, []io.Closer{in, out}}, "sha1", wants, 1<<20)
		_ = in.Close()
		_ = cmd.Wait()
		if ferr != nil {
			t.Logf("upload-pack stderr: %s", stderr.String())
		}
		return pack, ferr
	}

	t.Run("one commit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		pack, err := fetch(t, ctx, second)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(pack, []byte("PACK")) || !bytes.Equal(pack[8:12], []byte{0, 0, 0, 1}) {
			t.Fatalf("pack is not a single-object pack: % x", pack[:min(len(pack), 16)])
		}
		if g := scan(t, pack); g == nil {
			t.Fatal("no graph")
		}
	})
	t.Run("unknown want", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := fetch(t, ctx, strings.Repeat("9", 40)); !errors.Is(err, ErrHostRefused) {
			t.Fatalf("err = %v", err)
		}
	})
}

func FuzzFetchResponse(f *testing.F) {
	f.Add([]byte("\x00" + advert(goodAdvert, "sha1") + goodResponse("PACKdata")))
	f.Add([]byte("\x00" + advert(goodAdvert, "sha1") + pkt("packfile\n") + band(1, "PACK") + "0000"))
	f.Add([]byte("\x00" + advert(goodAdvert, "sha1") + pkt("ERR not our ref\n")))
	f.Add([]byte("\x00" + advert(goodAdvert, "sha1") + pkt("packfile\n") + band(3, "x")))
	f.Add([]byte("\x00" + pkt(fetchWant1+" HEAD\x00shallow filter\n")))
	f.Add([]byte("\x01" + advert(goodAdvert, "sha256") + goodResponse("PACKdata")))
	f.Add([]byte("\x01" + advert("shallow filter", "sha256") + pkt("packfile\n") + band(1, "PACK") + "0000"))
	f.Add([]byte("\x00" + advert(goodAdvert, "sha1") + pkt("shallow-info\n") + pkt("shallow "+fetchWant1+"\n") + pkt("shallow "+fetchWant2+"\n") +
		pkt("unshallow "+fetchWant2+"\n") + "0001" + pkt("packfile\n") + band(2, "p") + band(1, "PACK") + band(1, "data") + "0000"))
	f.Add([]byte("\x00" + "0001000200030004"))
	f.Add([]byte("\x06" + advert(goodAdvert, "sha1") + goodResponse("PACKdata")))   // 4 wants, sha1
	f.Add([]byte("\x07" + advert(goodAdvert, "sha256") + goodResponse("PACKdata"))) // 4 wants, sha256
	f.Fuzz(func(t *testing.T, b []byte) {
		const limit = 1 << 16
		// The first byte picks the object format and the number of wants (1..4); the rest is the host's output.
		format, idLen, nwants := "sha1", 40, 1
		if len(b) > 0 {
			if b[0]&1 == 1 {
				format, idLen = "sha256", 64
			}
			nwants = 1 + int(b[0]>>1)%4
			b = b[1:]
		}
		wants := make([]string, nwants)
		for i := range wants {
			wants[i] = strings.Repeat(string("0123456789abcdef"[i+1]), idLen)
		}
		h := &scriptedHost{in: bytes.NewReader(b)}
		pack, err := FetchCommits(context.Background(), h, format, wants, limit)
		if err != nil {
			if pack != nil {
				t.Fatal("pack returned with an error")
			}
			return
		}
		if len(pack) == 0 || len(pack) > limit || len(pack) > len(b) {
			t.Fatalf("pack of %d bytes from %d input bytes", len(pack), len(b))
		}
		if !bytes.HasPrefix(h.sent.Bytes(), []byte(pkt("command=fetch\n"))) || bytes.Contains(h.sent.Bytes(), []byte("have ")) ||
			bytes.Count(h.sent.Bytes(), []byte("want ")) != nwants {
			t.Fatalf("bad request %q", h.sent.String())
		}
	})
}
