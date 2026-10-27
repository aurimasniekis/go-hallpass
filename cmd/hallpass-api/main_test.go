package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/apienv"
)

func TestDisplayCommand(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"gh", "issue", "comment", "42", "--body", "Fixed"}, `gh issue comment 42 --body Fixed`},
		{[]string{"gh", "issue", "comment", "42", "--body", "Fixed in #43, thanks"}, `gh issue comment 42 --body 'Fixed in #43, thanks'`},
		{[]string{"curl", "--token", "abc", "https://x"}, `curl --token [redacted] https://x`},
		{[]string{"tool", "--api-key=abc", "--name=x"}, `tool --api-key=[redacted] --name=x`},
		{[]string{"echo", "it's"}, `echo 'it'\''s'`},
	} {
		if got := displayCommand(c.argv); got != c.want {
			t.Errorf("displayCommand(%q) = %q, want %q", c.argv, got, c.want)
		}
	}
}

func TestChildEnvReplacesProxyAndTokens(t *testing.T) {
	env := childEnv([]string{"PATH=/bin", "https_proxy=http://evil", "GH_TOKEN=real", "Ssl_Cert_File=/x", "HOME=/h"},
		apienv.Vars(1234, "/tmp/ca.pem", "/tmp/token"))
	joined := strings.Join(env, "\n")
	for _, bad := range []string{"http://evil", "GH_TOKEN=real", "/x"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("parent value %q survived:\n%s", bad, joined)
		}
	}
	for _, want := range []string{"PATH=/bin", "HOME=/h", "HTTPS_PROXY=http://127.0.0.1:1234", "SSL_CERT_FILE=/tmp/ca.pem", "GH_TOKEN=hallpass"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q:\n%s", want, joined)
		}
	}
}

// The local proxy adds the hallpass-api headers to the CONNECT and then passes bytes both ways untouched.
func TestLocalProxyTagsConnect(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	got := make(chan *http.Request, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		got <- req
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		line, _ := br.ReadString('\n')
		_, _ = io.WriteString(c, "echo:"+line)
	}()
	lp, err := startLocalProxy(context.Background(), up.Addr().(*net.TCPAddr).Port, map[string]string{
		apienv.HeaderCommand: apienv.Encode("gh issue comment 42"), apienv.HeaderInvocation: "inv-test-invocation-two", apienv.HeaderReason: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lp.Close()
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(lp.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\nhello\n")
	all, _ := io.ReadAll(io.LimitReader(c, 64))
	req := <-got
	if req.Host != "api.github.com:443" || apienv.Decode(req.Header.Get(apienv.HeaderCommand)) != "gh issue comment 42" ||
		req.Header.Get(apienv.HeaderInvocation) != "inv-test-invocation-two" || req.Header.Get(apienv.HeaderReason) != "" {
		t.Fatalf("upstream CONNECT: %s %v", req.Host, req.Header)
	}
	if !bytes.Contains(all, []byte("200 Connection established")) || !bytes.Contains(all, []byte("echo:hello")) {
		t.Fatalf("client saw %q", all)
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"--", "gh"}, nil, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "--gateway") {
		t.Fatalf("missing gateway: %d %q", code, errb.String())
	}
	if code := run(context.Background(), []string{"--gateway", "center"}, nil, &out, &errb); code != exitUsage {
		t.Fatalf("missing command: %d", code)
	}
}
