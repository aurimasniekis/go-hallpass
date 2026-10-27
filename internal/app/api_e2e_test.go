package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/apiproxy"
	"github.com/aurimasniekis/go-hallpass/internal/apirules"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
)

// ADR-0060: an agent reaches the API proxy only through a forward to "hallpass", gets the target CA from "api ca",
// and its HTTPS requests are authorized against its grants (the .invalid host cannot be reached upstream).
func TestGatewayAPIProxyEndToEnd(t *testing.T) {
	g := startGateway(t)
	ctx := context.Background()
	const host = "api.hallpass.invalid"
	srv, err := g.a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("gh"), Kind: ptr(inventory.KindAPI),
		API: &inventory.APITarget{Hosts: []string{host}}})
	must(t, err)
	role, err := g.a.Inventory.CreateRole(ctx, admin, srv.ID, inventory.RoleInput{Alias: ptr("read"),
		API: &inventory.APIRules{Rules: []apirules.Rule{{Effect: apirules.Allow, Methods: []string{"GET"}}}}})
	must(t, err)
	_, err = g.a.APIService.SetCredential(ctx, admin, role.ID, apiproxy.CredentialInput{Type: apiproxy.CredBearer, Secret: "github-pat-123456"})
	must(t, err)

	if out, _, code := g.run("list"); code != 0 || !strings.Contains(out, "gh (api)") {
		t.Fatalf("list: %d %q", code, out)
	}
	bundle, _, code := g.run("api ca")
	if code != 0 || !strings.Contains(bundle, "HallPass API proxy CA for gh") || !strings.Contains(bundle, "BEGIN CERTIFICATE") {
		t.Fatalf("api ca: %d %q", code, bundle)
	}
	if out, _, code := g.run("api env --port 19000"); code != 0 || !strings.Contains(out, "export HTTPS_PROXY=http://127.0.0.1:19000") ||
		!strings.Contains(out, "BEGIN CERTIFICATE") || strings.Contains(out, "github-pat") {
		t.Fatalf("api env: %d %q", code, out)
	}
	if out, _, code := g.run("api env --role read"); code != 0 || !strings.Contains(out, "export HTTPS_PROXY=http://read@127.0.0.1:18080") ||
		!strings.Contains(out, "export CLOUDSDK_PROXY_USERNAME=read") {
		t.Fatalf("api env --role: %d %q", code, out)
	}
	if out, _, code := g.runEnv(map[string]string{"CLAUDE_CODE_SESSION_ID": "conv-1"}, "api env --role read"); code != 0 ||
		!strings.Contains(out, "export HTTPS_PROXY=http://read:conv-1@127.0.0.1:18080") || !strings.Contains(out, "export CLOUDSDK_PROXY_PASSWORD=conv-1") {
		t.Fatalf("api env in a session: %d %q", code, out)
	}
	if out, _, code := g.runEnv(map[string]string{"HALLPASS_SESSION": "conv-2"}, "api env"); code != 0 ||
		!strings.Contains(out, "export HTTPS_PROXY=http://_:conv-2@127.0.0.1:18080") {
		t.Fatalf("api env without a role: %d %q", code, out)
	}
	if _, stderr, code := g.run("connect gh"); code == 0 || !strings.Contains(stderr, "API proxy") {
		t.Fatalf("connect to an API target: %d %q", code, stderr)
	}

	c, err := g.client(g.key)
	must(t, err)
	defer c.Close()
	if _, err := c.Dial("tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("a forward to another host was accepted")
	}

	// CONNECT to a host no visible target covers is refused before TLS.
	conn, err := c.Dial("tcp", apiproxy.Host+":443")
	must(t, err)
	_, _ = io.WriteString(conn, "CONNECT www.example.org:443 HTTP/1.1\r\nHost: www.example.org:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	must(t, err)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT to an unknown host: %d", resp.StatusCode)
	}
	_ = conn.Close()

	// CONNECT to the target, TLS with its CA, then a GET: auto-approved, authorized, forwarded (and failing upstream).
	conn, err = c.Dial("tcp", apiproxy.Host+":443")
	must(t, err)
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err = http.ReadResponse(br, nil)
	must(t, err)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %d", resp.StatusCode)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(bundle))
	tc := tls.Client(&bufConn{Conn: conn, r: br}, &tls.Config{ServerName: host, RootCAs: pool})
	must(t, tc.Handshake())
	_, _ = io.WriteString(tc, "GET /user HTTP/1.1\r\nHost: "+host+"\r\nAuthorization: Bearer fake\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(tc), nil)
	must(t, err)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("X-Hallpass-Error") != "upstream" {
		t.Fatalf("GET: %d %q", resp.StatusCode, resp.Header.Get("X-Hallpass-Error"))
	}
	grants, err := g.a.Access.ActiveGrantsForAgent(ctx, g.agentID(), "")
	must(t, err)
	if len(grants) != 1 || grants[0].RoleID != role.ID {
		t.Fatalf("grants: %+v", grants)
	}
}

func (g *gw) agentID() string {
	g.t.Helper()
	list, err := g.a.Agents.List(context.Background())
	must(g.t, err)
	return list[0].ID
}

// bufConn reads through a bufio.Reader that may hold bytes read past the CONNECT response.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
