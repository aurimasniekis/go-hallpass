package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/apiproxy"
	"github.com/aurimasniekis/go-hallpass/internal/apirules"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
)

const wrapperHost = "api.hallpass.test"

type wrapperResolver struct{}

func (wrapperResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == wrapperHost {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// fakeAPI is a TLS server for wrapperHost that records the Authorization header of each request.
func fakeAPI(t *testing.T) (port int, pool *x509.CertPool, seen func() []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: wrapperHost}, DNSNames: []string{wrapperHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	var mu sync.Mutex
	var auth []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	port, _ = strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	return port, pool, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), auth...)
	}
}

// hallpass-api with the system ssh and curl: the first run is refused and files a request that shows the command,
// an operator approves it, and hallpass-api runs curl again, which reaches the API with HallPass's credential.
func TestHallpassAPIWrapperEndToEnd(t *testing.T) {
	for _, tool := range []string{"ssh", "curl", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	port, pool, seen := fakeAPI(t)
	g := startGatewayWith(t, []Option{WithAPIProxyOptions(func(o *apiproxy.Options) {
		o.Guard, _ = egress.NewPublic([]string{"0.0.0.0/0"}, []string{"127.0.0.0/8"}, wrapperResolver{}, 5*time.Second)
		o.RootCAs, o.UpstreamPort = pool, port
	})})
	g.requestable()
	ctx := context.Background()
	opID := "opr_01aaaaaaaaaaaaaaaaaaaaaaaa"
	must(t, g.a.Store.W().Exec(ctx, `INSERT INTO operators (id, email, display_name, enabled, provisioned_via, created_at, created_by, updated_at)
		VALUES (?, 'approver@example.com', 'Approver', 1, 'admin', 1, 'test', 1)`, opID))
	must(t, g.a.Store.W().Exec(ctx, `INSERT INTO operator_roles (operator_id, role, source) VALUES (?, 'approver', 'manual')`, opID))
	_, err := g.a.Policy.CreateApproverRule(ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{opID}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)

	srv, err := g.a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("gh"), Kind: ptr(inventory.KindAPI),
		API: &inventory.APITarget{Hosts: []string{wrapperHost}}})
	must(t, err)
	role, err := g.a.Inventory.CreateRole(ctx, admin, srv.ID, inventory.RoleInput{Alias: ptr("issues"),
		API: &inventory.APIRules{Rules: []apirules.Rule{{Effect: apirules.Allow, Methods: []string{"POST"}, Paths: []string{"/repos/acme/*/issues/*/comments"}}}}})
	must(t, err)
	_, err = g.a.APIService.SetCredential(ctx, admin, role.ID, apiproxy.CredentialInput{Type: apiproxy.CredBearer, Secret: "real-github-token-0001"})
	must(t, err)

	// The agent's ssh setup: its key, the pinned gateway host key and an ssh wrapper with the options.
	dir := t.TempDir()
	blk, err := ssh.MarshalPrivateKey(g.key.Private, "")
	must(t, err)
	keyFile, knownHosts, sshScript := filepath.Join(dir, "key"), filepath.Join(dir, "known_hosts"), filepath.Join(dir, "ssh")
	must(t, os.WriteFile(keyFile, pem.EncodeToMemory(blk), 0o600))
	host, gwPort, _ := net.SplitHostPort(g.addr)
	must(t, os.WriteFile(knownHosts, fmt.Appendf(nil, "[%s]:%s %s\n", host, gwPort, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(g.hostPK)))), 0o600))
	// The ssh config the agent docs give, including ClearAllForwardings yes (the tunnel must override it) and SendEnv.
	sshConfig := filepath.Join(dir, "config")
	must(t, os.WriteFile(sshConfig, fmt.Appendf(nil, `Host center
  HostName %s
  Port %s
  User agent
  IdentityFile %s
  IdentitiesOnly yes
  UserKnownHostsFile %s
  StrictHostKeyChecking yes
  ForwardAgent no
  ClearAllForwardings yes
  ServerAliveInterval 30
  SendEnv CLAUDE_CODE_SESSION_ID HALLPASS_SESSION
`, host, gwPort, keyFile, knownHosts), 0o600))
	must(t, os.WriteFile(sshScript, fmt.Appendf(nil, "#!/bin/sh\nexec ssh -F %s \"$@\"\n", sshConfig), 0o700))
	bin := filepath.Join(dir, "hallpass-api")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/hallpass-api").CombinedOutput(); err != nil {
		t.Fatalf("build hallpass-api: %v\n%s", err, out)
	}

	// Approve the request the proxy files, once it appears.
	approved := make(chan string, 1)
	go func() {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			var id string
			if g.a.Store.ReadDB().QueryRowContext(ctx, `SELECT id FROM access_requests WHERE state = 'pending' AND role_id = ?`, role.ID).Scan(&id) != nil {
				continue
			}
			reason, _ := g.a.Access.Reason(ctx, id)
			if r, err := g.a.Access.GetRequest(ctx, id); err == nil {
				reason += " [session " + r.AgentSession + "]"
			}
			_, _ = g.a.Access.Decide(ctx, access.DecideInput{RequestID: id, Approve: true, Operator: policy.OperatorInfo{ID: opID,
				Roles: []string{"approver"}, Enabled: true}, Channel: access.ChannelWeb})
			approved <- reason
			return
		}
		close(approved)
	}()

	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "--gateway", "center", "--ssh", sshScript, "--role", "issues", "--reason", "Answer the customer on #42",
		"--wait", "1m", "--", "curl", "-sS", "-f", "-X", "POST", "-H", "Authorization: Bearer agent-own-token",
		"https://"+wrapperHost+"/repos/acme/api/issues/42/comments", "-d", `{"body":"Fixed"}`)
	cmd.Env = append(os.Environ(), "CLAUDE_CODE_SESSION_ID=0a1b2c3d-1111-4222-8333-444455556666")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	if err != nil {
		t.Fatalf("hallpass-api: %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}
	reason := <-approved
	if !strings.Contains(reason, "Answer the customer on #42 | Command (reported by the agent): curl -sS -f -X POST") ||
		!strings.HasSuffix(reason, "[session 0a1b2c3d-1111-4222-8333-444455556666]") ||
		!strings.Contains(reason, "/repos/acme/api/issues/42/comments") {
		t.Fatalf("request reason %q", reason)
	}
	if !strings.Contains(out.String(), `"ok":true`) || !strings.Contains(errb.String(), "needs approval") {
		t.Fatalf("stdout %q stderr %q", out.String(), errb.String())
	}
	got := seen()
	if len(got) != 1 || got[0] != "POST /repos/acme/api/issues/42/comments Bearer real-github-token-0001" {
		t.Fatalf("the API saw %q", got)
	}
}
