package credentials

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/destssh"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshtest"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

type env struct {
	svc   *Service
	inv   *inventory.Service
	dest  *sshtest.Server
	role  *inventory.Role
	srv   *inventory.Server
	guard *egress.Guard
	clk   *clock.Fake
}

func ptr[T any](v T) *T { return &v }

func setup(t *testing.T) *env {
	t.Helper()
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	aw := audit.NewWriter(kr)
	bus := eventbus.New()
	g, err := egress.New([]string{"127.0.0.0/8"}, []string{"127.0.0.1/32"}, nil, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Now())
	inv := inventory.New(s, aw, bus, inventory.Options{Guard: g, DialTimeout: 2 * time.Second})
	svc := New(s, kr, aw, bus, inv, Options{Guard: g, SourceAddresses: []string{"203.0.113.10"}, DialTimeout: 2 * time.Second, Clock: clk})
	dest := sshtest.Start(t)
	host, port := dest.Addr()
	ctx := context.Background()
	srv, err := inv.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr(host), Port: ptr(port)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.AddHostIdentity(ctx, admin, srv.ID, dest.KnownHostsLine(0)); err != nil {
		t.Fatal(err)
	}
	role, err := inv.CreateRole(ctx, admin, srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("readonly")})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, inv: inv, dest: dest, role: role, srv: srv, guard: g, clk: clk}
}

func pubOf(t *testing.T, c *LoginCredential) ssh.PublicKey {
	t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// HP-KEY-001..003: generate → probe (fails until installed) → activate → rotate with overlap → retire.
func TestManagedKeyLifecycle(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c1, err := e.svc.Generate(ctx, admin, e.role.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c1.State != StatePending || c1.Algorithm != ssh.KeyAlgoED25519 || c1.Kind != "managed_key" {
		t.Fatalf("%+v", c1)
	}
	want := `restrict,pty,from="203.0.113.10" ` + c1.PublicKey + " hallpass:web1/inspect"
	if c1.AuthorizedKeysLine != want {
		t.Fatalf("authorized line %q", c1.AuthorizedKeysLine)
	}
	b, _ := json.Marshal(c1)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "private") {
		t.Fatal("credential DTO exposes private material (HP-KEY-007)")
	}
	if _, err := e.svc.Activate(ctx, admin, c1.ID, false); !errors.Is(err, apperr.ErrPrecondition) {
		t.Fatalf("activation without probe: %v", err)
	}
	if _, err := e.svc.Probe(ctx, admin, c1.ID); err == nil {
		t.Fatal("probe succeeded before key installation")
	}
	e.dest.Authorize(pubOf(t, c1))
	if c, err := e.svc.Probe(ctx, admin, c1.ID); err != nil || c.ProbeOKAt == nil {
		t.Fatalf("probe: %v", err)
	}
	if logins := e.dest.Logins(); len(logins) != 1 || logins[0].User != "readonly" {
		t.Fatalf("logins %+v", logins)
	}
	if c, err := e.svc.Activate(ctx, admin, c1.ID, false); err != nil || c.State != StateActive {
		t.Fatal(err)
	}
	auth, err := e.svc.RoleAuth(ctx, e.role.ID, "grt_x", "con_x")
	if err != nil || auth.CredentialRef != c1.ID || auth.Kind != "key" {
		t.Fatalf("%+v %v", auth, err)
	}
	// Rotation: new key activates, old one stays valid (retiring) during the overlap window.
	c2, _ := e.svc.Generate(ctx, admin, e.role.ID)
	e.dest.Authorize(pubOf(t, c2))
	if _, err := e.svc.Probe(ctx, admin, c2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Activate(ctx, admin, c2.ID, false); err != nil {
		t.Fatal(err)
	}
	old, _ := e.svc.Get(ctx, c1.ID)
	if old.State != StateRetiring || old.RetireAfter == nil {
		t.Fatalf("old credential %+v", old)
	}
	if n, _ := e.svc.RetireDue(ctx); n != 0 {
		t.Fatal("retired before the overlap window ended")
	}
	e.clk.Advance(25 * time.Hour)
	if n, err := e.svc.RetireDue(ctx); err != nil || n != 1 {
		t.Fatalf("retire due: %d %v", n, err)
	}
	if r, _ := e.svc.Revoke(ctx, admin, c2.ID, "compromised"); r.State != StateRevoked {
		t.Fatal("revoke failed")
	}
	if _, err := e.svc.RoleAuth(ctx, e.role.ID, "g", "c"); !errors.Is(err, apperr.ErrUnavailable) {
		t.Fatalf("revoked credential still used: %v", err)
	}
}

func TestForceActivationAndImport(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	c, err := e.svc.Import(ctx, admin, e.role.ID, string(pem.EncodeToMemory(block)))
	if err != nil || c.Kind != "imported_key" {
		t.Fatal(err)
	}
	if c, err := e.svc.Activate(ctx, admin, c.ID, true); err != nil || c.State != StateActive {
		t.Fatalf("forced activation: %v", err)
	}
	weak := sshkeys.RSA(t, 2048)
	wb, _ := ssh.MarshalPrivateKey(weak.Private, "")
	if _, err := e.svc.Import(ctx, admin, e.role.ID, string(pem.EncodeToMemory(wb))); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("weak RSA imported: %v", err)
	}
	enc, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	if _, err := e.svc.Import(ctx, admin, e.role.ID, string(pem.EncodeToMemory(enc))); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("encrypted key imported: %v", err)
	}
}

// HP-KEY-004: certificates with explicit principals, short TTL, key ID binding and capability-limited extensions.
func TestUserCertificates(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	ca, err := e.svc.CreateUserCA(ctx, admin, "corp-users")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.BindRoleCert(ctx, admin, CertBinding{RoleID: e.role.ID, UserCAID: ca.ID, Principals: []string{"readonly-inspect"}}); err != nil {
		t.Fatal(err)
	}
	auth, err := e.svc.RoleAuth(ctx, e.role.ID, "grt_1", "con_1")
	if err != nil || auth.Kind != "certificate" {
		t.Fatal(err)
	}
	cert := auth.Signers[0].PublicKey().(*ssh.Certificate)
	ttl := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)) //nolint:gosec // test
	if cert.KeyId != "hallpass:"+e.role.ID+":grt_1:con_1" || cert.ValidPrincipals[0] != "readonly-inspect" || ttl > 3*time.Minute ||
		cert.CertType != ssh.UserCert {
		t.Fatalf("cert %+v ttl %s", cert, ttl)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Fatal("pty capability not reflected")
	}
	for _, forbidden := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc"} {
		if _, ok := cert.Extensions[forbidden]; ok {
			t.Fatalf("certificate grants %s", forbidden)
		}
	}
	if cert.CriticalOptions["source-address"] != "203.0.113.10" {
		t.Fatalf("source-address %q", cert.CriticalOptions["source-address"])
	}
	caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	e.dest.TrustUserCA(caPub, map[string][]string{"readonly": {"readonly-inspect"}})
	ver, err := e.inv.NewVerifier(ctx, e.srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	// source-address critical option would reject 127.0.0.1, so issue without it for the live login check.
	e.svc.opts.SourceAddresses = nil
	auth, _ = e.svc.RoleAuth(ctx, e.role.ID, "grt_2", "con_2")
	client, err := destssh.Dial(ctx, e.guard, destssh.Target{Host: e.srv.Address, Port: e.srv.Port, User: "readonly", Verifier: ver, Signers: auth.Signers}, 2*time.Second)
	if err != nil {
		t.Fatalf("certificate login failed: %v", err)
	}
	_ = client.Close()
	if logins := e.dest.Logins(); logins[len(logins)-1].CertKeyID != "hallpass:"+e.role.ID+":grt_2:con_2" {
		t.Fatalf("%+v", logins)
	}
	if err := e.svc.BindRoleCert(ctx, admin, CertBinding{RoleID: e.role.ID, UserCAID: ca.ID, Principals: []string{"x"}, TTL: 2 * time.Hour}); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatal("excessive TTL accepted")
	}
	if err := e.svc.UnbindRoleCert(ctx, admin, e.role.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RoleAuth(ctx, e.role.ID, "g", "c"); !errors.Is(err, apperr.ErrUnavailable) {
		t.Fatal("unbound role still issues certificates")
	}
}

// HP-KEY-005: an external crypto.Signer (stand-in for KMS) works through the adapter.
func TestExternalSignerAdapter(t *testing.T) {
	k := sshkeys.ECDSA256(t)
	s, err := FromCryptoSigner(k.Private)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(rand.Reader, []byte("data"))
	if err != nil || s.PublicKey().Verify([]byte("data"), sig) != nil {
		t.Fatalf("adapter signature invalid: %v", err)
	}
}

func TestDialRequiresVerifier(t *testing.T) {
	e := setup(t)
	_, err := destssh.Dial(context.Background(), e.guard, destssh.Target{Host: "127.0.0.1", Port: 22, Signers: []ssh.Signer{sshkeys.Ed25519(t).Signer}}, time.Second)
	if !errors.Is(err, destssh.ErrNoVerifier) {
		t.Fatal(err)
	}
}

// HP-SSH-011: a changed destination host key aborts before authentication.
func TestHostKeyMismatchBlocksLogin(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	impostor := sshtest.Start(t)
	host, port := impostor.Addr()
	ver, _ := e.inv.NewVerifier(ctx, e.srv.ID)
	k := sshkeys.Ed25519(t)
	impostor.Authorize(k.Public)
	_, err := destssh.Dial(ctx, e.guard, destssh.Target{Host: host, Port: port, User: "x", Verifier: ver, Signers: []ssh.Signer{k.Signer}}, 2*time.Second)
	if _, ok := destssh.IsHostKeyError(err); !ok {
		t.Fatalf("expected host key error, got %v", err)
	}
	if len(impostor.Logins()) != 0 {
		t.Fatal("credential presented to an untrusted host")
	}
}

// HP-SSH-005: gateway host key lifecycle.
func TestGatewayHostKeys(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.svc.EnsureGatewayHostKey(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.EnsureGatewayHostKey(ctx); err != nil {
		t.Fatal(err)
	}
	signers, err := e.svc.GatewayHostSigners(ctx)
	if err != nil || len(signers) != 1 || signers[0].PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("%v %v", signers, err)
	}
	if err := e.svc.StageGatewayHostKey(ctx, admin, ssh.KeyAlgoED25519); err == nil {
		t.Fatal("same-algorithm staging accepted")
	}
	if err := e.svc.StageGatewayHostKey(ctx, admin, ssh.KeyAlgoECDSA256); err != nil {
		t.Fatal(err)
	}
	if s, _ := e.svc.GatewayHostSigners(ctx); len(s) != 2 {
		t.Fatal("staged key not served during rotation")
	}
	if err := e.svc.PromoteGatewayHostKey(ctx, admin); err != nil {
		t.Fatal(err)
	}
	s, _ := e.svc.GatewayHostSigners(ctx)
	if len(s) != 1 || s[0].PublicKey().Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("after promotion: %v", s)
	}
	keys, _ := e.svc.GatewayHostKeys(ctx)
	if len(keys) != 2 {
		t.Fatalf("%+v", keys)
	}
}
