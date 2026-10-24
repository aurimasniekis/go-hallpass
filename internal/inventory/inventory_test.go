package inventory

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/storetest"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshtest"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func newSvc(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	s := storetest.Open(t)
	kr := keyringtest.Load(t, s)
	g, err := egress.New([]string{"10.0.0.0/8", "127.0.0.0/8"}, []string{"127.0.0.1/32"}, nil, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return New(s, audit.NewWriter(kr), eventbus.New(), Options{Guard: g, MaxGrantDuration: 24 * time.Hour, DialTimeout: 2 * time.Second}), s
}

func ptr[T any](v T) *T { return &v }

func mkServer(t *testing.T, svc *Service, alias, addr string, port int) *Server {
	t.Helper()
	srv, err := svc.CreateServer(context.Background(), admin, ServerInput{Alias: ptr(alias), Address: ptr(addr), Port: ptr(port),
		Description: ptr("web tier"), Groups: ptr([]string{"prod"}), Labels: ptr(map[string]string{"tier": "web"})})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestReservedAliases(t *testing.T) {
	for _, w := range ReservedWords {
		if ValidAlias(w) {
			t.Errorf("reserved word %q accepted", w)
		}
	}
	for _, ok := range []string{"foo-server", "db1", "a"} {
		if !ValidAlias(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"Foo", "1db", "-x", "x-", "a_b", "--", strings.Repeat("a", 64)} {
		if ValidAlias(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestServerLifecycle(t *testing.T) {
	svc, s := newSvc(t)
	ctx := context.Background()
	srv := mkServer(t, svc, "foo-server", "10.0.0.5", 22)
	if !srv.Enabled || srv.Groups[0] != "prod" || srv.Labels["tier"] != "web" || srv.DisplayName != "foo-server" {
		t.Fatalf("%+v", srv)
	}
	if _, err := svc.CreateServer(ctx, admin, ServerInput{Alias: ptr("foo-server"), Address: ptr("10.0.0.6")}); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatal(err)
	}
	for _, in := range []ServerInput{
		{Alias: ptr("list"), Address: ptr("10.0.0.6")},
		{Alias: ptr("meta"), Address: ptr("169.254.169.254")},
		{Alias: ptr("outside"), Address: ptr("192.168.1.1")},
		{Alias: ptr("loopy"), Address: ptr("localhost")},
	} {
		if _, err := svc.CreateServer(ctx, admin, in); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s accepted: %v", *in.Alias, err)
		}
	}
	upd, err := svc.UpdateServer(ctx, admin, srv.ID, ServerInput{Version: srv.Version, Address: ptr("10.0.0.9")})
	if err != nil || upd.Address != "10.0.0.9" || upd.Groups[0] != "prod" {
		t.Fatalf("%+v %v", upd, err)
	}
	if _, err := svc.UpdateServer(ctx, admin, srv.ID, ServerInput{Version: srv.Version, Address: ptr("10.0.0.8")}); !errors.Is(err, apperr.ErrConflict) {
		t.Fatal(err)
	}
	var hooked []string
	svc.OnDisable(func(_ context.Context, _ *store.Tx, kind, id string) error {
		hooked = append(hooked, kind+":"+id)
		return nil
	})
	d, err := svc.SetServerEnabled(ctx, admin, srv.ID, false)
	if err != nil || d.Enabled || len(hooked) != 1 {
		t.Fatalf("%v %v %v", d, err, hooked)
	}
	if res, err := audit.Verify(ctx, s.R()); err != nil || !res.OK || res.Events < 3 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRoleValidationAndDefaults(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	srv := mkServer(t, svc, "db1", "10.0.0.5", 22)
	r, err := svc.CreateRole(ctx, admin, srv.ID, RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("readonly"), Description: ptr("logs")})
	if err != nil {
		t.Fatal(err)
	}
	if r.RecordingMode != "mandatory" || r.RecordInput || !r.Has(CapShell) || r.MaxDuration != 6*time.Hour || len(r.ApprovalChannels) != 3 {
		t.Fatalf("unsafe defaults: %+v", r)
	}
	bad := []RoleInput{
		{Alias: ptr("exec"), RemoteUser: ptr("x")},
		{Alias: ptr("a"), RemoteUser: ptr("Root!")},
		{Alias: ptr("b"), RemoteUser: ptr("x"), Capabilities: ptr([]string{"pty"})},
		{Alias: ptr("c"), RemoteUser: ptr("x"), Capabilities: ptr([]string{"forward"})},
		{Alias: ptr("d"), RemoteUser: ptr("x"), MaxDuration: ptr(48 * time.Hour)},
		{Alias: ptr("e"), RemoteUser: ptr("x"), MaxConcurrent: ptr(1), MaxConcurrentPerAgent: ptr(5)},
		{Alias: ptr("f"), RemoteUser: ptr("x"), EnvAllow: ptr([]string{"BAD=1"})},
		{Alias: ptr("g"), RemoteUser: ptr("x"), ApprovalChannels: ptr([]string{"email"})},
	}
	for i, in := range bad {
		if _, err := svc.CreateRole(ctx, admin, srv.ID, in); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	if _, err := svc.CreateRole(ctx, admin, srv.ID, RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("x")}); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatal(err)
	}
	u, err := svc.UpdateRole(ctx, admin, r.ID, RoleInput{Version: r.Version, Capabilities: ptr([]string{"exec"}), Labels: ptr(map[string]string{"class": "readonly"})})
	if err != nil || u.Has(CapShell) || u.Labels["class"] != "readonly" {
		t.Fatalf("%+v %v", u, err)
	}
	roles, _ := svc.ListRoles(ctx, srv.ID)
	if len(roles) != 1 || roles[0].Labels["class"] != "readonly" {
		t.Fatalf("%+v", roles)
	}
}

// HP-SRV-004/006: explicit enrollment; duplicates across servers need an audited exception.
func TestHostIdentityDuplicates(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	a := mkServer(t, svc, "a", "10.0.0.1", 22)
	b := mkServer(t, svc, "b", "10.0.0.2", 22)
	hk := sshkeys.Ed25519(t)
	line := hk.AuthorizedLine("")
	h, err := svc.AddHostIdentity(ctx, admin, a.ID, "10.0.0.1 "+line)
	if err != nil || h.State != "active" || h.Fingerprint != hk.Fingerprint() {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := svc.AddHostIdentity(ctx, admin, b.ID, line); !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("duplicate host key accepted: %v", err)
	}
	if err := svc.AddDuplicateException(ctx, admin, hk.Fingerprint(), b.ID, a.ID, "short"); err == nil {
		t.Fatal("short justification accepted")
	}
	if err := svc.AddDuplicateException(ctx, admin, hk.Fingerprint(), b.ID, a.ID, "VIP fronting identical replicas"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddHostIdentity(ctx, admin, b.ID, line); err != nil {
		t.Fatalf("exception not honored: %v", err)
	}
	if _, err := svc.AddHostIdentity(ctx, admin, a.ID, "garbage"); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatal(err)
	}
	r, err := svc.RetireHostIdentity(ctx, admin, h.ID)
	if err != nil || r.State != "retired" {
		t.Fatal(err)
	}
}

// HP-SSH-011, HP-SRV-005: strict verification, changed keys rejected, no identity → no trust.
func TestVerifier(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	srv := mkServer(t, svc, "a", "10.0.0.1", 22)
	if _, err := svc.NewVerifier(ctx, srv.ID); err == nil {
		t.Fatal("server without identities must not be trusted")
	}
	hk, other := sshkeys.Ed25519(t), sshkeys.ECDSA256(t)
	if _, err := svc.AddHostIdentity(ctx, admin, srv.ID, hk.AuthorizedLine("")); err != nil {
		t.Fatal(err)
	}
	v, err := svc.NewVerifier(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22}
	if err := v.Callback("x", addr, hk.Public); err != nil {
		t.Fatal(err)
	}
	var he *HostKeyError
	if err := v.Callback("x", addr, other.Public); !errors.As(err, &he) || he.Presented != other.Fingerprint() {
		t.Fatalf("changed key accepted: %v", err)
	}
	if len(v.Algorithms) != 1 || v.Algorithms[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("algorithms %v", v.Algorithms)
	}
}

func signHostCert(t *testing.T, ca sshkeys.Key, host sshkeys.Key, principals []string, validFor time.Duration, typ uint32) *ssh.Certificate {
	t.Helper()
	now := time.Now()
	c := &ssh.Certificate{Key: host.Public, CertType: typ, ValidPrincipals: principals,
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(validFor).Unix())}
	if err := c.SignCert(rand.Reader, ca.Signer); err != nil {
		t.Fatal(err)
	}
	return c
}

// HP-SRV-007: host CA with explicit principal binding.
func TestHostCAVerification(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	srv := mkServer(t, svc, "a", "10.0.0.1", 22)
	ca, rogue, host := sshkeys.Ed25519(t), sshkeys.Ed25519(t), sshkeys.Ed25519(t)
	hca, err := svc.CreateHostCA(ctx, admin, "corp-hosts", ca.AuthorizedLine(""), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.BindHostCA(ctx, admin, srv.ID, hca.ID, nil); err == nil {
		t.Fatal("binding without principals accepted")
	}
	if err := svc.BindHostCA(ctx, admin, srv.ID, hca.ID, []string{"a.prod.example"}); err != nil {
		t.Fatal(err)
	}
	v, err := svc.NewVerifier(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22}
	good := signHostCert(t, ca, host, []string{"a.prod.example"}, 24*time.Hour, ssh.HostCert)
	if err := v.Callback("x", addr, good); err != nil {
		t.Fatalf("valid host cert rejected: %v", err)
	}
	for name, c := range map[string]*ssh.Certificate{
		"wrong principal": signHostCert(t, ca, host, []string{"b.prod.example"}, 24*time.Hour, ssh.HostCert),
		"rogue CA":        signHostCert(t, rogue, host, []string{"a.prod.example"}, 24*time.Hour, ssh.HostCert),
		"user cert":       signHostCert(t, ca, host, []string{"a.prod.example"}, 24*time.Hour, ssh.UserCert),
		"too long":        signHostCert(t, ca, host, []string{"a.prod.example"}, 90*24*time.Hour, ssh.HostCert),
	} {
		if err := v.Callback("x", addr, c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := v.Callback("x", addr, host.Public); err == nil {
		t.Fatal("plain key accepted without enrolled identity")
	}
}

// HP-SRV-004: scan records pending identities that require confirmation.
func TestScanAndConfirm(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	dest := sshtest.Start(t, sshkeys.Ed25519(t), sshkeys.ECDSA256(t))
	host, port := dest.Addr()
	srv := mkServer(t, svc, "dest", host, port)
	ids, err := svc.ScanHostKeys(ctx, admin, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0].State != "pending" || ids[0].EnrolledVia != "scan" {
		t.Fatalf("%+v", ids)
	}
	if _, err := svc.NewVerifier(ctx, srv.ID); err == nil {
		t.Fatal("pending identities must not be trusted")
	}
	if _, err := svc.ConfirmHostIdentity(ctx, admin, ids[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmHostIdentity(ctx, admin, ids[0].ID); !errors.Is(err, apperr.ErrPrecondition) {
		t.Fatal(err)
	}
	if v, err := svc.NewVerifier(ctx, srv.ID); err != nil || len(v.Algorithms) != 1 {
		t.Fatalf("%v %v", v, err)
	}
	// The list counts active identities like the detail does (the console's server and git lists show it).
	list, err := svc.ListServers(ctx)
	if err != nil || len(list) != 1 || list[0].ActiveHostID != 1 {
		t.Fatalf("listed active host identities: %+v %v", list, err)
	}
}

// A retired host key can be enrolled again, with the same operator step as the first time: a scan offers it as
// pending, a paste trusts it.
func TestReenrollRetiredHostKey(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	hostKey := sshkeys.Ed25519(t)
	dest := sshtest.Start(t, hostKey)
	host, port := dest.Addr()
	srv := mkServer(t, svc, "dest", host, port)
	scanned, err := svc.ScanHostKeys(ctx, admin, srv.ID)
	if err != nil || len(scanned) != 1 {
		t.Fatalf("%+v %v", scanned, err)
	}
	id := scanned[0].ID
	if _, err := svc.ConfirmHostIdentity(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RetireHostIdentity(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	rescanned, err := svc.ScanHostKeys(ctx, admin, srv.ID)
	if err != nil || len(rescanned) != 1 || rescanned[0].ID != id || rescanned[0].State != "pending" {
		t.Fatalf("rescan of a retired key: %+v %v", rescanned, err)
	}
	if _, err := svc.NewVerifier(ctx, srv.ID); err == nil {
		t.Fatal("a re-scanned key must not be trusted before confirmation")
	}
	if _, err := svc.ConfirmHostIdentity(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RetireHostIdentity(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(hostKey.Public))
	pasted, err := svc.AddHostIdentity(ctx, admin, srv.ID, line)
	if err != nil || pasted.ID != id || pasted.State != "active" || pasted.EnrolledVia != "paste" {
		t.Fatalf("paste of a retired key: %+v %v", pasted, err)
	}
	if _, err := svc.AddHostIdentity(ctx, admin, srv.ID, line); !errors.Is(err, apperr.ErrAlreadyExists) {
		t.Fatalf("paste of an active key: %v", err)
	}
}

// Deleted servers and roles disappear from lists, keep their former name for history, refuse changes and free
// their alias.
func TestSoftDelete(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	srv := mkServer(t, svc, "web1", "10.0.0.5", 22)
	role, err := svc.CreateRole(ctx, admin, srv.ID, RoleInput{Alias: ptr("deploy"), RemoteUser: ptr("deploy")})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteRole(ctx, admin, role.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteRole(ctx, admin, role.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	got, err := svc.GetRole(ctx, role.ID)
	if err != nil || !got.Deleted() || got.Alias != "deploy" || got.Enabled {
		t.Fatalf("deleted role: %+v %v", got, err)
	}
	if list, _ := svc.ListRoles(ctx, srv.ID); len(list) != 0 {
		t.Fatalf("deleted role listed: %+v", list)
	}
	if _, err := svc.UpdateRole(ctx, admin, role.ID, RoleInput{Version: got.Version, Description: ptr("x")}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update of a deleted role: %v", err)
	}
	if _, err := svc.SetRoleEnabled(ctx, admin, role.ID, true); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("enabling a deleted role: %v", err)
	}
	if _, err := svc.CreateRole(ctx, admin, srv.ID, RoleInput{Alias: ptr("deploy"), RemoteUser: ptr("deploy")}); err != nil {
		t.Fatalf("alias of a deleted role is not reusable: %v", err)
	}

	if err := svc.DeleteServer(ctx, admin, srv.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.ListServers(ctx); len(list) != 0 {
		t.Fatalf("deleted server listed: %+v", list)
	}
	all, err := svc.ListServersWithDeleted(ctx)
	if err != nil || len(all) != 1 || !all[0].Deleted() || all[0].Alias != "web1" {
		t.Fatalf("with deleted: %+v %v", all, err)
	}
	if _, err := svc.CreateRole(ctx, admin, srv.ID, RoleInput{Alias: ptr("x"), RemoteUser: ptr("x")}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("role on a deleted server: %v", err)
	}
	if _, err := svc.SetServerEnabled(ctx, admin, srv.ID, true); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("enabling a deleted server: %v", err)
	}
	mkServer(t, svc, "web1", "10.0.0.6", 22) // the alias is free again
}

// A failed scan says why, so an operator can tell an egress denial from an unreachable server.
func TestScanFailureReason(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	srv := mkServer(t, svc, "closed", "127.0.0.1", port)
	if _, err := svc.ScanHostKeys(ctx, admin, srv.ID); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("closed port: %v", err)
	}
	narrow, err := egress.New([]string{"10.0.0.0/8"}, nil, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	svc.opts.Guard = narrow
	if _, err := svc.ScanHostKeys(ctx, admin, srv.ID); err == nil || !strings.Contains(err.Error(), "egress.allow_cidrs") {
		t.Fatalf("egress denial: %v", err)
	}
}

// Git remotes: access profiles use only git capabilities and need repository patterns; push needs ref rules; the
// kind is fixed at creation; SSH roles cannot carry git rules.
func TestGitRemoteProfiles(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	git, err := svc.CreateServer(ctx, admin, ServerInput{Kind: ptr(KindGit), Alias: ptr("github"), Address: ptr("10.0.0.40"), Port: ptr(22)})
	if err != nil {
		t.Fatal(err)
	}
	if git.Kind != KindGit {
		t.Fatalf("kind = %q", git.Kind)
	}
	ssh := mkServer(t, svc, "web1", "10.0.0.41", 22)
	if ssh.Kind != KindSSH {
		t.Fatalf("default kind = %q", ssh.Kind)
	}
	if _, err := svc.UpdateServer(ctx, admin, git.ID, ServerInput{Version: git.Version, Kind: ptr(KindSSH)}); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("kind change accepted: %v", err)
	}
	if _, err := svc.CreateServer(ctx, admin, ServerInput{Kind: ptr("ftp"), Alias: ptr("x"), Address: ptr("10.0.0.42")}); !errors.Is(err, apperr.ErrInvalid) {
		t.Fatalf("unknown kind accepted: %v", err)
	}

	read, err := svc.CreateRole(ctx, admin, git.ID, RoleInput{Alias: ptr("acme-read"), Git: &GitRules{Repos: []string{"acme/*", "platform/{infra,terraform}"}}})
	if err != nil {
		t.Fatal(err)
	}
	if read.RemoteUser != "git" || !read.Has(CapGitRead) || read.Has(CapExec) || read.Git == nil || len(read.Git.Repos) != 2 {
		t.Fatalf("git profile defaults: %+v", read)
	}
	if got, _ := svc.GetRole(ctx, read.ID); got.Git == nil || got.Git.Repos[0] != "acme/*" {
		t.Fatalf("git rules not stored: %+v", got.Git)
	}
	push := &GitRules{Repos: []string{"acme/api"}, Push: gitproto.RefRules{Branches: []string{"agent/**"}, ProtectedBranches: []string{"main"}}}
	if _, err := svc.CreateRole(ctx, admin, git.ID, RoleInput{Alias: ptr("acme-push"), Capabilities: ptr([]string{CapGitRead, CapGitWrite}), Git: push}); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]RoleInput{
		"no repos":            {Alias: ptr("a1")},
		"empty repos":         {Alias: ptr("a2"), Git: &GitRules{}},
		"bad pattern":         {Alias: ptr("a3"), Git: &GitRules{Repos: []string{"acme/{api"}}},
		"ssh capability":      {Alias: ptr("a4"), Capabilities: ptr([]string{CapExec}), Git: &GitRules{Repos: []string{"x/y"}}},
		"write without refs":  {Alias: ptr("a5"), Capabilities: ptr([]string{CapGitWrite}), Git: &GitRules{Repos: []string{"x/y"}}},
		"push rules no write": {Alias: ptr("a6"), Git: &GitRules{Repos: []string{"x/y"}, Push: gitproto.RefRules{Branches: []string{"a/*"}}}},
		"record input":        {Alias: ptr("a7"), RecordInput: ptr(true), Git: &GitRules{Repos: []string{"x/y"}}},
		"file transfer":       {Alias: ptr("a8"), Capabilities: ptr([]string{CapGitRead, CapFileTransfer}), Git: &GitRules{Repos: []string{"x/y"}}},
	} {
		if _, err := svc.CreateRole(ctx, admin, git.ID, in); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	for name, in := range map[string]RoleInput{
		"git capability on ssh": {Alias: ptr("b1"), RemoteUser: ptr("deploy"), Capabilities: ptr([]string{CapGitRead})},
		"git rules on ssh":      {Alias: ptr("b2"), RemoteUser: ptr("deploy"), Git: &GitRules{Repos: []string{"x/y"}}},
	} {
		if _, err := svc.CreateRole(ctx, admin, ssh.ID, in); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if r, err := svc.CreateRole(ctx, admin, ssh.ID, RoleInput{Alias: ptr("files"), RemoteUser: ptr("deploy"),
		Capabilities: ptr([]string{CapFileTransfer})}); err != nil || !r.Has(CapFileTransfer) || r.Has(CapExec) {
		t.Fatalf("file-transfer only role: %+v %v", r, err)
	}
	upd, err := svc.UpdateRole(ctx, admin, read.ID, RoleInput{Version: read.Version, Git: &GitRules{Repos: []string{"acme/api"}}})
	if err != nil || len(upd.Git.Repos) != 1 {
		t.Fatalf("update git rules: %+v %v", upd, err)
	}
}
