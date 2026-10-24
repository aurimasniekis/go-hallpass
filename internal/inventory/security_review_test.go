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

	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

// SR-12 (HP-POL-008): server, role, group, label and limit changes publish policy.changed (not only
// inventory.changed), so active grants are re-checked within the enforcement bound.
func TestPolicyChangedOnInventoryChanges(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	sub := svc.bus.Subscribe(16, eventbus.TopicPolicyChanged)
	defer sub.Close()
	expect := func(what string) {
		t.Helper()
		select {
		case <-sub.C:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: policy.changed not published", what)
		}
	}
	srv := mkServer(t, svc, "web1", "10.0.0.1", 22)
	expect("create server")
	srv, err := svc.UpdateServer(ctx, admin, srv.ID, ServerInput{Version: srv.Version, Groups: ptr([]string{"staging"})})
	if err != nil {
		t.Fatal(err)
	}
	expect("server group change")
	r, err := svc.CreateRole(ctx, admin, srv.ID, RoleInput{Alias: ptr("ops"), RemoteUser: ptr("ops")})
	if err != nil {
		t.Fatal(err)
	}
	expect("create role")
	if _, err := svc.UpdateRole(ctx, admin, r.ID, RoleInput{Version: r.Version, DefaultDuration: ptr(10 * time.Minute), MaxDuration: ptr(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	expect("role max_duration change")
}

// SR-45 (HP-SSH-004 on the destination leg): RSA host keys and host CAs below 3072 bits are refused at enrollment,
// and host certificates signed with SHA-1 ssh-rsa are rejected.
func TestDestinationAlgorithmFloor(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	srv := mkServer(t, svc, "a", "10.0.0.1", 22)
	if _, err := svc.AddHostIdentity(ctx, admin, srv.ID, sshkeys.RSA(t, 2048).AuthorizedLine("")); err == nil {
		t.Fatal("RSA-2048 host key enrolled")
	}
	if _, err := svc.AddHostIdentity(ctx, admin, srv.ID, sshkeys.RSA(t, 3072).AuthorizedLine("")); err != nil {
		t.Fatalf("RSA-3072 host key refused: %v", err)
	}
	if _, err := svc.CreateHostCA(ctx, admin, "weak", sshkeys.RSA(t, 2048).AuthorizedLine(""), 24*time.Hour); err == nil {
		t.Fatal("RSA-2048 host CA accepted")
	}
	ca, host := sshkeys.RSA(t, 3072), sshkeys.Ed25519(t)
	hca, err := svc.CreateHostCA(ctx, admin, "corp", ca.AuthorizedLine(""), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.BindHostCA(ctx, admin, srv.ID, hca.ID, []string{"a.prod.example"}); err != nil {
		t.Fatal(err)
	}
	v, err := svc.NewVerifier(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22}
	if err := v.Callback("x", addr, signHostCert(t, ca, host, []string{"a.prod.example"}, time.Hour, ssh.HostCert)); err != nil {
		t.Fatalf("rsa-sha2 signed host cert rejected: %v", err)
	}
	sha1CA, err := ssh.NewSignerWithAlgorithms(ca.Signer.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := &ssh.Certificate{Key: host.Public, CertType: ssh.HostCert, ValidPrincipals: []string{"a.prod.example"},
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix())}
	if err := c.SignCert(rand.Reader, sha1CA); err != nil {
		t.Fatal(err)
	}
	if c.Signature.Format != ssh.KeyAlgoRSA {
		t.Fatalf("test cert signed with %s", c.Signature.Format)
	}
	if err := v.Callback("x", addr, c); err == nil {
		t.Fatal("host certificate with a SHA-1 ssh-rsa CA signature accepted")
	}
}

// SR-08: a host certificate rejected for its principals does not put the principals (host names) in the
// audited Reason; they stay in Error() for the gateway log.
func TestHostCertRejectionReasonIsAddressFree(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	srv := mkServer(t, svc, "a", "10.0.0.1", 22)
	ca, host := sshkeys.Ed25519(t), sshkeys.Ed25519(t)
	hca, err := svc.CreateHostCA(ctx, admin, "corp", ca.AuthorizedLine(""), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.BindHostCA(ctx, admin, srv.ID, hca.ID, []string{"a.prod.example"}); err != nil {
		t.Fatal(err)
	}
	v, err := svc.NewVerifier(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Callback("x", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22},
		signHostCert(t, ca, host, []string{"secret-host.internal.example"}, time.Hour, ssh.HostCert))
	var he *HostKeyError
	if !errors.As(err, &he) {
		t.Fatalf("want HostKeyError, got %v", err)
	}
	if strings.Contains(he.Reason, "secret-host") || strings.Contains(he.Reason, "a.prod.example") {
		t.Fatalf("reason names host principals: %q", he.Reason)
	}
	if !strings.Contains(he.Error(), "secret-host") {
		t.Fatalf("log text lost the detail: %q", he.Error())
	}
}
