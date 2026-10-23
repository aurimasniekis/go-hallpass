package credentials

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Signer is the signing abstraction for CAs (HP-KEY-005). Local CAs use sealed keys; external KMS/HSM signers
// implement crypto.Signer and are adapted with ssh.NewSignerFromSigner, which converts ECDSA ASN.1 signatures to
// the SSH wire format. Only Ed25519, ECDSA P-256/384/521 and RSA PKCS#1 v1.5 (SHA-256/512) can produce valid SSH
// signatures; signers offering only other schemes (e.g. RSA-PSS) are incompatible.
type Signer = ssh.Signer

// SignerResolver resolves an external signer reference (e.g. "kms:…") to a crypto.Signer.
type SignerResolver interface {
	Resolve(ctx context.Context, ref string) (crypto.Signer, error)
}

var (
	resolverMu sync.RWMutex
	resolver   SignerResolver
)

// SetSignerResolver installs the resolver for external CA signers (none in v1; review item R-03).
func SetSignerResolver(r SignerResolver) {
	resolverMu.Lock()
	resolver = r
	resolverMu.Unlock()
}

// FromCryptoSigner adapts an external crypto.Signer to an SSH signer.
func FromCryptoSigner(s crypto.Signer) (Signer, error) { return ssh.NewSignerFromSigner(s) }

// UserCA is an OpenSSH user certificate authority (public part).
type UserCA struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	External    bool   `json:"external"`
	State       string `json:"state"`
}

// CreateUserCA generates a sealed Ed25519 user CA.
func (svc *Service) CreateUserCA(ctx context.Context, actor audit.Actor, name string) (*UserCA, error) {
	if !inventory.ValidAlias(name) {
		return nil, apperr.New(apperr.CodeInvalid, "name: %s", inventory.AliasRule)
	}
	priv, pub, err := newEd25519()
	if err != nil {
		return nil, err
	}
	id := ids.New(ids.UserCA)
	sealed, err := svc.seal("user_cas", id, priv)
	if err != nil {
		return nil, err
	}
	err = svc.s.W().TxNamed(ctx, "credentials.create_user_ca", func(tx *store.Tx) error {
		if err := tx.Q.InsertUserCA(ctx, db.InsertUserCAParams{
			ID: id, Name: name, Algorithm: pub.Type(), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
			FingerprintSha256: ssh.FingerprintSHA256(pub), PrivateEnc: sealed, CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), UpdatedAt: tx.NowMicros(),
		}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "a user CA named %q already exists", name)
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "user_ca.created", Target: audit.Target{Type: "user_ca", ID: id},
			Details: map[string]any{"name": name, "fingerprint": ssh.FingerprintSHA256(pub)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	r, err := svc.s.R().GetUserCA(ctx, id)
	if err != nil {
		return nil, err
	}
	return userCAFromRow(r), nil
}

// ListUserCAs returns all user CAs.
func (svc *Service) ListUserCAs(ctx context.Context) ([]*UserCA, error) {
	rows, err := svc.s.R().ListUserCAs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*UserCA, 0, len(rows))
	for _, r := range rows {
		out = append(out, userCAFromRow(r))
	}
	return out, nil
}

func userCAFromRow(r db.UserCa) *UserCA {
	return &UserCA{ID: r.ID, Name: r.Name, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Fingerprint: r.FingerprintSha256,
		External: r.SignerRef.Valid, State: r.State}
}

// CertBinding configures certificate-based login for a role.
type CertBinding struct {
	RoleID     string        `json:"role_id"`
	UserCAID   string        `json:"user_ca_id"`
	Principals []string      `json:"principals"`
	TTL        time.Duration `json:"ttl"`
}

// BindRoleCert makes a role log in with short-lived certificates from caID with explicit principals (HP-KEY-004).
func (svc *Service) BindRoleCert(ctx context.Context, actor audit.Actor, b CertBinding) error {
	if b.TTL == 0 {
		b.TTL = 2 * time.Minute
	}
	v := &apperr.Validation{}
	if b.TTL < 30*time.Second || b.TTL > time.Hour {
		v.Add("ttl", "must be between 30s and 1h; sessions are ended by Hallpass, not by certificate expiry")
	}
	b.Principals = slices.Compact(slices.Sorted(slices.Values(b.Principals)))
	if len(b.Principals) == 0 || len(b.Principals) > 16 {
		v.Add("principals", "1-16 explicit principals are required")
	}
	for _, p := range b.Principals {
		if p == "" || strings.ContainsAny(p, " ,\t\n") || len(p) > 64 {
			v.Add("principals", "invalid principal %q", p)
		}
	}
	if err := v.Err(); err != nil {
		return err
	}
	pj, _ := json.Marshal(b.Principals)
	return svc.s.W().TxNamed(ctx, "credentials.bind_role_cert", func(tx *store.Tx) error {
		if _, err := tx.Q.GetRole(ctx, b.RoleID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "role not found")
		} else if err != nil {
			return err
		}
		if ca, err := tx.Q.GetUserCA(ctx, b.UserCAID); errors.Is(err, sql.ErrNoRows) || (err == nil && ca.State != "active") {
			return apperr.New(apperr.CodeNotFound, "active user CA not found")
		} else if err != nil {
			return err
		}
		if err := tx.Q.UpsertRoleCertBinding(ctx, db.UpsertRoleCertBindingParams{
			RoleID: b.RoleID, UserCaID: b.UserCAID, PrincipalsJson: string(pj), TtlS: int64(b.TTL / time.Second),
			UpdatedAt: tx.NowMicros(), UpdatedBy: actorRef(actor),
		}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "role.cert_binding.set", Target: audit.Target{Type: "role", ID: b.RoleID},
			Details: map[string]any{"user_ca_id": b.UserCAID, "principals": b.Principals, "ttl": b.TTL.String()}})
		svc.publish(tx, b.RoleID)
		return err
	})
}

// UnbindRoleCert returns a role to managed-key login.
func (svc *Service) UnbindRoleCert(ctx context.Context, actor audit.Actor, roleID string) error {
	return svc.s.W().TxNamed(ctx, "credentials.unbind_role_cert", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteRoleCertBinding(ctx, roleID)
		if err != nil || n == 0 {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "role.cert_binding.removed", Target: audit.Target{Type: "role", ID: roleID}})
		svc.publish(tx, roleID)
		return err
	})
}

func (svc *Service) caSigner(ctx context.Context, caID string) (ssh.Signer, error) {
	r, err := svc.s.R().GetUserCA(ctx, caID)
	if err != nil {
		return nil, err
	}
	if r.State != "active" {
		return nil, apperr.New(apperr.CodeUnavailable, "user CA %s is not active", r.Name)
	}
	if len(r.PrivateEnc) > 0 {
		return svc.unseal("user_cas", r.ID, r.PrivateEnc)
	}
	resolverMu.RLock()
	res := resolver
	resolverMu.RUnlock()
	if res == nil {
		return nil, apperr.New(apperr.CodeUnavailable, "external signer %q configured but no signer backend is installed", r.SignerRef.String)
	}
	cs, err := res.Resolve(ctx, r.SignerRef.String)
	if err != nil {
		return nil, err
	}
	return FromCryptoSigner(cs)
}

// issueCert signs a per-connection certificate for an ephemeral key. Principals come only from the binding (never from
// agent input), extensions only from role capabilities, and source-address pins the gateway when configured.
func (svc *Service) issueCert(ctx context.Context, role *inventory.Role, b db.RoleCertBinding, grantID, connID string) (*Auth, error) {
	ca, err := svc.caSigner(ctx, b.UserCaID)
	if err != nil {
		return nil, err
	}
	priv, pub, err := newEd25519()
	if err != nil {
		return nil, err
	}
	var principals []string
	if err := json.Unmarshal([]byte(b.PrincipalsJson), &principals); err != nil || len(principals) == 0 {
		return nil, errors.New("invalid certificate principals")
	}
	now := svc.opts.Clock.Now()
	ext := map[string]string{}
	if role.Has(inventory.CapPTY) {
		ext["permit-pty"] = ""
	}
	crit := map[string]string{}
	if len(svc.opts.SourceAddresses) > 0 {
		crit["source-address"] = strings.Join(svc.opts.SourceAddresses, ",")
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          randomSerial(),
		CertType:        ssh.UserCert,
		KeyId:           "hallpass:" + role.ID + ":" + grantID + ":" + connID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()),                   //nolint:gosec // post-epoch
		ValidBefore:     uint64(now.Add(time.Duration(b.TtlS) * time.Second).Unix()), //nolint:gosec // post-epoch
		Permissions:     ssh.Permissions{CriticalOptions: crit, Extensions: ext},
	}
	if err := cert.SignCert(randReader{}, ca); err != nil {
		return nil, err
	}
	ephemeral, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, err
	}
	cs, err := ssh.NewCertSigner(cert, ephemeral)
	if err != nil {
		return nil, err
	}
	return &Auth{Signers: []ssh.Signer{cs}, CredentialRef: "ca:" + b.UserCaID, Kind: "certificate"}, nil
}
