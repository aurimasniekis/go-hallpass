// Package credentials manages gateway-held destination login credentials, OpenSSH user CAs and the gateway's own
// SSH host keys (HP-KEY-*, ADR-0006). Private keys are generated inside HallPass, sealed with the keyring's
// credential key, never exported, and never sent to agents.
package credentials

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/destssh"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Credential states.
const (
	StatePending  = "pending"
	StateActive   = "active"
	StateRetiring = "retiring"
	StateRetired  = "retired"
	StateRevoked  = "revoked"
)

// ProbeFreshness is how recent a successful probe must be to activate a credential without force.
const ProbeFreshness = 24 * time.Hour

// Options configure the service.
type Options struct {
	Guard           *egress.Guard
	SourceAddresses []string      // gateway egress addresses for from= and source-address restrictions
	Overlap         time.Duration // how long a replaced credential stays valid (default 24h)
	DialTimeout     time.Duration
	Clock           clock.Clock
}

// Service manages credentials.
type Service struct {
	s     *store.Store
	kr    *keyring.Keyring
	audit *audit.Writer
	bus   *eventbus.Bus
	inv   *inventory.Service
	opts  Options
}

// New returns a credentials service.
func New(s *store.Store, kr *keyring.Keyring, aw *audit.Writer, bus *eventbus.Bus, inv *inventory.Service, o Options) *Service {
	if o.Overlap <= 0 {
		o.Overlap = 24 * time.Hour
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	return &Service{s: s, kr: kr, audit: aw, bus: bus, inv: inv, opts: o}
}

// LoginCredential is a destination login key (public part only).
type LoginCredential struct {
	ID                 string     `json:"id"`
	RoleID             string     `json:"role_id"`
	Kind               string     `json:"kind"`
	Algorithm          string     `json:"algorithm"`
	PublicKey          string     `json:"public_key"`
	Fingerprint        string     `json:"fingerprint"`
	State              string     `json:"state"`
	ProbeOKAt          *time.Time `json:"probe_ok_at,omitempty"`
	ProbeError         string     `json:"probe_error,omitempty"`
	ActivatedAt        *time.Time `json:"activated_at,omitempty"`
	RetireAfter        *time.Time `json:"retire_after,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	CreatedBy          string     `json:"created_by"`
	AuthorizedKeysLine string     `json:"authorized_keys_line"`
}

func sealAAD(table, id string) []byte { return keyring.FieldAAD(table, "private_enc", id) }

func (svc *Service) seal(table, id string, priv crypto.Signer) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	return svc.kr.Seal(keyring.PurposeCredential, sealAAD(table, id), pem.EncodeToMemory(block))
}

func (svc *Service) unseal(table, id string, sealed []byte) (ssh.Signer, error) {
	pemBytes, err := svc.kr.Open(keyring.PurposeCredential, sealAAD(table, id), sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal %s %s: %w", table, id, err)
	}
	return ssh.ParsePrivateKey(pemBytes)
}

func newEd25519() (ed25519.PrivateKey, ssh.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	spk, err := ssh.NewPublicKey(pub)
	return priv, spk, err
}

// Generate creates a pending managed Ed25519 login key for a role (HP-KEY-001).
func (svc *Service) Generate(ctx context.Context, actor audit.Actor, roleID string) (*LoginCredential, error) {
	priv, pub, err := newEd25519()
	if err != nil {
		return nil, err
	}
	return svc.insert(ctx, actor, roleID, "managed_key", priv, pub)
}

// Import stores an existing unencrypted OpenSSH/PEM private key as a pending credential, flagged as imported.
// Imported keys are never re-exported (HP-KEY-007).
func (svc *Service) Import(ctx context.Context, actor audit.Actor, roleID, pemData string) (*LoginCredential, error) {
	raw, err := ssh.ParseRawPrivateKey([]byte(pemData))
	if err != nil {
		var pme *ssh.PassphraseMissingError
		if errors.As(err, &pme) {
			return nil, apperr.New(apperr.CodeInvalid, "encrypted private keys are not supported; decrypt it locally first")
		}
		return nil, apperr.New(apperr.CodeInvalid, "not a valid private key")
	}
	var signer crypto.Signer
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		signer = *k
	case ed25519.PrivateKey:
		signer = k
	case *ecdsa.PrivateKey:
		signer = k
	case *rsa.PrivateKey:
		if k.N.BitLen() < 3072 {
			return nil, apperr.New(apperr.CodeInvalid, "RSA keys must be at least 3072 bits")
		}
		signer = k
	default:
		return nil, apperr.New(apperr.CodeInvalid, "unsupported private key type")
	}
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	return svc.insert(ctx, actor, roleID, "imported_key", signer, pub)
}

func (svc *Service) insert(ctx context.Context, actor audit.Actor, roleID, kind string, priv crypto.Signer, pub ssh.PublicKey) (*LoginCredential, error) {
	id := ids.New(ids.Credential)
	sealed, err := svc.seal("login_credentials", id, priv)
	if err != nil {
		return nil, err
	}
	fp := ssh.FingerprintSHA256(pub)
	err = svc.s.W().TxNamed(ctx, "credentials.insert", func(tx *store.Tx) error {
		if r, err := tx.Q.GetRole(ctx, roleID); errors.Is(err, sql.ErrNoRows) || (err == nil && r.DeletedAt.Valid) {
			return apperr.New(apperr.CodeNotFound, "role not found")
		} else if err != nil {
			return err
		}
		if err := tx.Q.InsertLoginCredential(ctx, db.InsertLoginCredentialParams{
			ID: id, RoleID: roleID, Kind: kind, Algorithm: pub.Type(), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
			FingerprintSha256: fp, PrivateEnc: sealed, CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), UpdatedAt: tx.NowMicros(),
		}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeAlreadyExists, "this key is already used as a login credential")
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "credential.created", Target: audit.Target{Type: "role", ID: roleID},
			Details: map[string]any{"credential_id": id, "kind": kind, "fingerprint": fp, "algorithm": pub.Type()}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// Get returns a credential with its suggested authorized_keys line.
func (svc *Service) Get(ctx context.Context, id string) (*LoginCredential, error) {
	r, err := svc.s.R().GetLoginCredential(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "credential not found")
	}
	if err != nil {
		return nil, err
	}
	return svc.decorate(ctx, r)
}

// List returns all credentials of a role.
func (svc *Service) List(ctx context.Context, roleID string) ([]*LoginCredential, error) {
	rows, err := svc.s.R().ListLoginCredentials(ctx, roleID)
	if err != nil {
		return nil, err
	}
	out := make([]*LoginCredential, 0, len(rows))
	for _, r := range rows {
		c, err := svc.decorate(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (svc *Service) decorate(ctx context.Context, r db.LoginCredential) (*LoginCredential, error) {
	c := credFromRow(r)
	role, err := svc.inv.GetRole(ctx, r.RoleID)
	if err != nil {
		return nil, err
	}
	srv, err := svc.inv.GetServer(ctx, role.ServerID)
	if err != nil {
		return nil, err
	}
	c.AuthorizedKeysLine = AuthorizedKeysLine(c.PublicKey, role, srv.Alias, svc.opts.SourceAddresses)
	return c, nil
}

// AuthorizedKeysLine renders the suggested destination authorized_keys entry for a login key (HP-KEY-002):
// "restrict" disables forwarding and PTY; PTY is re-enabled only when the role grants it; from= limits the source.
func AuthorizedKeysLine(publicKey string, role *inventory.Role, serverAlias string, sources []string) string {
	opts := []string{"restrict"}
	if role.Has(inventory.CapPTY) {
		opts = append(opts, "pty")
	}
	if len(sources) > 0 {
		opts = append(opts, `from="`+strings.Join(sources, ",")+`"`)
	}
	return strings.Join(opts, ",") + " " + publicKey + " hallpass:" + serverAlias + "/" + role.Alias
}

// Probe connects to the destination with a credential (verifying the host key) and disconnects without running
// anything, recording the outcome (HP-KEY-003).
func (svc *Service) Probe(ctx context.Context, actor audit.Actor, id string) (*LoginCredential, error) {
	r, err := svc.s.R().GetLoginCredential(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "credential not found")
	} else if err != nil {
		return nil, err
	}
	if r.State == StateRevoked || r.State == StateRetired {
		return nil, apperr.New(apperr.CodePrecondition, "credential is %s", r.State)
	}
	signer, err := svc.unseal("login_credentials", id, r.PrivateEnc)
	if err != nil {
		return nil, err
	}
	probeErr := svc.probe(ctx, r.RoleID, signer)
	msg := sql.NullString{}
	if probeErr != nil {
		msg = sql.NullString{String: truncate(probeErr.Error(), 500), Valid: true}
	}
	err = svc.s.W().TxNamed(ctx, "credentials.probe", func(tx *store.Tx) error {
		ok := sql.NullInt64{}
		if probeErr == nil {
			ok = sql.NullInt64{Int64: tx.NowMicros(), Valid: true}
		}
		if err := tx.Q.RecordProbe(ctx, db.RecordProbeParams{ProbeOkAt: ok, ProbeError: msg, UpdatedAt: tx.NowMicros(), ID: id}); err != nil {
			return err
		}
		outcome := audit.OutcomeSuccess
		if probeErr != nil {
			outcome = audit.OutcomeFailure
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "credential.probed", Outcome: outcome,
			Target: audit.Target{Type: "role", ID: r.RoleID}, Details: map[string]any{"credential_id": id, "error": msg.String}})
		return err
	})
	if err != nil {
		return nil, err
	}
	c, err := svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if probeErr != nil {
		return c, apperr.Wrap(apperr.CodePrecondition, probeErr, "probe failed")
	}
	return c, nil
}

func (svc *Service) probe(ctx context.Context, roleID string, signer ssh.Signer) error {
	role, err := svc.inv.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	srv, err := svc.inv.GetServer(ctx, role.ServerID)
	if err != nil {
		return err
	}
	ver, err := svc.inv.NewVerifier(ctx, srv.ID)
	if err != nil {
		return err
	}
	if svc.opts.Guard == nil {
		return errors.New("egress policy not configured")
	}
	client, err := destssh.Dial(ctx, svc.opts.Guard, destssh.Target{
		Host: srv.Address, Port: srv.Port, User: role.RemoteUser, Verifier: ver, Signers: []ssh.Signer{signer},
	}, svc.opts.DialTimeout)
	if err != nil {
		return err
	}
	return client.Close()
}

// Activate makes a credential the role's active login key. The previously active key enters "retiring" for the
// overlap window. A recent successful probe is required unless force is set (audited).
func (svc *Service) Activate(ctx context.Context, actor audit.Actor, id string, force bool) (*LoginCredential, error) {
	err := svc.s.W().TxNamed(ctx, "credentials.activate", func(tx *store.Tx) error {
		r, err := tx.Q.GetLoginCredential(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "credential not found")
		} else if err != nil {
			return err
		}
		if r.State != StatePending {
			return apperr.New(apperr.CodePrecondition, "only pending credentials can be activated (state %s)", r.State)
		}
		fresh := r.ProbeOkAt.Valid && tx.Now.Sub(time.UnixMicro(r.ProbeOkAt.Int64)) < ProbeFreshness
		if !fresh && !force {
			return apperr.New(apperr.CodePrecondition, "run a successful probe first (install the authorized_keys line on the destination), or force activation")
		}
		if prev, err := tx.Q.ActiveLoginCredential(ctx, r.RoleID); err == nil {
			if _, err := tx.Q.SetLoginCredentialState(ctx, db.SetLoginCredentialStateParams{
				State: StateRetiring, RetireAfter: sql.NullInt64{Int64: tx.Now.Add(svc.opts.Overlap).UnixMicro(), Valid: true},
				Now: tx.NowMicros(), ID: prev.ID, FromState: StateActive,
			}); err != nil {
				return err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		n, err := tx.Q.SetLoginCredentialState(ctx, db.SetLoginCredentialStateParams{
			State: StateActive, ActivatedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Now: tx.NowMicros(), ID: id, FromState: StatePending,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return apperr.New(apperr.CodeConflict, "credential changed concurrently")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "credential.activated", Target: audit.Target{Type: "role", ID: r.RoleID},
			Details: map[string]any{"credential_id": id, "forced": force && !fresh}})
		svc.publish(tx, r.RoleID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// Revoke stops using a credential immediately; channels authenticated with it are terminated by the enforcer.
func (svc *Service) Revoke(ctx context.Context, actor audit.Actor, id, reason string) (*LoginCredential, error) {
	err := svc.s.W().TxNamed(ctx, "credentials.revoke", func(tx *store.Tx) error {
		r, err := tx.Q.GetLoginCredential(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "credential not found")
		} else if err != nil {
			return err
		}
		if r.State == StateRevoked || r.State == StateRetired {
			return nil
		}
		if _, err := tx.Q.SetLoginCredentialState(ctx, db.SetLoginCredentialStateParams{
			State: StateRevoked, RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Now: tx.NowMicros(), ID: id, FromState: r.State,
		}); err != nil {
			return err
		}
		ev := audit.Event{Actor: actor, Action: "credential.revoked", Target: audit.Target{Type: "role", ID: r.RoleID},
			Details: map[string]any{"credential_id": id, "previous_state": r.State}}
		if reason != "" {
			ev.Sensitive = map[string]any{"reason": reason}
		}
		_, err = svc.audit.Append(ctx, tx, ev)
		svc.publish(tx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// RetireDue moves credentials whose overlap window ended from retiring to retired (periodic job).
func (svc *Service) RetireDue(ctx context.Context) (int, error) {
	due, err := svc.s.R().DueRetiringCredentials(ctx, sql.NullInt64{Int64: svc.opts.Clock.Now().UnixMicro(), Valid: true})
	if err != nil || len(due) == 0 {
		return 0, err
	}
	n := 0
	err = svc.s.W().TxNamed(ctx, "credentials.retire_due", func(tx *store.Tx) error {
		n = 0
		for _, r := range due {
			c, err := tx.Q.SetLoginCredentialState(ctx, db.SetLoginCredentialStateParams{
				State: StateRetired, RetiredAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, Now: tx.NowMicros(), ID: r.ID, FromState: StateRetiring,
			})
			if err != nil {
				return err
			}
			if c == 1 {
				n++
				if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "credential.retired", Target: audit.Target{Type: "role", ID: r.RoleID},
					Details: map[string]any{"credential_id": r.ID}}); err != nil {
					return err
				}
				svc.publish(tx, r.ID)
			}
		}
		return nil
	})
	return n, err
}

func (svc *Service) publish(tx *store.Tx, key string) {
	tx.AfterCommit(func() {
		if svc.bus != nil {
			svc.bus.Publish(eventbus.Event{Topic: eventbus.TopicCredentialChange, Key: key})
		}
	})
}

// Auth is what the data plane needs to log in to a destination as a role.
type Auth struct {
	Signers       []ssh.Signer
	CredentialRef string // credential ID, or "ca:<user CA id>" for certificates
	Kind          string // "key" or "certificate"
}

// RoleAuth returns login material for a role: a short-lived certificate when a CA binding exists, otherwise the
// active managed key. grantID and connID are embedded in certificate key IDs for destination-side accounting.
func (svc *Service) RoleAuth(ctx context.Context, roleID, grantID, connID string) (*Auth, error) {
	role, err := svc.inv.GetRole(ctx, roleID)
	if err == nil && role.Deleted() {
		err = apperr.New(apperr.CodeNotFound, "role not found")
	}
	if err != nil {
		return nil, err
	}
	b, err := svc.s.R().GetRoleCertBinding(ctx, roleID)
	if err == nil {
		return svc.issueCert(ctx, role, b, grantID, connID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	r, err := svc.s.R().ActiveLoginCredential(ctx, roleID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeUnavailable, "role has no active login credential")
	} else if err != nil {
		return nil, err
	}
	signer, err := svc.unseal("login_credentials", r.ID, r.PrivateEnc)
	if err != nil {
		return nil, err
	}
	return &Auth{Signers: []ssh.Signer{signer}, CredentialRef: r.ID, Kind: "key"}, nil
}

func credFromRow(r db.LoginCredential) *LoginCredential {
	c := &LoginCredential{
		ID: r.ID, RoleID: r.RoleID, Kind: r.Kind, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Fingerprint: r.FingerprintSha256,
		State: r.State, ProbeError: r.ProbeError.String, CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), CreatedBy: r.CreatedBy,
	}
	ts := func(v sql.NullInt64) *time.Time {
		if !v.Valid {
			return nil
		}
		t := time.UnixMicro(v.Int64).UTC()
		return &t
	}
	c.ProbeOKAt, c.ActivatedAt, c.RetireAfter = ts(r.ProbeOkAt), ts(r.ActivatedAt), ts(r.RetireAfter)
	return c
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func actorRef(a audit.Actor) string {
	if a.ID == "" {
		return a.Type
	}
	return a.Type + ":" + a.ID
}

func randomSerial() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}
