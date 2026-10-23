package credentials

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return rand.Read(p) }

// GatewayHostKey is the public part of one of the gateway's own SSH host keys (HP-SSH-005).
type GatewayHostKey struct {
	ID          string    `json:"id"`
	Algorithm   string    `json:"algorithm"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
}

// EnsureGatewayHostKey creates the initial Ed25519 gateway host key if none is active.
func (svc *Service) EnsureGatewayHostKey(ctx context.Context) error {
	keys, err := svc.s.R().ListGatewayHostKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.State == "active" {
			return nil
		}
	}
	return svc.addGatewayHostKey(ctx, audit.System, ssh.KeyAlgoED25519, "active")
}

func generateHostKey(algorithm string) (crypto.Signer, ssh.PublicKey, error) {
	switch algorithm {
	case ssh.KeyAlgoED25519:
		priv, pub, err := newEd25519()
		return priv, pub, err
	case ssh.KeyAlgoECDSA256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub, err := ssh.NewPublicKey(&priv.PublicKey)
		return priv, pub, err
	}
	return nil, nil, apperr.New(apperr.CodeInvalid, "unsupported gateway host key algorithm %q (use %s or %s)", algorithm, ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256)
}

func (svc *Service) addGatewayHostKey(ctx context.Context, actor audit.Actor, algorithm, state string) error {
	priv, pub, err := generateHostKey(algorithm)
	if err != nil {
		return err
	}
	id := ids.New(ids.GatewayHostKey)
	sealed, err := svc.seal("gateway_host_keys", id, priv)
	if err != nil {
		return err
	}
	return svc.s.W().TxNamed(ctx, "credentials.gateway_host_key", func(tx *store.Tx) error {
		if err := tx.Q.InsertGatewayHostKey(ctx, db.InsertGatewayHostKeyParams{
			ID: id, Algorithm: pub.Type(), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
			FingerprintSha256: ssh.FingerprintSHA256(pub), PrivateEnc: sealed, State: state, CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros(),
		}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeConflict, "a gateway host key of this algorithm is already active")
			}
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "gateway.host_key.created", Target: audit.Target{Type: "gateway_host_key", ID: id},
			Details: map[string]any{"algorithm": pub.Type(), "fingerprint": ssh.FingerprintSHA256(pub), "state": state}})
		return err
	})
}

// GatewayHostKeys lists non-retired gateway host keys.
func (svc *Service) GatewayHostKeys(ctx context.Context) ([]*GatewayHostKey, error) {
	rows, err := svc.s.R().ListGatewayHostKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*GatewayHostKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, &GatewayHostKey{ID: r.ID, Algorithm: r.Algorithm, PublicKey: r.PublicKey, Fingerprint: r.FingerprintSha256,
			State: r.State, CreatedAt: time.UnixMicro(r.CreatedAt).UTC()})
	}
	return out, nil
}

// GatewayHostSigners returns the signers the SSH server presents: the active key plus a staged "next" key of a
// different algorithm during rotation (x/crypto/ssh offers one key per algorithm and lacks hostkeys-00, ADR-0020).
func (svc *Service) GatewayHostSigners(ctx context.Context) ([]ssh.Signer, error) {
	rows, err := svc.s.R().ListGatewayHostKeys(ctx)
	if err != nil {
		return nil, err
	}
	var out []ssh.Signer
	seen := map[string]bool{}
	for _, state := range []string{"active", "next"} {
		for _, r := range rows {
			if r.State != state || seen[r.Algorithm] {
				continue
			}
			s, err := svc.unseal("gateway_host_keys", r.ID, r.PrivateEnc)
			if err != nil {
				return nil, err
			}
			seen[r.Algorithm] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no gateway host key; run EnsureGatewayHostKey")
	}
	return out, nil
}

// StageGatewayHostKey generates a "next" host key of an algorithm different from the active one; it is served
// alongside the active key so agents can pin it before promotion.
func (svc *Service) StageGatewayHostKey(ctx context.Context, actor audit.Actor, algorithm string) error {
	rows, err := svc.s.R().ListGatewayHostKeys(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.State == "next" {
			return apperr.New(apperr.CodePrecondition, "a staged host key already exists; promote or retire it first")
		}
		if r.State == "active" && r.Algorithm == algorithm {
			return apperr.New(apperr.CodePrecondition, "stage a different algorithm than the active key (%s) so both can be served during rotation", r.Algorithm)
		}
	}
	return svc.addGatewayHostKey(ctx, actor, algorithm, "next")
}

// PromoteGatewayHostKey makes the staged key active; the old active key becomes "previous" (no longer served).
func (svc *Service) PromoteGatewayHostKey(ctx context.Context, actor audit.Actor) error {
	return svc.s.W().TxNamed(ctx, "credentials.promote_host_key", func(tx *store.Tx) error {
		rows, err := tx.Q.ListGatewayHostKeys(ctx)
		if err != nil {
			return err
		}
		var next *db.GatewayHostKey
		for i := range rows {
			if rows[i].State == "next" {
				next = &rows[i]
			}
		}
		if next == nil {
			return apperr.New(apperr.CodePrecondition, "no staged host key")
		}
		for _, r := range rows {
			if r.State == "active" {
				if _, err := tx.Q.SetGatewayHostKeyState(ctx, db.SetGatewayHostKeyStateParams{State: "previous", Now: tx.NowMicros(), ID: r.ID, FromState: "active"}); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Q.SetGatewayHostKeyState(ctx, db.SetGatewayHostKeyStateParams{State: "active", Now: tx.NowMicros(), ID: next.ID, FromState: "next"}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "gateway.host_key.promoted", Target: audit.Target{Type: "gateway_host_key", ID: next.ID},
			Details: map[string]any{"fingerprint": next.FingerprintSha256, "algorithm": next.Algorithm}})
		return err
	})
}
