// Package apiproxy lets agents call HTTPS APIs (GitHub, Cloudflare, Google Cloud, …) through HallPass without ever
// holding the API credential (ADR-0060). An agent opens an SSH tunnel to the gateway's proxy and points its tools at
// it; the proxy terminates TLS with the target's own CA (name-constrained to the target's hosts), checks each request
// against the agent's grant and the access profile's rules, replaces any credential the agent sent with the profile's
// credential, forwards the request and records its metadata in the session timeline.
package apiproxy

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Credential types.
const (
	CredBearer = "bearer"                 // Authorization: Bearer <secret>
	CredHeader = "header"                 // <header>: <secret>
	CredBasic  = "basic"                  // Authorization: Basic base64(<username>:<secret>)
	CredGoogle = "google_service_account" // a service account key; HallPass sends short-lived access tokens
)

// CredentialTypes lists the valid credential types.
var CredentialTypes = []string{CredBearer, CredHeader, CredBasic, CredGoogle}

// GoogleTokenURL is the only token endpoint a Google service account key may name.
const GoogleTokenURL = "https://oauth2.googleapis.com/token" //nolint:gosec // G101 false positive: an endpoint URL

// DefaultGoogleScopes are used when a Google credential names none.
var DefaultGoogleScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// MaxSecretBytes bounds a credential secret.
const MaxSecretBytes = 16 << 10

var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// headers a credential may not set: they frame the request or belong to the proxy.
var reservedHeaders = []string{"Host", "Content-Length", "Content-Type", "Transfer-Encoding", "Connection", "Upgrade",
	"Te", "Trailer", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Cookie", "Forwarded", "Via"}

// CredentialInput sets an access profile's credential. Secret is write-only: it is sealed and never returned.
type CredentialInput struct {
	Type     string   `json:"type"`
	Header   string   `json:"header,omitempty"`
	Username string   `json:"username,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	Secret   string   `json:"secret"`
}

// Credential describes an access profile's credential without its secret.
type Credential struct {
	RoleID    string    `json:"role_id"`
	Type      string    `json:"type"`
	Header    string    `json:"header,omitempty"`
	Username  string    `json:"username,omitempty"`
	Scopes    []string  `json:"scopes"`
	Hint      string    `json:"hint"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// Ref names the credential version in channel records and the enforcer.
func (c *Credential) Ref() string { return fmt.Sprintf("api_credential:%s:v%d", c.RoleID, c.Version) }

// Service manages API target CAs and credentials.
type Service struct {
	s     *store.Store
	kr    *keyring.Keyring
	audit *audit.Writer
	bus   *eventbus.Bus
	inv   *inventory.Service
	clock clock.Clock

	mu  sync.Mutex
	cas map[string]*signedCA // server ID → unsealed CA (replaced when the stored certificate changes)
}

// NewService returns the service.
func NewService(s *store.Store, kr *keyring.Keyring, aw *audit.Writer, bus *eventbus.Bus, inv *inventory.Service, c clock.Clock) *Service {
	if c == nil {
		c = clock.System{}
	}
	return &Service{s: s, kr: kr, audit: aw, bus: bus, inv: inv, clock: c, cas: map[string]*signedCA{}}
}

func caAAD(serverID string) []byte { return keyring.FieldAAD("servers", "api_ca_key_enc", serverID) }

func secretAAD(roleID string) []byte {
	return keyring.FieldAAD("api_credentials", "secret_enc", roleID)
}

// apiTarget loads a live API target.
func (svc *Service) apiTarget(ctx context.Context, serverID string) (*inventory.Server, error) {
	srv, err := svc.inv.GetServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if srv.Deleted() || srv.Kind != inventory.KindAPI || srv.API == nil {
		return nil, apperr.New(apperr.CodeNotFound, "API target not found")
	}
	return srv, nil
}

// CA returns the target's CA certificate, issuing one when the target has none or its hosts changed since.
func (svc *Service) CA(ctx context.Context, serverID string) (*x509.Certificate, error) {
	ca, err := svc.signer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	return ca.cert, nil
}

// signer returns the target's CA with its private key.
func (svc *Service) signer(ctx context.Context, serverID string) (*signedCA, error) {
	srv, err := svc.apiTarget(ctx, serverID)
	if err != nil {
		return nil, err
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	now := svc.clock.Now()
	row, err := svc.s.R().GetServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if row.ApiCaCert.Valid {
		if cert, err := parseCertPEM(row.ApiCaCert.String); err == nil && caCovers(cert, srv.API.Hosts, now) {
			if c := svc.cas[serverID]; c != nil && c.cert.Equal(cert) {
				return c, nil
			}
			der, err := svc.kr.Open(keyring.PurposeCredential, caAAD(serverID), row.ApiCaKeyEnc)
			if err != nil {
				return nil, fmt.Errorf("unseal API CA of %s: %w", serverID, err)
			}
			key, err := x509.ParseECPrivateKey(der)
			if err != nil {
				return nil, err
			}
			c := &signedCA{cert: cert, key: key}
			svc.cas[serverID] = c
			return c, nil
		}
	}
	return svc.issueCA(ctx, srv, now)
}

// issueCA creates and stores a new CA for the target's current hosts. Agents must fetch the new bundle.
func (svc *Service) issueCA(ctx context.Context, srv *inventory.Server, now time.Time) (*signedCA, error) {
	cert, key, err := newCA(srv.Alias, srv.ID, srv.API.Hosts, now)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	sealed, err := svc.kr.Seal(keyring.PurposeCredential, caAAD(srv.ID), der)
	if err != nil {
		return nil, err
	}
	err = svc.s.W().TxNamed(ctx, "apiproxy.issue_ca", func(tx *store.Tx) error {
		if err := tx.Q.SetServerAPICA(ctx, db.SetServerAPICAParams{ApiCaCert: sql.NullString{String: encodeCert(cert), Valid: true},
			ApiCaKeyEnc: sealed, ID: srv.ID}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem}, Action: "api_target.ca_issued",
			Target: audit.Target{Type: "server", ID: srv.ID},
			Details: map[string]any{"alias": srv.Alias, "fingerprint": Fingerprint(cert), "permitted_dns": cert.PermittedDNSDomains,
				"not_after": cert.NotAfter.UTC().Format(time.RFC3339)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	c := &signedCA{cert: cert, key: key}
	svc.cas[srv.ID] = c
	return c, nil
}

// CABundle returns the PEM CA certificates of the given API targets, in order.
func (svc *Service) CABundle(ctx context.Context, serverIDs []string) (string, error) {
	var b strings.Builder
	for _, id := range serverIDs {
		srv, err := svc.apiTarget(ctx, id)
		if err != nil {
			return "", err
		}
		cert, err := svc.CA(ctx, id)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "# HallPass API proxy CA for %s (%s), SHA-256 %s\n", srv.Alias, strings.Join(srv.API.Hosts, ", "), Fingerprint(cert))
		b.WriteString(encodeCert(cert))
	}
	return b.String(), nil
}

// apiRole loads a live access profile of an API target.
func (svc *Service) apiRole(ctx context.Context, roleID string) (*inventory.Role, *inventory.Server, error) {
	role, err := svc.inv.GetRole(ctx, roleID)
	if err != nil {
		return nil, nil, err
	}
	if role.Deleted() {
		return nil, nil, apperr.New(apperr.CodeNotFound, "role not found")
	}
	srv, err := svc.apiTarget(ctx, role.ServerID)
	if err != nil {
		return nil, nil, apperr.New(apperr.CodeInvalid, "credentials of this kind are only for access profiles of API targets")
	}
	return role, srv, nil
}

func validateCredential(in *CredentialInput) (hint string, err error) {
	v := &apperr.Validation{}
	if !slices.Contains(CredentialTypes, in.Type) {
		v.Add("type", "must be one of %s", strings.Join(CredentialTypes, ", "))
	}
	if in.Secret == "" || len(in.Secret) > MaxSecretBytes {
		v.Add("secret", "required, at most %d bytes", MaxSecretBytes)
	}
	if in.Type != CredHeader && in.Header != "" {
		v.Add("header", "only for type header")
	}
	if in.Type != CredBasic && in.Username != "" {
		v.Add("username", "only for type basic")
	}
	if in.Type != CredGoogle && len(in.Scopes) > 0 {
		v.Add("scopes", "only for type google_service_account")
	}
	switch in.Type {
	case CredBearer, CredHeader, CredBasic:
		for _, c := range in.Secret {
			if c < 0x20 || c == 0x7f {
				v.Add("secret", "must not contain control characters or line breaks")
				break
			}
		}
		if len(in.Secret) >= 12 {
			hint = "…" + in.Secret[len(in.Secret)-4:]
		}
	}
	switch in.Type {
	case CredHeader:
		if !headerNameRE.MatchString(in.Header) || slices.ContainsFunc(reservedHeaders, func(h string) bool { return strings.EqualFold(h, in.Header) }) ||
			strings.HasPrefix(strings.ToLower(in.Header), "proxy-") {
			v.Add("header", "a header name such as X-Api-Key (not a reserved header)")
		}
		in.Header = http.CanonicalHeaderKey(in.Header)
	case CredBasic:
		if in.Username == "" || len(in.Username) > 256 || strings.ContainsAny(in.Username, ":\r\n") {
			v.Add("username", "required, at most 256 bytes, without ':'")
		}
	case CredGoogle:
		sa, err := parseServiceAccount([]byte(in.Secret))
		if err != nil {
			v.Add("secret", "%s", err.Error())
		} else {
			hint = sa.ClientEmail
		}
		if len(in.Scopes) == 0 {
			in.Scopes = slices.Clone(DefaultGoogleScopes)
		}
		for _, s := range in.Scopes {
			if !strings.HasPrefix(s, "https://www.googleapis.com/auth/") || len(s) > 256 {
				v.Add("scopes", "%q is not a Google OAuth scope (https://www.googleapis.com/auth/…)", s)
			}
		}
	}
	return hint, v.Err()
}

// serviceAccount is the part of a Google service account key HallPass uses.
type serviceAccount struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
}

func parseServiceAccount(b []byte) (*serviceAccount, error) {
	var sa serviceAccount
	if err := json.Unmarshal(b, &sa); err != nil {
		return nil, errors.New("not a Google service account key (JSON)")
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New(`not a Google service account key: needs "type": "service_account", client_email and private_key`)
	}
	if sa.TokenURI != "" && sa.TokenURI != GoogleTokenURL {
		return nil, fmt.Errorf("token_uri must be %s", GoogleTokenURL)
	}
	if _, err := parseRSAKey(sa.PrivateKey); err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	return &sa, nil
}

// SetCredential stores (or replaces) an access profile's credential. The new credential applies to the next
// request; nothing is cached across versions.
func (svc *Service) SetCredential(ctx context.Context, actor audit.Actor, roleID string, in CredentialInput) (*Credential, error) {
	role, srv, err := svc.apiRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	hint, err := validateCredential(&in)
	if err != nil {
		return nil, err
	}
	sealed, err := svc.kr.Seal(keyring.PurposeCredential, secretAAD(roleID), []byte(in.Secret))
	if err != nil {
		return nil, err
	}
	if in.Scopes == nil {
		in.Scopes = []string{}
	}
	scopes, _ := json.Marshal(in.Scopes)
	err = svc.s.W().TxNamed(ctx, "apiproxy.set_credential", func(tx *store.Tx) error {
		if err := tx.Q.UpsertAPICredential(ctx, db.UpsertAPICredentialParams{RoleID: roleID, Type: in.Type, Header: in.Header,
			Username: in.Username, ScopesJson: string(scopes), SecretEnc: sealed, Hint: hint, UpdatedAt: tx.NowMicros(),
			UpdatedBy: actorRef(actor)}); err != nil {
			return err
		}
		row, err := tx.Q.GetAPICredential(ctx, roleID)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "api_credential.set", Target: audit.Target{Type: "role", ID: roleID},
			Details: map[string]any{"server_id": srv.ID, "alias": srv.Alias, "role": role.Alias, "type": in.Type, "header": in.Header,
				"username": in.Username, "scopes": in.Scopes, "hint": hint, "version": row.Version}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetCredential(ctx, roleID)
}

// GetCredential describes an access profile's credential (never the secret).
func (svc *Service) GetCredential(ctx context.Context, roleID string) (*Credential, error) {
	row, err := svc.s.R().GetAPICredential(ctx, roleID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "no credential is set for this access profile")
	}
	if err != nil {
		return nil, err
	}
	return credentialFromRow(row), nil
}

func credentialFromRow(row db.ApiCredential) *Credential {
	c := &Credential{RoleID: row.RoleID, Type: row.Type, Header: row.Header, Username: row.Username, Hint: row.Hint,
		Version: row.Version, UpdatedAt: time.UnixMicro(row.UpdatedAt).UTC(), UpdatedBy: row.UpdatedBy, Scopes: []string{}}
	_ = json.Unmarshal([]byte(row.ScopesJson), &c.Scopes)
	return c
}

// DeleteCredential removes an access profile's credential; requests through the profile fail until a new one is set.
func (svc *Service) DeleteCredential(ctx context.Context, actor audit.Actor, roleID string) error {
	return svc.s.W().TxNamed(ctx, "apiproxy.delete_credential", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteAPICredential(ctx, roleID)
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "no credential is set for this access profile")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "api_credential.deleted", Target: audit.Target{Type: "role", ID: roleID}})
		return err
	})
}

// secretCredential is a credential with its unsealed secret, used only to authorize one upstream request.
type secretCredential struct {
	*Credential
	secret []byte
}

// credential loads and unseals an access profile's credential.
func (svc *Service) credential(ctx context.Context, roleID string) (*secretCredential, error) {
	row, err := svc.s.R().GetAPICredential(ctx, roleID)
	if err != nil {
		return nil, err
	}
	secret, err := svc.kr.Open(keyring.PurposeCredential, secretAAD(roleID), row.SecretEnc)
	if err != nil {
		return nil, fmt.Errorf("unseal API credential of %s: %w", roleID, err)
	}
	return &secretCredential{Credential: credentialFromRow(row), secret: secret}, nil
}

func actorRef(a audit.Actor) string {
	if a.ID == "" {
		return a.Type
	}
	return a.Type + ":" + a.ID
}
