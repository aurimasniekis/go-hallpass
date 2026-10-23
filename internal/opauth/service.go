package opauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/groups"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Internal operator roles (HP-RBAC-001).
const (
	RoleAdministrator = "administrator"
	RoleApprover      = "approver"
	RoleAuditor       = "auditor"
	RoleViewer        = "viewer"
)

// AllRoles lists valid internal roles.
var AllRoles = []string{RoleAdministrator, RoleApprover, RoleAuditor, RoleViewer}

// Options configure the service.
type Options struct {
	PasswordMinBytes int
	SessionIdle      time.Duration
	SessionAbsolute  time.Duration
	ReauthWindow     time.Duration
	// MFARequiredRoles forces TOTP enrollment for local accounts holding these roles (HP-AUTH-008).
	MFARequiredRoles []string
	Issuer           string
	Clock            clock.Clock
	// HashConcurrency bounds simultaneous Argon2id computations (CPU/memory DoS guard).
	HashConcurrency int
	// Metrics counts operator login attempts by method and outcome (HP-OBS-004). Nil disables.
	Metrics *metrics.Metrics
}

// Service manages operators and their authentication.
type Service struct {
	s     *store.Store
	kr    *keyring.Keyring
	audit *audit.Writer
	bus   *eventbus.Bus
	opts  Options
	sem   chan struct{}
}

// New returns the operator authentication service.
func New(s *store.Store, kr *keyring.Keyring, aw *audit.Writer, bus *eventbus.Bus, o Options) *Service {
	if o.PasswordMinBytes <= 0 {
		o.PasswordMinBytes = 12
	}
	if o.SessionIdle <= 0 {
		o.SessionIdle = 30 * time.Minute
	}
	if o.SessionAbsolute <= 0 {
		o.SessionAbsolute = 12 * time.Hour
	}
	if o.ReauthWindow <= 0 {
		o.ReauthWindow = 5 * time.Minute
	}
	if o.MFARequiredRoles == nil {
		o.MFARequiredRoles = []string{RoleAdministrator, RoleApprover}
	}
	if o.Issuer == "" {
		o.Issuer = "Hallpass"
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.HashConcurrency <= 0 {
		o.HashConcurrency = 4
	}
	return &Service{s: s, kr: kr, audit: aw, bus: bus, opts: o, sem: make(chan struct{}, o.HashConcurrency)}
}

// Operator is an operator account (no secrets).
type Operator struct {
	ID             string           `json:"id"`
	Email          string           `json:"email,omitempty"`
	DisplayName    string           `json:"display_name"`
	Enabled        bool             `json:"enabled"`
	ProvisionedVia string           `json:"provisioned_via"`
	Roles          []string         `json:"roles"`
	Assignments    []RoleAssignment `json:"role_assignments"`
	Groups         []string         `json:"groups"`
	HasPassword    bool             `json:"has_password"`
	MFAEnrolled    bool             `json:"mfa_enrolled"`
	MFARequired    bool             `json:"mfa_required"`
	Version        int64            `json:"version"`
	CreatedAt      time.Time        `json:"created_at"`
	LastLoginAt    *time.Time       `json:"last_login_at,omitempty"`
}

// RoleAssignment records where a role came from (manual or SSO mapping).
type RoleAssignment struct {
	Role      string `json:"role"`
	Source    string `json:"source"`
	SourceRef string `json:"source_ref,omitempty"`
}

// ErrInvalidCredentials is the single response for every failed login (HP-AUTH-005).
var ErrInvalidCredentials = apperr.New(apperr.CodeUnauthorized, "invalid credentials")

// NormalizeEmail lower-cases and validates an email address.
func NormalizeEmail(e string) (string, error) {
	e = strings.ToLower(strings.TrimSpace(e))
	if len(e) > 254 {
		return "", apperr.New(apperr.CodeInvalid, "email too long")
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || !strings.Contains(e, "@") {
		return "", apperr.New(apperr.CodeInvalid, "invalid email address")
	}
	return e, nil
}

func validRoles(roles []string) error {
	for _, r := range roles {
		if !slices.Contains(AllRoles, r) {
			return apperr.New(apperr.CodeInvalid, "unknown role %q", r)
		}
	}
	return nil
}

// Get returns an operator.
func (svc *Service) Get(ctx context.Context, id string) (*Operator, error) {
	r, err := svc.s.R().GetOperator(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "operator not found")
	}
	if err != nil {
		return nil, err
	}
	return svc.hydrate(ctx, svc.s.R(), r)
}

// List returns all operators.
func (svc *Service) List(ctx context.Context) ([]*Operator, error) {
	rows, err := svc.s.R().ListOperators(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Operator, 0, len(rows))
	for _, r := range rows {
		op, err := svc.hydrate(ctx, svc.s.R(), r)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, nil
}

func (svc *Service) hydrate(ctx context.Context, q *db.Queries, r db.Operator) (*Operator, error) {
	op := &Operator{ID: r.ID, Email: r.Email.String, DisplayName: r.DisplayName, Enabled: r.Enabled == 1, ProvisionedVia: r.ProvisionedVia,
		Version: r.Version, CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), Roles: []string{}, Assignments: []RoleAssignment{}}
	if r.LastLoginAt.Valid {
		t := time.UnixMicro(r.LastLoginAt.Int64).UTC()
		op.LastLoginAt = &t
	}
	roles, err := q.ListOperatorRoles(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	for _, ra := range roles {
		op.Assignments = append(op.Assignments, RoleAssignment{Role: ra.Role, Source: ra.Source, SourceRef: ra.SourceRef})
		if !slices.Contains(op.Roles, ra.Role) {
			op.Roles = append(op.Roles, ra.Role)
		}
	}
	slices.Sort(op.Roles)
	if op.Groups, err = q.ListOperatorGroupNames(ctx, r.ID); err != nil {
		return nil, err
	}
	if _, err := q.GetLocalCredential(ctx, r.ID); err == nil {
		op.HasPassword = true
	}
	if t, err := q.GetTOTP(ctx, r.ID); err == nil && t.ConfirmedAt.Valid {
		op.MFAEnrolled = true
	}
	op.MFARequired = r.MfaRequired == 1
	for _, role := range op.Roles {
		if op.HasPassword && slices.Contains(svc.opts.MFARequiredRoles, role) {
			op.MFARequired = true
		}
	}
	return op, nil
}

// CreateInput creates an operator.
type CreateInput struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Password    string   `json:"password,omitempty"` // optional; otherwise invite or reset token
	MFARequired bool     `json:"mfa_required"`
}

// Create adds an operator (administrators only; enforced by the API layer). New operators have only the roles
// explicitly given (HP-RBAC-007).
func (svc *Service) Create(ctx context.Context, actor audit.Actor, in CreateInput) (*Operator, error) {
	return svc.create(ctx, actor, in, "admin")
}

func (svc *Service) create(ctx context.Context, actor audit.Actor, in CreateInput, via string) (*Operator, error) {
	var email sql.NullString
	if in.Email != "" {
		e, err := NormalizeEmail(in.Email)
		if err != nil {
			return nil, err
		}
		email = sql.NullString{String: e, Valid: true}
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" || len(name) > 128 {
		return nil, apperr.New(apperr.CodeInvalid, "display name is required (at most 128 bytes)")
	}
	if err := validRoles(in.Roles); err != nil {
		return nil, err
	}
	var phc string
	if in.Password != "" {
		var err error
		if phc, err = svc.hash(ctx, in.Password); err != nil {
			return nil, err
		}
	}
	id := ids.New(ids.Operator)
	err := svc.s.W().TxNamed(ctx, "opauth.create", func(tx *store.Tx) error {
		if email.Valid {
			if _, err := tx.Q.GetOperatorByEmail(ctx, email); err == nil {
				return apperr.New(apperr.CodeAlreadyExists, "an operator with this email already exists")
			}
		}
		if err := tx.Q.InsertOperator(ctx, db.InsertOperatorParams{ID: id, Email: email, DisplayName: name, Enabled: 1, ProvisionedVia: via,
			MfaRequired: b2i(in.MFARequired), CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		for _, r := range in.Roles {
			if err := tx.Q.InsertOperatorRole(ctx, db.InsertOperatorRoleParams{OperatorID: id, Role: r, Source: "manual"}); err != nil {
				return err
			}
		}
		if phc != "" {
			if err := tx.Q.UpsertLocalCredential(ctx, db.UpsertLocalCredentialParams{OperatorID: id, PasswordPhc: phc,
				ParamsVersion: int64(CurrentParams.Version), ChangedAt: tx.NowMicros()}); err != nil {
				return err
			}
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.created", Target: audit.Target{Type: "operator", ID: id},
			Details: map[string]any{"email": email.String, "roles": in.Roles, "via": via, "has_password": phc != ""}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// SetRoles replaces an operator's manual roles. Removing the last enabled administrator is refused (HP-AUTH-015);
// reducing privileges revokes the operator's sessions (HP-AUTH-010).
func (svc *Service) SetRoles(ctx context.Context, actor audit.Actor, id string, roles []string) (*Operator, error) {
	if err := validRoles(roles); err != nil {
		return nil, err
	}
	roles = slices.Compact(slices.Sorted(slices.Values(roles)))
	err := svc.s.W().TxNamed(ctx, "opauth.set_roles", func(tx *store.Tx) error {
		row, err := tx.Q.GetOperator(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "operator not found")
		} else if err != nil {
			return err
		}
		before, err := svc.hydrate(ctx, tx.Q, row)
		if err != nil {
			return err
		}
		if err := tx.Q.DeleteOperatorRolesBySource(ctx, db.DeleteOperatorRolesBySourceParams{OperatorID: id, Source: "manual"}); err != nil {
			return err
		}
		for _, r := range roles {
			if err := tx.Q.InsertOperatorRole(ctx, db.InsertOperatorRoleParams{OperatorID: id, Role: r, Source: "manual"}); err != nil {
				return err
			}
		}
		if err := ensureAdminRemains(ctx, tx); err != nil {
			return err
		}
		after, err := svc.hydrate(ctx, tx.Q, row)
		if err != nil {
			return err
		}
		if reduced(before.Roles, after.Roles) {
			if _, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
				Reason: sql.NullString{String: "roles_changed", Valid: true}, OperatorID: id, ExceptHash: []byte{}}); err != nil {
				return err
			}
		}
		svc.publish(tx, id)
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.roles.set", Target: audit.Target{Type: "operator", ID: id},
			Details: map[string]any{"before": before.Roles, "after": after.Roles}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

func reduced(before, after []string) bool {
	for _, r := range before {
		if !slices.Contains(after, r) {
			return true
		}
	}
	return false
}

// ErrLastAdmin protects against administrator lockout.
var ErrLastAdmin = apperr.New(apperr.CodePrecondition, "this change would leave no enabled administrator")

func ensureAdminRemains(ctx context.Context, tx *store.Tx) error {
	n, err := tx.Q.CountEnabledAdmins(ctx)
	if err != nil {
		return err
	}
	ops, err := tx.Q.CountOperators(ctx)
	if err != nil {
		return err
	}
	if n == 0 && ops > 0 {
		return ErrLastAdmin
	}
	return nil
}

// SetEnabled enables or disables an operator; disabling revokes all sessions and is refused for the last enabled
// administrator.
func (svc *Service) SetEnabled(ctx context.Context, actor audit.Actor, id string, enabled bool) (*Operator, error) {
	err := svc.s.W().TxNamed(ctx, "opauth.set_enabled", func(tx *store.Tx) error {
		n, err := tx.Q.SetOperatorEnabled(ctx, db.SetOperatorEnabledParams{Enabled: b2i(enabled), Now: tx.NowMicros(), ID: id})
		if err != nil || n == 0 {
			if _, gerr := tx.Q.GetOperator(ctx, id); errors.Is(gerr, sql.ErrNoRows) {
				return apperr.New(apperr.CodeNotFound, "operator not found")
			}
			return err
		}
		if err := ensureAdminRemains(ctx, tx); err != nil {
			return err
		}
		if !enabled {
			if _, err := tx.Q.RevokeOperatorSessions(ctx, db.RevokeOperatorSessionsParams{Now: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
				Reason: sql.NullString{String: "disabled", Valid: true}, OperatorID: id, ExceptHash: []byte{}}); err != nil {
				return err
			}
		}
		action := "operator.enabled"
		if !enabled {
			action = "operator.disabled"
		}
		svc.publish(tx, id)
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, Target: audit.Target{Type: "operator", ID: id}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// SetGroups replaces an operator's manual operator-group memberships (used by approver rules).
func (svc *Service) SetGroups(ctx context.Context, actor audit.Actor, id string, names []string) (*Operator, error) {
	v := &apperr.Validation{}
	groups.ValidateGroupNames(v, "groups", names)
	if err := v.Err(); err != nil {
		return nil, err
	}
	err := svc.s.W().TxNamed(ctx, "opauth.set_groups", func(tx *store.Tx) error {
		gids, err := groups.Ensure(ctx, tx, groups.KindOperator, names)
		if err != nil {
			return err
		}
		if err := tx.Q.DeleteOperatorGroupsBySource(ctx, db.DeleteOperatorGroupsBySourceParams{OperatorID: id, Source: "manual"}); err != nil {
			return err
		}
		for _, g := range gids {
			if err := tx.Q.InsertOperatorGroup(ctx, db.InsertOperatorGroupParams{GroupID: g, OperatorID: id, Source: "manual"}); err != nil {
				return err
			}
		}
		if _, err := tx.Q.BumpPolicyVersion(ctx, tx.NowMicros()); err != nil {
			return err
		}
		svc.publish(tx, id)
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "operator.groups.set", Target: audit.Target{Type: "operator", ID: id},
			Details: map[string]any{"groups": groups.Normalize(names)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

func (svc *Service) publish(tx *store.Tx, id string) {
	tx.AfterCommit(func() {
		if svc.bus != nil {
			svc.bus.Publish(eventbus.Event{Topic: eventbus.TopicOperatorChanged, Key: id})
		}
	})
}

// hash normalizes and hashes a password under the concurrency limit.
func (svc *Service) hash(ctx context.Context, pw string) (string, error) {
	n, err := NormalizePassword(pw, svc.opts.PasswordMinBytes)
	if err != nil {
		return "", err
	}
	if err := svc.acquire(ctx); err != nil {
		return "", err
	}
	defer svc.release()
	return HashPassword(n, CurrentParams)
}

func (svc *Service) acquire(ctx context.Context) error {
	select {
	case svc.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (svc *Service) release() { <-svc.sem }

// randomToken returns a 256-bit URL-safe random token.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// tokenMAC derives the stored lookup key of a token (HMAC with the token key).
func (svc *Service) tokenMAC(token string) ([]byte, error) {
	return svc.kr.MAC(keyring.PurposeToken, []byte("opauth|"+token))
}

func (svc *Service) tokenMACs(token string) ([][]byte, error) {
	return svc.kr.MACAll(keyring.PurposeToken, []byte("opauth|"+token))
}

func throttleKeyAccount(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "acct:" + hex.EncodeToString(h[:12])
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func actorRef(a audit.Actor) string {
	if a.ID == "" {
		return a.Type
	}
	return a.Type + ":" + a.ID
}

func newOperatorID() string { return ids.New(ids.Operator) }
