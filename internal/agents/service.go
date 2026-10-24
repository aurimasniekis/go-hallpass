// Package agents manages agent identities and their SSH public keys (HP-AGT-*).
package agents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/groups"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Limits.
const (
	MaxSourceCIDRs     = 32
	MaxDescriptionLen  = 2000
	MaxKeysPerAgent    = 16
	MaxRevokeReasonLen = 1000
	touchInterval      = time.Hour
)

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

// Agent is an agent identity.
type Agent struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	SourceCIDRs []string          `json:"source_cidrs"`
	Groups      []string          `json:"groups"`
	Labels      map[string]string `json:"labels"`
	Version     int64             `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	CreatedBy   string            `json:"created_by"`
	UpdatedAt   time.Time         `json:"updated_at"`
	UpdatedBy   string            `json:"updated_by"`
	DisabledAt  *time.Time        `json:"disabled_at,omitempty"`
}

// Key is an agent public key.
type Key struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	Fingerprint string     `json:"fingerprint"`
	Algorithm   string     `json:"algorithm"`
	Bits        int        `json:"bits"`
	PublicKey   string     `json:"public_key"`
	Comment     string     `json:"comment"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// TxHook runs inside the transaction that disables an agent or revokes a key, so dependent state (pending requests,
// grants) changes atomically with it. Registered by the access service (WP09).
type TxHook func(ctx context.Context, tx *store.Tx, agentID, keyID, reason string) error

// Service manages agents.
type Service struct {
	s     *store.Store
	kr    *keyring.Keyring
	audit *audit.Writer
	bus   *eventbus.Bus
	clock clock.Clock

	mu          sync.RWMutex
	disableHook []TxHook
	revokeHook  []TxHook
}

// New returns an agent service.
func New(s *store.Store, kr *keyring.Keyring, aw *audit.Writer, bus *eventbus.Bus, c clock.Clock) *Service {
	if c == nil {
		c = clock.System{}
	}
	return &Service{s: s, kr: kr, audit: aw, bus: bus, clock: c}
}

// OnDisable registers a hook run inside the disable transaction (keyID is empty).
func (svc *Service) OnDisable(h TxHook) {
	svc.mu.Lock()
	svc.disableHook = append(svc.disableHook, h)
	svc.mu.Unlock()
}

// OnKeyRevoke registers a hook run inside the key revocation transaction.
func (svc *Service) OnKeyRevoke(h TxHook) {
	svc.mu.Lock()
	svc.revokeHook = append(svc.revokeHook, h)
	svc.mu.Unlock()
}

// CreateInput creates an agent.
type CreateInput struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     *bool             `json:"enabled,omitempty"`
	SourceCIDRs []string          `json:"source_cidrs"`
	Groups      []string          `json:"groups"`
	Labels      map[string]string `json:"labels"`
	PublicKeys  []string          `json:"public_keys"`
}

// UpdateInput changes an agent; nil fields are unchanged. Version must match (optimistic concurrency).
type UpdateInput struct {
	Version     int64              `json:"version"`
	Name        *string            `json:"name,omitempty"`
	Description *string            `json:"description,omitempty"`
	SourceCIDRs *[]string          `json:"source_cidrs,omitempty"`
	Groups      *[]string          `json:"groups,omitempty"`
	Labels      *map[string]string `json:"labels,omitempty"`
}

func validateCommon(v *apperr.Validation, name, desc string, cidrs, grps []string, labels map[string]string) []netip.Prefix {
	if !nameRE.MatchString(name) {
		v.Add("name", "must be 1-64 lowercase letters, digits, '.', '_' or '-', starting and ending alphanumeric")
	}
	if len(desc) > MaxDescriptionLen {
		v.Add("description", "at most %d bytes", MaxDescriptionLen)
	}
	if len(cidrs) > MaxSourceCIDRs {
		v.Add("source_cidrs", "at most %d entries", MaxSourceCIDRs)
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			v.Add("source_cidrs", "invalid CIDR %q", c)
			continue
		}
		prefixes = append(prefixes, p.Masked())
	}
	groups.ValidateGroupNames(v, "groups", grps)
	groups.ValidateLabels(v, "labels", labels)
	return prefixes
}

func cidrJSON(prefixes []netip.Prefix) string {
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// Create registers an agent with optional initial keys.
func (svc *Service) Create(ctx context.Context, actor audit.Actor, in CreateInput) (*Agent, error) {
	v := &apperr.Validation{}
	prefixes := validateCommon(v, in.Name, in.Description, in.SourceCIDRs, in.Groups, in.Labels)
	if len(in.PublicKeys) > MaxKeysPerAgent {
		v.Add("public_keys", "at most %d keys", MaxKeysPerAgent)
	}
	parsed := make([]*ParsedKey, 0, len(in.PublicKeys))
	for _, line := range in.PublicKeys {
		pk, err := ParseAgentKey(line)
		if err != nil {
			v.Add("public_keys", "%s", err.Error())
			continue
		}
		parsed = append(parsed, pk)
	}
	if err := v.Err(); err != nil {
		return nil, err
	}
	enabled := in.Enabled == nil || *in.Enabled
	id := ids.New(ids.Agent)
	err := svc.s.W().TxNamed(ctx, "agents.create", func(tx *store.Tx) error {
		if _, err := tx.Q.GetAgentByName(ctx, in.Name); err == nil {
			return apperr.New(apperr.CodeAlreadyExists, "an agent named %q already exists", in.Name)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := tx.Q.InsertAgent(ctx, db.InsertAgentParams{
			ID: id, Name: in.Name, Description: in.Description, Enabled: b2i(enabled), SourceCidrsJson: cidrJSON(prefixes),
			CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), UpdatedAt: tx.NowMicros(), UpdatedBy: actorRef(actor),
		}); err != nil {
			return err
		}
		if err := svc.setGroupsLabels(ctx, tx, id, in.Groups, in.Labels); err != nil {
			return err
		}
		for _, pk := range parsed {
			if _, err := svc.insertKey(ctx, tx, actor, id, pk); err != nil {
				return err
			}
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{
			Actor: actor, Action: "agent.created", Target: audit.Target{Type: "agent", ID: id},
			Details: map[string]any{"name": in.Name, "enabled": enabled, "keys": len(parsed), "groups": groups.Normalize(in.Groups)},
		})
		svc.afterCommit(tx, eventbus.TopicAgentChanged, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

func (svc *Service) setGroupsLabels(ctx context.Context, tx *store.Tx, agentID string, grps []string, labels map[string]string) error {
	if grps != nil {
		gids, err := groups.Ensure(ctx, tx, groups.KindAgent, grps)
		if err != nil {
			return err
		}
		if err := tx.Q.DeleteAgentGroups(ctx, agentID); err != nil {
			return err
		}
		for _, gid := range gids {
			if err := tx.Q.InsertAgentGroup(ctx, db.InsertAgentGroupParams{AgentID: agentID, GroupID: gid}); err != nil {
				return err
			}
		}
	}
	if labels != nil {
		return groups.SetLabels(ctx, tx, groups.EntityAgent, agentID, labels)
	}
	return nil
}

// Update changes agent attributes.
func (svc *Service) Update(ctx context.Context, actor audit.Actor, id string, in UpdateInput) (*Agent, error) {
	cur, err := svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	name, desc, cidrs := cur.Name, cur.Description, cur.SourceCIDRs
	if in.Name != nil {
		name = *in.Name
	}
	if in.Description != nil {
		desc = *in.Description
	}
	if in.SourceCIDRs != nil {
		cidrs = *in.SourceCIDRs
	}
	var grps []string
	if in.Groups != nil {
		grps = *in.Groups
	}
	var labels map[string]string
	if in.Labels != nil {
		labels = *in.Labels
		if labels == nil {
			labels = map[string]string{}
		}
	}
	v := &apperr.Validation{}
	prefixes := validateCommon(v, name, desc, cidrs, grps, labels)
	if err := v.Err(); err != nil {
		return nil, err
	}
	err = svc.s.W().TxNamed(ctx, "agents.update", func(tx *store.Tx) error {
		if name != cur.Name {
			if other, err := tx.Q.GetAgentByName(ctx, name); err == nil && other.ID != id {
				return apperr.New(apperr.CodeAlreadyExists, "an agent named %q already exists", name)
			}
		}
		n, err := tx.Q.UpdateAgent(ctx, db.UpdateAgentParams{
			Name: name, Description: desc, SourceCidrsJson: cidrJSON(prefixes), UpdatedAt: tx.NowMicros(),
			UpdatedBy: actorRef(actor), ID: id, Version: in.Version,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeConflict, "agent was modified concurrently; reload and retry")
		}
		if in.Groups != nil || in.Labels != nil {
			if in.Groups == nil {
				grps = nil
			}
			if err := svc.setGroupsLabels(ctx, tx, id, grps, labels); err != nil {
				return err
			}
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		details := map[string]any{"name": name}
		if in.SourceCIDRs != nil {
			details["source_cidrs"] = cidrs
		}
		if in.Groups != nil {
			details["groups"] = groups.Normalize(grps)
		}
		if in.Labels != nil {
			details["labels"] = labels
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "agent.updated", Target: audit.Target{Type: "agent", ID: id}, Details: details})
		svc.afterCommit(tx, eventbus.TopicAgentChanged, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// SetEnabled enables or disables an agent. Disabling runs disable hooks in the same transaction (HP-AGT-008).
func (svc *Service) SetEnabled(ctx context.Context, actor audit.Actor, id string, enabled bool, reason string) (*Agent, error) {
	if len(reason) > MaxRevokeReasonLen {
		return nil, apperr.New(apperr.CodeInvalid, "reason too long")
	}
	err := svc.s.W().TxNamed(ctx, "agents.set_enabled", func(tx *store.Tx) error {
		if _, err := tx.Q.GetAgent(ctx, id); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "agent not found")
		} else if err != nil {
			return err
		}
		n, err := tx.Q.SetAgentEnabled(ctx, db.SetAgentEnabledParams{Enabled: b2i(enabled), Now: tx.NowMicros(), Actor: actorRef(actor), ID: id})
		if err != nil || n == 0 {
			return err // no change: already in the requested state
		}
		if !enabled {
			svc.mu.RLock()
			hooks := append([]TxHook(nil), svc.disableHook...)
			svc.mu.RUnlock()
			for _, h := range hooks {
				if err := h(ctx, tx, id, "", "agent_disabled"); err != nil {
					return err
				}
			}
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		action := "agent.enabled"
		topic := eventbus.TopicAgentChanged
		if !enabled {
			action, topic = "agent.disabled", eventbus.TopicAgentDisabled
		}
		ev := audit.Event{Actor: actor, Action: action, Target: audit.Target{Type: "agent", ID: id}}
		if reason != "" {
			ev.Sensitive = map[string]any{"reason": reason}
		}
		_, err = svc.audit.Append(ctx, tx, ev)
		svc.afterCommit(tx, topic, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Get(ctx, id)
}

// AddKey registers a new public key for an agent (HP-AGT-002/003).
func (svc *Service) AddKey(ctx context.Context, actor audit.Actor, agentID, line string) (*Key, error) {
	pk, err := ParseAgentKey(line)
	if err != nil {
		return nil, err
	}
	var keyID string
	err = svc.s.W().TxNamed(ctx, "agents.add_key", func(tx *store.Tx) error {
		if _, err := tx.Q.GetAgent(ctx, agentID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "agent not found")
		} else if err != nil {
			return err
		}
		n, err := tx.Q.CountActiveAgentKeys(ctx, agentID)
		if err != nil {
			return err
		}
		if n >= MaxKeysPerAgent {
			return apperr.New(apperr.CodePrecondition, "agent already has %d active keys; revoke one first", n)
		}
		keyID, err = svc.insertKey(ctx, tx, actor, agentID, pk)
		svc.afterCommit(tx, eventbus.TopicAgentChanged, agentID)
		return err
	})
	if err != nil {
		return nil, err
	}
	k, err := svc.s.R().GetAgentKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return keyFromRow(k), nil
}

func (svc *Service) insertKey(ctx context.Context, tx *store.Tx, actor audit.Actor, agentID string, pk *ParsedKey) (string, error) {
	if existing, err := tx.Q.GetAgentKeyByFingerprint(ctx, pk.Fingerprint); err == nil {
		if existing.AgentID == agentID {
			return "", apperr.New(apperr.CodeAlreadyExists, "key %s is already registered for this agent (state %s)", pk.Fingerprint, existing.State)
		}
		// Keys are globally unique, including revoked (tombstoned) keys: ownership is never ambiguous (HP-AGT-003).
		return "", apperr.New(apperr.CodeAlreadyExists, "key %s is already registered to another agent (%s)", pk.Fingerprint, existing.AgentID)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	id := ids.New(ids.AgentKey)
	if err := tx.Q.InsertAgentKey(ctx, db.InsertAgentKeyParams{
		ID: id, AgentID: agentID, FingerprintSha256: pk.Fingerprint, Algorithm: pk.Algorithm, Bits: int64(pk.Bits),
		PublicKey: pk.Line, Comment: pk.Comment, CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor),
	}); err != nil {
		if store.IsConstraint(err) {
			return "", apperr.New(apperr.CodeAlreadyExists, "key %s is already registered", pk.Fingerprint)
		}
		return "", err
	}
	_, err := svc.audit.Append(ctx, tx, audit.Event{
		Actor: actor, Action: "agent.key.added", Target: audit.Target{Type: "agent", ID: agentID},
		Details: map[string]any{"key_id": id, "fingerprint": pk.Fingerprint, "algorithm": pk.Algorithm, "bits": pk.Bits},
	})
	return id, err
}

// RevokeKey revokes a key immediately (HP-AGT-005). Revocation hooks terminate dependent access in the same
// transaction, and connections authenticated by the key are terminated by the enforcer.
func (svc *Service) RevokeKey(ctx context.Context, actor audit.Actor, agentID, keyID, reason string) (*Key, error) {
	if len(reason) > MaxRevokeReasonLen {
		return nil, apperr.New(apperr.CodeInvalid, "reason too long")
	}
	err := svc.s.W().TxNamed(ctx, "agents.revoke_key", func(tx *store.Tx) error {
		k, err := tx.Q.GetAgentKey(ctx, keyID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && k.AgentID != agentID) {
			return apperr.New(apperr.CodeNotFound, "key not found")
		} else if err != nil {
			return err
		}
		if k.State == "revoked" {
			return nil
		}
		var enc []byte
		if reason != "" {
			if enc, err = svc.kr.Seal(keyring.PurposeField, keyring.FieldAAD("agent_keys", "revoke_reason_enc", keyID), []byte(reason)); err != nil {
				return err
			}
		}
		n, err := tx.Q.RevokeAgentKey(ctx, db.RevokeAgentKeyParams{
			RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, RevokedBy: sql.NullString{String: actorRef(actor), Valid: true},
			RevokeReasonEnc: enc, ID: keyID, AgentID: agentID,
		})
		if err != nil || n == 0 {
			return err
		}
		svc.mu.RLock()
		hooks := append([]TxHook(nil), svc.revokeHook...)
		svc.mu.RUnlock()
		for _, h := range hooks {
			if err := h(ctx, tx, agentID, keyID, "key_revoked"); err != nil {
				return err
			}
		}
		ev := audit.Event{Actor: actor, Action: "agent.key.revoked", Target: audit.Target{Type: "agent", ID: agentID},
			Details: map[string]any{"key_id": keyID, "fingerprint": k.FingerprintSha256}}
		if reason != "" {
			ev.Sensitive = map[string]any{"reason": reason}
		}
		_, err = svc.audit.Append(ctx, tx, ev)
		tx.AfterCommit(func() {
			if svc.bus != nil {
				svc.bus.Publish(eventbus.Event{Topic: eventbus.TopicAgentKeyRevoked, Key: keyID, Payload: agentID})
			}
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	k, err := svc.s.R().GetAgentKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return keyFromRow(k), nil
}

// bumpPolicy increments policy_version and publishes policy.changed after commit. Group, label, source and enabled
// changes alter policy evaluation, so the access service must re-apply policy to pending requests and active grants
// within the enforcement bound (HP-POL-008, SR-12); the agent.* topics alone have no reconciling subscriber.
func (svc *Service) bumpPolicy(ctx context.Context, tx *store.Tx) error {
	v, err := tx.Q.BumpPolicyVersion(ctx, tx.NowMicros())
	if err != nil {
		return err
	}
	tx.AfterCommit(func() {
		if svc.bus != nil {
			svc.bus.Publish(eventbus.Event{Topic: eventbus.TopicPolicyChanged, Payload: v})
		}
	})
	return nil
}

func (svc *Service) afterCommit(tx *store.Tx, topic, agentID string) {
	tx.AfterCommit(func() {
		if svc.bus != nil {
			svc.bus.Publish(eventbus.Event{Topic: topic, Key: agentID})
		}
	})
}

// Get returns an agent with groups and labels.
func (svc *Service) Get(ctx context.Context, id string) (*Agent, error) {
	r, err := svc.s.R().GetAgent(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "agent not found")
	}
	if err != nil {
		return nil, err
	}
	a := agentFromRow(r)
	if a.Groups, err = svc.s.R().ListAgentGroupNames(ctx, id); err != nil {
		return nil, err
	}
	if a.Labels, err = groups.Labels(ctx, svc.s.R(), groups.EntityAgent, id); err != nil {
		return nil, err
	}
	return a, nil
}

// List returns all agents with groups and labels.
func (svc *Service) List(ctx context.Context) ([]*Agent, error) {
	rows, err := svc.s.R().ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	gs, err := svc.s.R().ListAllAgentGroups(ctx)
	if err != nil {
		return nil, err
	}
	byAgent := map[string][]string{}
	for _, g := range gs {
		byAgent[g.AgentID] = append(byAgent[g.AgentID], g.Name)
	}
	labels, err := groups.AllLabels(ctx, svc.s.R(), groups.EntityAgent)
	if err != nil {
		return nil, err
	}
	out := make([]*Agent, 0, len(rows))
	for _, r := range rows {
		a := agentFromRow(r)
		a.Groups = append(a.Groups, byAgent[r.ID]...)
		if l := labels[r.ID]; l != nil {
			a.Labels = l
		}
		out = append(out, a)
	}
	return out, nil
}

// Keys lists an agent's keys (active and revoked).
func (svc *Service) Keys(ctx context.Context, agentID string) ([]*Key, error) {
	rows, err := svc.s.R().ListAgentKeys(ctx, agentID)
	if err != nil {
		return nil, err
	}
	out := make([]*Key, 0, len(rows))
	for _, r := range rows {
		out = append(out, keyFromRow(r))
	}
	return out, nil
}

// Identity is the result of successful agent authentication.
type Identity struct {
	AgentID     string
	AgentName   string
	KeyID       string
	Fingerprint string
}

// Authentication failure reasons (recorded in audit; agents always see the same generic failure, HP-SSH-003).
const (
	FailUnknownKey    = "unknown_key"
	FailRevokedKey    = "revoked_key"
	FailAgentDisabled = "agent_disabled"
	FailSourceDenied  = "source_not_allowed"
	FailKeyPolicy     = "key_policy"
)

// ErrAuthFailed is returned for every authentication failure.
var ErrAuthFailed = errors.New("authentication failed")

// AuthError carries the internal failure reason.
type AuthError struct {
	Reason      string
	Fingerprint string
	AgentID     string
}

func (e *AuthError) Error() string { return "authentication failed: " + e.Reason }
func (e *AuthError) Unwrap() error { return ErrAuthFailed }

// Authenticate resolves the identity for a public key presented from source (HP-SSH-002, HP-AGT-007).
// Identity comes only from the key; the SSH username plays no role.
func (svc *Service) Authenticate(ctx context.Context, pk ssh.PublicKey, source netip.Addr) (*Identity, error) {
	fp := ssh.FingerprintSHA256(pk)
	if err := CheckKeyPolicy(pk); err != nil {
		return nil, &AuthError{Reason: FailKeyPolicy, Fingerprint: fp}
	}
	r, err := svc.s.R().AuthLookup(ctx, fp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &AuthError{Reason: FailUnknownKey, Fingerprint: fp}
	}
	if err != nil {
		return nil, err
	}
	switch {
	case r.KeyState != "active":
		return nil, &AuthError{Reason: FailRevokedKey, Fingerprint: fp, AgentID: r.AgentID}
	case r.Enabled != 1:
		return nil, &AuthError{Reason: FailAgentDisabled, Fingerprint: fp, AgentID: r.AgentID}
	}
	var cidrs []string
	_ = json.Unmarshal([]byte(r.SourceCidrsJson), &cidrs)
	if len(cidrs) > 0 && !sourceAllowed(cidrs, source) {
		return nil, &AuthError{Reason: FailSourceDenied, Fingerprint: fp, AgentID: r.AgentID}
	}
	now := svc.clock.Now()
	if !r.LastUsedAt.Valid || now.Sub(time.UnixMicro(r.LastUsedAt.Int64)) > touchInterval {
		_ = svc.s.W().TxNamed(ctx, "agents.touch_key", func(tx *store.Tx) error {
			return tx.Q.TouchAgentKey(ctx, db.TouchAgentKeyParams{
				Now: sql.NullInt64{Int64: now.UnixMicro(), Valid: true}, ID: r.KeyID,
				Threshold: sql.NullInt64{Int64: now.Add(-touchInterval).UnixMicro(), Valid: true},
			})
		})
	}
	return &Identity{AgentID: r.AgentID, AgentName: r.AgentName, KeyID: r.KeyID, Fingerprint: fp}, nil
}

func sourceAllowed(cidrs []string, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

func agentFromRow(r db.Agent) *Agent {
	a := &Agent{
		ID: r.ID, Name: r.Name, Description: r.Description, Enabled: r.Enabled == 1, Version: r.Version,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), CreatedBy: r.CreatedBy, UpdatedAt: time.UnixMicro(r.UpdatedAt).UTC(),
		UpdatedBy: r.UpdatedBy, Groups: []string{}, Labels: map[string]string{}, SourceCIDRs: []string{},
	}
	_ = json.Unmarshal([]byte(r.SourceCidrsJson), &a.SourceCIDRs)
	if r.DisabledAt.Valid {
		t := time.UnixMicro(r.DisabledAt.Int64).UTC()
		a.DisabledAt = &t
	}
	return a
}

func keyFromRow(r db.AgentKey) *Key {
	k := &Key{
		ID: r.ID, AgentID: r.AgentID, Fingerprint: r.FingerprintSha256, Algorithm: r.Algorithm, Bits: int(r.Bits),
		PublicKey: r.PublicKey, Comment: r.Comment, State: r.State, CreatedAt: time.UnixMicro(r.CreatedAt).UTC(),
		CreatedBy: r.CreatedBy, RevokedBy: r.RevokedBy.String,
	}
	if r.RevokedAt.Valid {
		t := time.UnixMicro(r.RevokedAt.Int64).UTC()
		k.RevokedAt = &t
	}
	if r.LastUsedAt.Valid {
		t := time.UnixMicro(r.LastUsedAt.Int64).UTC()
		k.LastUsedAt = &t
	}
	return k
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
