package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/gitproto"
	"github.com/aurimasniekis/go-hallpass/internal/groups"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

var (
	remoteUserRE     = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)
	envNameRE        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}\*?$`)
	retentionClassRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// RoleInput creates or updates a role; nil fields keep current values (create applies defaults).
type RoleInput struct {
	Version               int64              `json:"version,omitempty"`
	Alias                 *string            `json:"alias,omitempty"`
	DisplayName           *string            `json:"display_name,omitempty"`
	Description           *string            `json:"description,omitempty"`
	RemoteUser            *string            `json:"remote_user,omitempty"`
	Capabilities          *[]string          `json:"capabilities,omitempty"`
	DefaultDuration       *time.Duration     `json:"default_duration,omitempty"`
	MaxDuration           *time.Duration     `json:"max_duration,omitempty"`
	MaxConcurrent         *int               `json:"max_concurrent,omitempty"`
	MaxConcurrentPerAgent *int               `json:"max_concurrent_per_agent,omitempty"`
	RecordInput           *bool              `json:"record_input,omitempty"`
	RecordingMode         *string            `json:"recording_mode,omitempty"`
	EnvAllow              *[]string          `json:"env_allow,omitempty"`
	ApprovalChannels      *[]string          `json:"approval_channels,omitempty"`
	RestrictionNotes      *string            `json:"restriction_notes,omitempty"`
	RetentionClass        *string            `json:"retention_class,omitempty"`
	Labels                *map[string]string `json:"labels,omitempty"`
	Enabled               *bool              `json:"enabled,omitempty"`
	Git                   *GitRules          `json:"git,omitempty"`
	ApprovalsRequired     *int               `json:"approvals_required,omitempty"`
	API                   *APIRules          `json:"api,omitempty"`
}

// MaxApprovalsRequired bounds RoleInput.ApprovalsRequired.
const MaxApprovalsRequired = 5

// GitRules say what an access profile on a git remote covers. Repository patterns are matched case-insensitively
// against the normalized repository path (no ".git" suffix); push rules apply to git-write only.
type GitRules struct {
	Repos []string          `json:"repos"`
	Push  gitproto.RefRules `json:"push"`
}

// Limits for git rules.
const (
	MaxGitRepoPatterns = 100
	MaxGitRefPatterns  = 100
)

// Compile validates the rules and returns the compiled repository patterns and push policy.
func (g *GitRules) Compile() (gitproto.PatternSet, *gitproto.RefPolicy, error) {
	repos, err := gitproto.CompilePatterns(g.Repos, true)
	if err != nil {
		return nil, nil, err
	}
	push, err := g.Push.Compile()
	if err != nil {
		return nil, nil, err
	}
	return repos, push, nil
}

func validateGitRules(v *apperr.Validation, r *Role) {
	if r.Git == nil || len(r.Git.Repos) == 0 {
		v.Add("git.repos", "at least one repository pattern is required, e.g. acme/{api,web}")
		return
	}
	if len(r.Git.Repos) > MaxGitRepoPatterns {
		v.Add("git.repos", "at most %d patterns", MaxGitRepoPatterns)
	}
	p := r.Git.Push
	if len(p.Branches)+len(p.ProtectedBranches)+len(p.Tags) > MaxGitRefPatterns {
		v.Add("git.push", "at most %d ref patterns in total", MaxGitRefPatterns)
	}
	if _, _, err := r.Git.Compile(); err != nil {
		v.Add("git", "%s", err.Error())
	}
	pushRules := len(p.Branches)+len(p.Tags) > 0 || p.AllowDelete
	if pushRules && !r.Has(CapGitWrite) {
		v.Add("git.push", "push rules need the git-write capability")
	}
	if r.Has(CapGitWrite) && !pushRules {
		v.Add("git.push", "git-write needs at least one branch or tag pattern")
	}
}

func (svc *Service) validateRole(v *apperr.Validation, r *Role, kind string) {
	if !ValidAlias(r.Alias) {
		v.Add("alias", "%s", AliasRule)
	}
	if r.DisplayName == "" || len(r.DisplayName) > MaxNameLen {
		v.Add("display_name", "required, at most %d bytes", MaxNameLen)
	}
	if len(r.Description) > MaxDescriptionLen || len(r.RestrictionNotes) > MaxDescriptionLen {
		v.Add("description", "at most %d bytes", MaxDescriptionLen)
	}
	if !remoteUserRE.MatchString(r.RemoteUser) {
		v.Add("remote_user", "must be a valid POSIX user name")
	}
	if len(r.Capabilities) == 0 {
		v.Add("capabilities", "at least one capability is required")
	}
	for _, c := range r.Capabilities {
		if !slices.Contains(AllCapabilities, c) {
			v.Add("capabilities", "unknown capability %q (valid: %s)", c, strings.Join(AllCapabilities, ", "))
		}
	}
	if kind != KindAPI && (r.API != nil || r.Has(CapAPI)) {
		v.Add("api", "API rules and the api capability are only for API targets")
	}
	switch kind {
	case KindAPI:
		for _, c := range r.Capabilities {
			if c != CapAPI {
				v.Add("capabilities", "API targets only use the api capability")
			}
		}
		if r.RecordInput {
			v.Add("record_input", "not available for API targets")
		}
		if len(r.EnvAllow) > 0 {
			v.Add("env_allow", "not available for API targets")
		}
		if r.Git != nil {
			v.Add("git", "git rules are only for git remotes")
		}
		validateAPIRules(v, r)
	case KindGit:
		for _, c := range r.Capabilities {
			if c != CapGitRead && c != CapGitWrite {
				v.Add("capabilities", "git remotes only use git-read and git-write")
			}
		}
		if r.RecordInput {
			v.Add("record_input", "not available for git remotes")
		}
		validateGitRules(v, r)
	default:
		if r.Has(CapGitRead) || r.Has(CapGitWrite) {
			v.Add("capabilities", "git-read and git-write are only for git remotes")
		}
		if !r.Has(CapShell) && !r.Has(CapExec) && !r.Has(CapFileTransfer) {
			v.Add("capabilities", "must include shell, exec or file-transfer")
		}
		if r.Git != nil {
			v.Add("git", "git rules are only for git remotes")
		}
	}
	if r.DefaultDuration < time.Minute || r.DefaultDuration > r.MaxDuration {
		v.Add("default_duration", "must be at least 1m and at most max_duration")
	}
	if r.MaxDuration > svc.opts.MaxGrantDuration {
		v.Add("max_duration", "exceeds the global maximum %s", svc.opts.MaxGrantDuration)
	}
	if r.MaxConcurrent < 1 || r.MaxConcurrent > 10000 {
		v.Add("max_concurrent", "must be within 1..10000")
	}
	if r.MaxConcurrentPerAgent < 1 || r.MaxConcurrentPerAgent > r.MaxConcurrent {
		v.Add("max_concurrent_per_agent", "must be within 1..max_concurrent")
	}
	if r.RecordingMode != "mandatory" && r.RecordingMode != "best_effort" {
		v.Add("recording_mode", "must be mandatory or best_effort")
	}
	for _, e := range r.EnvAllow {
		if !envNameRE.MatchString(e) {
			v.Add("env_allow", "invalid variable name or prefix %q", e)
		}
	}
	if len(r.ApprovalChannels) == 0 {
		v.Add("approval_channels", "at least one approval channel is required")
	}
	for _, c := range r.ApprovalChannels {
		if !slices.Contains(AllApprovalChannels, c) {
			v.Add("approval_channels", "unknown channel %q", c)
		}
	}
	if r.ApprovalsRequired < 1 || r.ApprovalsRequired > MaxApprovalsRequired {
		v.Add("approvals_required", "must be within 1..%d", MaxApprovalsRequired)
	}
	if !retentionClassRE.MatchString(r.RetentionClass) {
		v.Add("retention_class", "invalid retention class name")
	}
	groups.ValidateLabels(v, "labels", r.Labels)
}

func applyRoleInput(r *Role, in RoleInput) {
	r.Alias = deref(in.Alias, r.Alias)
	r.DisplayName = deref(in.DisplayName, r.DisplayName)
	r.Description = deref(in.Description, r.Description)
	r.RemoteUser = deref(in.RemoteUser, r.RemoteUser)
	r.Capabilities = normalizeList(deref(in.Capabilities, r.Capabilities))
	r.DefaultDuration = deref(in.DefaultDuration, r.DefaultDuration)
	r.MaxDuration = deref(in.MaxDuration, r.MaxDuration)
	r.MaxConcurrent = deref(in.MaxConcurrent, r.MaxConcurrent)
	r.MaxConcurrentPerAgent = deref(in.MaxConcurrentPerAgent, r.MaxConcurrentPerAgent)
	r.RecordInput = deref(in.RecordInput, r.RecordInput)
	r.RecordingMode = deref(in.RecordingMode, r.RecordingMode)
	r.EnvAllow = normalizeList(deref(in.EnvAllow, r.EnvAllow))
	r.ApprovalChannels = normalizeList(deref(in.ApprovalChannels, r.ApprovalChannels))
	r.RestrictionNotes = deref(in.RestrictionNotes, r.RestrictionNotes)
	r.RetentionClass = deref(in.RetentionClass, r.RetentionClass)
	r.Labels = deref(in.Labels, r.Labels)
	r.ApprovalsRequired = deref(in.ApprovalsRequired, r.ApprovalsRequired)
	if r.Labels == nil {
		r.Labels = map[string]string{}
	}
	if in.Git != nil {
		g := *in.Git
		g.Repos = normalizeList(g.Repos)
		r.Git = &g
	}
	if in.API != nil {
		a := *in.API
		r.API = &a
	}
}

func gitRulesJSON(g *GitRules) sql.NullString {
	if g == nil {
		return sql.NullString{}
	}
	b, _ := json.Marshal(g)
	return sql.NullString{String: string(b), Valid: true}
}

func normalizeList(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func jsonList(l []string) string {
	if l == nil {
		l = []string{}
	}
	b, _ := json.Marshal(l)
	return string(b)
}

// CreateRole adds a role to a server. Defaults: capabilities shell+exec+pty, 30m default, 6h max (≤ global),
// concurrency 10/2, mandatory recording, input not recorded.
func (svc *Service) CreateRole(ctx context.Context, actor audit.Actor, serverID string, in RoleInput) (*Role, error) {
	srv, err := svc.liveServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	r := &Role{
		ServerID: serverID, Capabilities: []string{CapExec, CapPTY, CapShell}, DefaultDuration: 30 * time.Minute,
		MaxDuration: min(6*time.Hour, svc.opts.MaxGrantDuration), MaxConcurrent: 10, MaxConcurrentPerAgent: 2,
		RecordingMode: "mandatory", EnvAllow: []string{}, ApprovalChannels: slices.Clone(AllApprovalChannels),
		RetentionClass: "default", Labels: map[string]string{}, Enabled: deref(in.Enabled, true), ApprovalsRequired: 1,
	}
	if srv.Kind == KindGit {
		// Git hosts take every user as "git" and never open shells: read-only by default.
		r.Capabilities, r.RemoteUser = []string{CapGitRead}, "git"
	}
	if srv.Kind == KindAPI {
		// An API client opens a few connections at a time; each is one tunnel through the proxy.
		r.Capabilities, r.RemoteUser, r.MaxConcurrent, r.MaxConcurrentPerAgent = []string{CapAPI}, "api", 20, 10
	}
	applyRoleInput(r, in)
	if r.DisplayName == "" {
		r.DisplayName = r.Alias
	}
	v := &apperr.Validation{}
	svc.validateRole(v, r, srv.Kind)
	if err := v.Err(); err != nil {
		return nil, err
	}
	id := ids.New(ids.Role)
	err = svc.s.W().TxNamed(ctx, "inventory.create_role", func(tx *store.Tx) error {
		if _, err := tx.Q.GetServer(ctx, serverID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "server not found")
		} else if err != nil {
			return err
		}
		if _, err := tx.Q.GetRoleByAlias(ctx, db.GetRoleByAliasParams{ServerID: serverID, Alias: r.Alias}); err == nil {
			return apperr.New(apperr.CodeAlreadyExists, "role %q already exists on this server", r.Alias)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := tx.Q.InsertRole(ctx, db.InsertRoleParams{
			ID: id, ServerID: serverID, Alias: r.Alias, DisplayName: r.DisplayName, Description: r.Description,
			RemoteUser: r.RemoteUser, CapabilitiesJson: jsonList(r.Capabilities), DefaultDurationS: int64(r.DefaultDuration / time.Second),
			MaxDurationS: int64(r.MaxDuration / time.Second), MaxConcurrent: int64(r.MaxConcurrent),
			MaxConcurrentPerAgent: int64(r.MaxConcurrentPerAgent), RecordInput: b2i(r.RecordInput), RecordingMode: r.RecordingMode,
			EnvAllowJson: jsonList(r.EnvAllow), ApprovalChannelsJson: jsonList(r.ApprovalChannels), RestrictionNotes: r.RestrictionNotes,
			RetentionClass: r.RetentionClass, Enabled: b2i(r.Enabled), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros(),
			UpdatedBy: actorRef(actor), GitRulesJson: gitRulesJSON(r.Git), ApprovalsRequired: int64(r.ApprovalsRequired),
		}); err != nil {
			return err
		}
		if err := tx.Q.SetRoleAPIRules(ctx, db.SetRoleAPIRulesParams{ApiRulesJson: apiJSON(r.API), ID: id}); err != nil {
			return err
		}
		if err := groups.SetLabels(ctx, tx, groups.EntityRole, id, r.Labels); err != nil {
			return err
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "role.created", Target: audit.Target{Type: "role", ID: id},
			Details: map[string]any{"server_id": serverID, "alias": r.Alias, "remote_user": r.RemoteUser, "capabilities": r.Capabilities,
				"max_duration": r.MaxDuration.String(), "recording_mode": r.RecordingMode, "record_input": r.RecordInput, "git": r.Git,
				"approvals_required": r.ApprovalsRequired, "api": r.API}})
		svc.publish(tx, eventbus.TopicInventoryChanged, serverID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetRole(ctx, id)
}

// UpdateRole changes a role (optimistic concurrency on Version).
func (svc *Service) UpdateRole(ctx context.Context, actor audit.Actor, id string, in RoleInput) (*Role, error) {
	cur, err := svc.GetRole(ctx, id)
	if err == nil && cur.Deleted() {
		err = apperr.New(apperr.CodeNotFound, "role not found")
	}
	if err != nil {
		return nil, err
	}
	srv, err := svc.GetServer(ctx, cur.ServerID)
	if err != nil {
		return nil, err
	}
	next := *cur
	applyRoleInput(&next, in)
	v := &apperr.Validation{}
	svc.validateRole(v, &next, srv.Kind)
	if err := v.Err(); err != nil {
		return nil, err
	}
	err = svc.s.W().TxNamed(ctx, "inventory.update_role", func(tx *store.Tx) error {
		if next.Alias != cur.Alias {
			if o, err := tx.Q.GetRoleByAlias(ctx, db.GetRoleByAliasParams{ServerID: cur.ServerID, Alias: next.Alias}); err == nil && o.ID != id {
				return apperr.New(apperr.CodeAlreadyExists, "role %q already exists on this server", next.Alias)
			}
		}
		n, err := tx.Q.UpdateRole(ctx, db.UpdateRoleParams{
			Alias: next.Alias, DisplayName: next.DisplayName, Description: next.Description, RemoteUser: next.RemoteUser,
			CapabilitiesJson: jsonList(next.Capabilities), DefaultDurationS: int64(next.DefaultDuration / time.Second),
			MaxDurationS: int64(next.MaxDuration / time.Second), MaxConcurrent: int64(next.MaxConcurrent),
			MaxConcurrentPerAgent: int64(next.MaxConcurrentPerAgent), RecordInput: b2i(next.RecordInput),
			RecordingMode: next.RecordingMode, EnvAllowJson: jsonList(next.EnvAllow), ApprovalChannelsJson: jsonList(next.ApprovalChannels),
			RestrictionNotes: next.RestrictionNotes, RetentionClass: next.RetentionClass, GitRulesJson: gitRulesJSON(next.Git),
			ApprovalsRequired: int64(next.ApprovalsRequired),
			UpdatedAt:         tx.NowMicros(), UpdatedBy: actorRef(actor), ID: id, Version: in.Version,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeConflict, "role was modified concurrently; reload and retry")
		}
		if err := tx.Q.SetRoleAPIRules(ctx, db.SetRoleAPIRulesParams{ApiRulesJson: apiJSON(next.API), ID: id}); err != nil {
			return err
		}
		if in.Labels != nil {
			if err := groups.SetLabels(ctx, tx, groups.EntityRole, id, next.Labels); err != nil {
				return err
			}
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "role.updated", Target: audit.Target{Type: "role", ID: id},
			Details: map[string]any{"alias": next.Alias, "remote_user": next.RemoteUser, "capabilities": next.Capabilities,
				"max_duration": next.MaxDuration.String(), "recording_mode": next.RecordingMode, "record_input": next.RecordInput, "git": next.Git,
				"approvals_required": next.ApprovalsRequired, "api": next.API}})
		svc.publish(tx, eventbus.TopicInventoryChanged, cur.ServerID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetRole(ctx, id)
}

// SetRoleEnabled enables or disables a role; disabling revokes dependent access via hooks.
func (svc *Service) SetRoleEnabled(ctx context.Context, actor audit.Actor, id string, enabled bool) (*Role, error) {
	err := svc.s.W().TxNamed(ctx, "inventory.role_enabled", func(tx *store.Tx) error {
		r, err := tx.Q.GetRole(ctx, id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && r.DeletedAt.Valid) {
			return apperr.New(apperr.CodeNotFound, "role not found")
		} else if err != nil {
			return err
		}
		n, err := tx.Q.SetRoleEnabled(ctx, db.SetRoleEnabledParams{Enabled: b2i(enabled), Now: tx.NowMicros(), Actor: actorRef(actor), ID: id})
		if err != nil || n == 0 {
			return err
		}
		if !enabled {
			if err := svc.runDisableHooks(ctx, tx, "role", id); err != nil {
				return err
			}
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		action, topic := "role.enabled", eventbus.TopicInventoryChanged
		if !enabled {
			action, topic = "role.disabled", eventbus.TopicTargetDisabled
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, Target: audit.Target{Type: "role", ID: id},
			Details: map[string]any{"server_id": r.ServerID}})
		svc.publish(tx, topic, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetRole(ctx, id)
}

// DeleteRole deletes a role or access profile: it is disabled (revoking grants and canceling pending requests), its
// login keys are revoked, and it disappears from lists and policy. The row stays so history can name it, and the
// alias becomes free for reuse.
func (svc *Service) DeleteRole(ctx context.Context, actor audit.Actor, id string) error {
	return svc.s.W().TxNamed(ctx, "inventory.delete_role", func(tx *store.Tx) error {
		r, err := tx.Q.GetRole(ctx, id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && r.DeletedAt.Valid) {
			return apperr.New(apperr.CodeNotFound, "role not found")
		} else if err != nil {
			return err
		}
		revoked, err := svc.deleteRoleTx(ctx, tx, actor, id)
		if err != nil {
			return err
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "role.deleted", Target: audit.Target{Type: "role", ID: id},
			Details: map[string]any{"server_id": r.ServerID, "alias": r.Alias, "revoked_credentials": revoked}})
		svc.publish(tx, eventbus.TopicTargetDisabled, id)
		return err
	})
}

// deleteRoleTx marks a role deleted, ends its access and revokes its login keys; it returns the revoked key IDs.
func (svc *Service) deleteRoleTx(ctx context.Context, tx *store.Tx, actor audit.Actor, id string) ([]string, error) {
	if _, err := tx.Q.DeleteRole(ctx, db.DeleteRoleParams{Now: nullNow(tx), Actor: nullActor(actor), ID: id}); err != nil {
		return nil, err
	}
	if err := svc.runDisableHooks(ctx, tx, "role", id); err != nil {
		return nil, err
	}
	// A deleted API access profile's credential is destroyed, not kept for history.
	if _, err := tx.Q.DeleteAPICredential(ctx, id); err != nil {
		return nil, err
	}
	return tx.Q.RevokeRoleLoginCredentials(ctx, db.RevokeRoleLoginCredentialsParams{Now: nullNow(tx), RoleID: id})
}

// GetRole returns a role with labels. A deleted role is returned too, with DeletedAt set; changes to it are refused.
func (svc *Service) GetRole(ctx context.Context, id string) (*Role, error) {
	r, err := svc.s.R().GetRole(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "role not found")
	}
	if err != nil {
		return nil, err
	}
	role := RoleFromRow(r)
	if role.Labels, err = groups.Labels(ctx, svc.s.R(), groups.EntityRole, id); err != nil {
		return nil, err
	}
	return role, nil
}

// ListRoles returns the roles of a server.
func (svc *Service) ListRoles(ctx context.Context, serverID string) ([]*Role, error) {
	rows, err := svc.s.R().ListRoles(ctx, serverID)
	if err != nil {
		return nil, err
	}
	labels, err := groups.AllLabels(ctx, svc.s.R(), groups.EntityRole)
	if err != nil {
		return nil, err
	}
	out := make([]*Role, 0, len(rows))
	for _, r := range rows {
		role := RoleFromRow(r)
		if l := labels[r.ID]; l != nil {
			role.Labels = l
		}
		out = append(out, role)
	}
	return out, nil
}

// RoleFromRow converts a database row.
func RoleFromRow(r db.ServerRole) *Role {
	role := &Role{
		ID: r.ID, ServerID: r.ServerID, Alias: r.Alias, DisplayName: r.DisplayName, Description: r.Description,
		RemoteUser: r.RemoteUser, DefaultDuration: time.Duration(r.DefaultDurationS) * time.Second,
		MaxDuration: time.Duration(r.MaxDurationS) * time.Second, MaxConcurrent: int(r.MaxConcurrent),
		MaxConcurrentPerAgent: int(r.MaxConcurrentPerAgent), RecordInput: r.RecordInput == 1, RecordingMode: r.RecordingMode,
		RestrictionNotes: r.RestrictionNotes, RetentionClass: r.RetentionClass, Enabled: r.Enabled == 1, Version: r.Version,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), UpdatedAt: time.UnixMicro(r.UpdatedAt).UTC(), Labels: map[string]string{},
		ApprovalsRequired: int(r.ApprovalsRequired),
	}
	_ = json.Unmarshal([]byte(r.CapabilitiesJson), &role.Capabilities)
	_ = json.Unmarshal([]byte(r.EnvAllowJson), &role.EnvAllow)
	_ = json.Unmarshal([]byte(r.ApprovalChannelsJson), &role.ApprovalChannels)
	if r.GitRulesJson.Valid {
		var g GitRules
		if json.Unmarshal([]byte(r.GitRulesJson.String), &g) == nil {
			role.Git = &g
		}
	}
	if r.ApiRulesJson.Valid {
		var a APIRules
		if json.Unmarshal([]byte(r.ApiRulesJson.String), &a) == nil {
			role.API = &a
		}
	}
	if r.DeletedAt.Valid {
		t := time.UnixMicro(r.DeletedAt.Int64).UTC()
		role.DeletedAt, role.Alias, role.Enabled = &t, r.DeletedAlias.String, false
	}
	return role
}
