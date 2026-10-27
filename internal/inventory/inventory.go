// Package inventory manages destination servers, their access roles and their SSH host identities (HP-SRV-*).
//
// Host identities verify destinations; they never grant login. Login credentials live in package credentials,
// and certificate authorities are separate types again (HP-KEY-006).
package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/egress"
	"github.com/aurimasniekis/go-hallpass/internal/eventbus"
	"github.com/aurimasniekis/go-hallpass/internal/groups"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Limits and defaults.
const (
	MaxDescriptionLen = 4000
	MaxNameLen        = 128
)

// Capabilities a role can grant (channel types; not a command sandbox, HP-POL-014). Git remotes use only the git
// capabilities; SSH servers only the others.
const (
	CapShell    = "shell"
	CapExec     = "exec"
	CapPTY      = "pty"
	CapGitRead  = "git-read"  // clone, fetch, archive
	CapGitWrite = "git-write" // push
	// CapFileTransfer allows SFTP (and scp, which uses SFTP) to the server. Every file operation is recorded.
	CapFileTransfer = "file-transfer"
	// CapAPI allows HTTPS requests to an API target through the API proxy, as the profile's rules permit.
	CapAPI = "api"
)

// AllCapabilities lists valid capabilities.
var AllCapabilities = []string{CapShell, CapExec, CapPTY, CapGitRead, CapGitWrite, CapFileTransfer, CapAPI}

// Server kinds.
const (
	KindSSH = "ssh" // a destination host agents reach with shell and exec
	KindGit = "git" // a git host agents reach with plain git through the gateway
	KindAPI = "api" // an HTTPS API agents call through the gateway's API proxy
)

// Approval channels.
var AllApprovalChannels = []string{"web", "slack", "telegram"}

// Server is a destination host.
type Server struct {
	ID           string            `json:"id"`
	Kind         string            `json:"kind"`
	Alias        string            `json:"alias"`
	DisplayName  string            `json:"display_name"`
	Description  string            `json:"description"`
	Environment  string            `json:"environment"`
	Address      string            `json:"address"`
	Port         int               `json:"port"`
	Enabled      bool              `json:"enabled"`
	HostCAID     string            `json:"host_ca_id,omitempty"`
	Principals   []string          `json:"host_ca_principals"`
	Metadata     map[string]string `json:"metadata"`
	Groups       []string          `json:"groups"`
	Labels       map[string]string `json:"labels"`
	Version      int64             `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	UpdatedBy    string            `json:"updated_by"`
	ActiveHostID int               `json:"active_host_identities"`
	// API holds the host names of an API target; nil for other kinds.
	API *APITarget `json:"api,omitempty"`
	// DeletedAt is set for a deleted server, which is kept only so history can name it (Alias is its former name).
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Deleted reports whether the server was deleted.
func (s *Server) Deleted() bool { return s.DeletedAt != nil }

// Role is a way to log in to a server.
type Role struct {
	ID                    string            `json:"id"`
	ServerID              string            `json:"server_id"`
	Alias                 string            `json:"alias"`
	DisplayName           string            `json:"display_name"`
	Description           string            `json:"description"`
	RemoteUser            string            `json:"remote_user"`
	Capabilities          []string          `json:"capabilities"`
	DefaultDuration       time.Duration     `json:"default_duration"`
	MaxDuration           time.Duration     `json:"max_duration"`
	MaxConcurrent         int               `json:"max_concurrent"`
	MaxConcurrentPerAgent int               `json:"max_concurrent_per_agent"`
	RecordInput           bool              `json:"record_input"`
	RecordingMode         string            `json:"recording_mode"`
	EnvAllow              []string          `json:"env_allow"`
	ApprovalChannels      []string          `json:"approval_channels"`
	RestrictionNotes      string            `json:"restriction_notes"`
	RetentionClass        string            `json:"retention_class"`
	Labels                map[string]string `json:"labels"`
	Enabled               bool              `json:"enabled"`
	Version               int64             `json:"version"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
	// Git holds the repository and push rules of a git remote's access profile; nil for SSH roles.
	Git *GitRules `json:"git,omitempty"`
	// API holds the request rules of an API target's access profile; nil for other kinds.
	API *APIRules `json:"api,omitempty"`
	// ApprovalsRequired is how many distinct approvers must approve a request (1..5). Above 1, policy auto-approval
	// does not apply to the role.
	ApprovalsRequired int `json:"approvals_required"`
	// DeletedAt is set for a deleted role, which is kept only so history can name it (Alias is its former name).
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Deleted reports whether the role was deleted.
func (r *Role) Deleted() bool { return r.DeletedAt != nil }

// Has reports whether the role grants capability c.
func (r *Role) Has(c string) bool { return slices.Contains(r.Capabilities, c) }

// TxHook runs inside a transaction that disables a server or role (kind "server" or "role").
type TxHook func(ctx context.Context, tx *store.Tx, kind, id string) error

// Options configure the service.
type Options struct {
	Guard            *egress.Guard
	MaxGrantDuration time.Duration
	Clock            clock.Clock
	DialTimeout      time.Duration
}

// Service manages inventory.
type Service struct {
	s     *store.Store
	audit *audit.Writer
	bus   *eventbus.Bus
	opts  Options

	mu          sync.RWMutex
	disableHook []TxHook
}

// New returns an inventory service.
func New(s *store.Store, aw *audit.Writer, bus *eventbus.Bus, o Options) *Service {
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.MaxGrantDuration <= 0 {
		o.MaxGrantDuration = 24 * time.Hour
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	return &Service{s: s, audit: aw, bus: bus, opts: o}
}

// OnDisable registers a hook run inside server/role disable transactions (HP-SRV-008).
func (svc *Service) OnDisable(h TxHook) {
	svc.mu.Lock()
	svc.disableHook = append(svc.disableHook, h)
	svc.mu.Unlock()
}

func (svc *Service) runDisableHooks(ctx context.Context, tx *store.Tx, kind, id string) error {
	svc.mu.RLock()
	hooks := slices.Clone(svc.disableHook)
	svc.mu.RUnlock()
	for _, h := range hooks {
		if err := h(ctx, tx, kind, id); err != nil {
			return err
		}
	}
	return nil
}

// bumpPolicy increments policy_version and publishes policy.changed after commit. Server, role, group, label and
// limit changes alter policy evaluation, so the access service must re-apply policy to pending requests and active
// grants within the enforcement bound (HP-POL-008, SR-12); inventory.changed alone has no reconciling subscriber.
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

func (svc *Service) publish(tx *store.Tx, topic, key string) {
	tx.AfterCommit(func() {
		if svc.bus != nil {
			svc.bus.Publish(eventbus.Event{Topic: topic, Key: key})
		}
	})
}

// ServerInput creates or updates a server. On update, nil pointer fields keep current values.
type ServerInput struct {
	Version     int64              `json:"version,omitempty"`
	Kind        *string            `json:"kind,omitempty"` // set on create only
	Alias       *string            `json:"alias,omitempty"`
	DisplayName *string            `json:"display_name,omitempty"`
	Description *string            `json:"description,omitempty"`
	Environment *string            `json:"environment,omitempty"`
	Address     *string            `json:"address,omitempty"`
	Port        *int               `json:"port,omitempty"`
	Enabled     *bool              `json:"enabled,omitempty"`
	Metadata    *map[string]string `json:"metadata,omitempty"`
	Groups      *[]string          `json:"groups,omitempty"`
	Labels      *map[string]string `json:"labels,omitempty"`
	// API sets the host names of an API target (kind api); its address and port follow from them.
	API *APITarget `json:"api,omitempty"`
}

func deref[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

func (svc *Service) validateServer(v *apperr.Validation, s *Server) {
	if s.Kind != KindSSH && s.Kind != KindGit && s.Kind != KindAPI {
		v.Add("kind", "must be ssh, git or api")
	}
	if !ValidAlias(s.Alias) {
		v.Add("alias", "%s", AliasRule)
	}
	if s.DisplayName == "" || len(s.DisplayName) > MaxNameLen {
		v.Add("display_name", "required, at most %d bytes", MaxNameLen)
	}
	if len(s.Description) > MaxDescriptionLen {
		v.Add("description", "at most %d bytes", MaxDescriptionLen)
	}
	if len(s.Environment) > 64 {
		v.Add("environment", "at most 64 bytes")
	}
	if s.Kind == KindAPI {
		// API hosts are reached through the API proxy's own egress policy, on port 443 only.
		validateAPITarget(v, s)
	} else if s.API != nil {
		v.Add("api", "host names are only for API targets")
	} else if svc.opts.Guard == nil {
		v.Add("address", "egress policy not configured")
	} else if err := svc.opts.Guard.ValidateDestination(s.Address, s.Port); err != nil {
		v.Add("address", "%s", err.Error())
	}
	if len(s.Metadata) > 32 {
		v.Add("metadata", "at most 32 entries")
	}
	groups.ValidateGroupNames(v, "groups", s.Groups)
	groups.ValidateLabels(v, "labels", s.Labels)
}

// CreateServer adds a destination server.
func (svc *Service) CreateServer(ctx context.Context, actor audit.Actor, in ServerInput) (*Server, error) {
	srv := &Server{
		Kind:  deref(in.Kind, KindSSH),
		Alias: deref(in.Alias, ""), DisplayName: deref(in.DisplayName, ""), Description: deref(in.Description, ""),
		Environment: deref(in.Environment, ""), Address: deref(in.Address, ""), Port: deref(in.Port, 22),
		Enabled: deref(in.Enabled, true), Metadata: deref(in.Metadata, map[string]string{}),
		Groups: deref(in.Groups, []string{}), Labels: deref(in.Labels, map[string]string{}),
	}
	if srv.DisplayName == "" {
		srv.DisplayName = srv.Alias
	}
	if srv.API = normalizeAPITarget(in.API); srv.Kind == KindAPI {
		srv.Address, srv.Port = srv.API.PrimaryHost(), APIPort
	}
	v := &apperr.Validation{}
	svc.validateServer(v, srv)
	if err := v.Err(); err != nil {
		return nil, err
	}
	id := ids.New(ids.Server)
	meta, _ := json.Marshal(srv.Metadata)
	err := svc.s.W().TxNamed(ctx, "inventory.create_server", func(tx *store.Tx) error {
		if _, err := tx.Q.GetServerByAlias(ctx, srv.Alias); err == nil {
			return apperr.New(apperr.CodeAlreadyExists, "a server with alias %q already exists", srv.Alias)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := tx.Q.InsertServer(ctx, db.InsertServerParams{
			ID: id, Alias: srv.Alias, DisplayName: srv.DisplayName, Description: srv.Description, Environment: srv.Environment,
			Address: srv.Address, Port: int64(srv.Port), Enabled: b2i(srv.Enabled), MetadataJson: string(meta),
			CreatedAt: tx.NowMicros(), CreatedBy: actorRef(actor), UpdatedAt: tx.NowMicros(), UpdatedBy: actorRef(actor),
			Kind: srv.Kind,
		}); err != nil {
			return err
		}
		if err := tx.Q.SetServerAPIHosts(ctx, db.SetServerAPIHostsParams{ApiHostsJson: apiJSON(srv.API), ID: id}); err != nil {
			return err
		}
		if err := svc.setServerGroupsLabels(ctx, tx, id, srv.Groups, srv.Labels); err != nil {
			return err
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.created", Target: audit.Target{Type: "server", ID: id},
			Details: map[string]any{"kind": srv.Kind, "alias": srv.Alias, "address": srv.Address, "port": srv.Port, "enabled": srv.Enabled, "api": srv.API}})
		svc.publish(tx, eventbus.TopicInventoryChanged, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetServer(ctx, id)
}

func (svc *Service) setServerGroupsLabels(ctx context.Context, tx *store.Tx, id string, grps []string, labels map[string]string) error {
	if grps != nil {
		gids, err := groups.Ensure(ctx, tx, groups.KindServer, grps)
		if err != nil {
			return err
		}
		if err := tx.Q.DeleteServerGroups(ctx, id); err != nil {
			return err
		}
		for _, g := range gids {
			if err := tx.Q.InsertServerGroup(ctx, db.InsertServerGroupParams{ServerID: id, GroupID: g}); err != nil {
				return err
			}
		}
	}
	if labels != nil {
		return groups.SetLabels(ctx, tx, groups.EntityServer, id, labels)
	}
	return nil
}

// UpdateServer changes server attributes (optimistic concurrency on Version).
func (svc *Service) UpdateServer(ctx context.Context, actor audit.Actor, id string, in ServerInput) (*Server, error) {
	cur, err := svc.liveServer(ctx, id)
	if err != nil {
		return nil, err
	}
	next := *cur
	next.Alias = deref(in.Alias, cur.Alias)
	next.DisplayName = deref(in.DisplayName, cur.DisplayName)
	next.Description = deref(in.Description, cur.Description)
	next.Environment = deref(in.Environment, cur.Environment)
	next.Address = deref(in.Address, cur.Address)
	next.Port = deref(in.Port, cur.Port)
	next.Metadata = deref(in.Metadata, cur.Metadata)
	next.Groups = deref(in.Groups, cur.Groups)
	next.Labels = deref(in.Labels, cur.Labels)
	if in.API != nil {
		next.API = normalizeAPITarget(in.API)
	}
	if next.Kind == KindAPI {
		next.Address, next.Port = next.API.PrimaryHost(), APIPort
	}
	v := &apperr.Validation{}
	if in.Kind != nil && *in.Kind != cur.Kind {
		v.Add("kind", "cannot be changed after the server is created")
	}
	svc.validateServer(v, &next)
	if err := v.Err(); err != nil {
		return nil, err
	}
	meta, _ := json.Marshal(next.Metadata)
	err = svc.s.W().TxNamed(ctx, "inventory.update_server", func(tx *store.Tx) error {
		if next.Alias != cur.Alias {
			if o, err := tx.Q.GetServerByAlias(ctx, next.Alias); err == nil && o.ID != id {
				return apperr.New(apperr.CodeAlreadyExists, "a server with alias %q already exists", next.Alias)
			}
		}
		n, err := tx.Q.UpdateServer(ctx, db.UpdateServerParams{
			Alias: next.Alias, DisplayName: next.DisplayName, Description: next.Description, Environment: next.Environment,
			Address: next.Address, Port: int64(next.Port), MetadataJson: string(meta), UpdatedAt: tx.NowMicros(),
			UpdatedBy: actorRef(actor), ID: id, Version: in.Version,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeConflict, "server was modified concurrently; reload and retry")
		}
		if err := tx.Q.SetServerAPIHosts(ctx, db.SetServerAPIHostsParams{ApiHostsJson: apiJSON(next.API), ID: id}); err != nil {
			return err
		}
		var grps []string
		var labels map[string]string
		if in.Groups != nil {
			grps = next.Groups
		}
		if in.Labels != nil {
			labels = next.Labels
		}
		if err := svc.setServerGroupsLabels(ctx, tx, id, grps, labels); err != nil {
			return err
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		details := map[string]any{"alias": next.Alias}
		if next.Address != cur.Address || next.Port != cur.Port {
			details["address"], details["port"], details["previous_address"] = next.Address, next.Port, cur.Address+":"+strconv.Itoa(cur.Port)
		}
		if next.API != nil && !slices.Equal(next.API.Hosts, cur.API.Hosts) {
			details["api"], details["previous_api"] = next.API, cur.API
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.updated", Target: audit.Target{Type: "server", ID: id}, Details: details})
		svc.publish(tx, eventbus.TopicInventoryChanged, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetServer(ctx, id)
}

// SetServerEnabled enables or disables a server; disabling revokes dependent access via hooks (HP-SRV-008).
func (svc *Service) SetServerEnabled(ctx context.Context, actor audit.Actor, id string, enabled bool) (*Server, error) {
	err := svc.s.W().TxNamed(ctx, "inventory.server_enabled", func(tx *store.Tx) error {
		if r, err := tx.Q.GetServer(ctx, id); errors.Is(err, sql.ErrNoRows) || (err == nil && r.DeletedAt.Valid) {
			return apperr.New(apperr.CodeNotFound, "server not found")
		} else if err != nil {
			return err
		}
		n, err := tx.Q.SetServerEnabled(ctx, db.SetServerEnabledParams{Enabled: b2i(enabled), Now: tx.NowMicros(), Actor: actorRef(actor), ID: id})
		if err != nil || n == 0 {
			return err
		}
		if !enabled {
			if err := svc.runDisableHooks(ctx, tx, "server", id); err != nil {
				return err
			}
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		action, topic := "server.enabled", eventbus.TopicInventoryChanged
		if !enabled {
			action, topic = "server.disabled", eventbus.TopicTargetDisabled
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, Target: audit.Target{Type: "server", ID: id}})
		svc.publish(tx, topic, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetServer(ctx, id)
}

// liveServer returns a server that is not deleted: a deleted one cannot be changed.
func (svc *Service) liveServer(ctx context.Context, id string) (*Server, error) {
	srv, err := svc.GetServer(ctx, id)
	if err == nil && srv.Deleted() {
		return nil, apperr.New(apperr.CodeNotFound, "server not found")
	}
	return srv, err
}

// DeleteServer deletes a server or git remote and all its roles: they are disabled (revoking grants and canceling
// pending requests), their login keys are revoked, and they disappear from lists and policy. The rows stay so history
// can name them, and the aliases become free for reuse.
func (svc *Service) DeleteServer(ctx context.Context, actor audit.Actor, id string) error {
	return svc.s.W().TxNamed(ctx, "inventory.delete_server", func(tx *store.Tx) error {
		r, err := tx.Q.GetServer(ctx, id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && r.DeletedAt.Valid) {
			return apperr.New(apperr.CodeNotFound, "server not found")
		} else if err != nil {
			return err
		}
		roles, err := tx.Q.ListRoles(ctx, id)
		if err != nil {
			return err
		}
		var aliases, revoked []string
		for _, role := range roles {
			keys, err := svc.deleteRoleTx(ctx, tx, actor, role.ID)
			if err != nil {
				return err
			}
			aliases, revoked = append(aliases, role.Alias), append(revoked, keys...)
		}
		if _, err := tx.Q.DeleteServer(ctx, db.DeleteServerParams{Now: nullNow(tx), Actor: nullActor(actor), ID: id}); err != nil {
			return err
		}
		if err := svc.runDisableHooks(ctx, tx, "server", id); err != nil {
			return err
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.deleted", Target: audit.Target{Type: "server", ID: id},
			Details: map[string]any{"alias": r.Alias, "kind": r.Kind, "roles": aliases, "revoked_credentials": revoked}})
		svc.publish(tx, eventbus.TopicTargetDisabled, id)
		return err
	})
}

// GetServer returns a server with groups, labels and host-CA principals. A deleted server is returned too, with
// DeletedAt set; changes to it are refused.
func (svc *Service) GetServer(ctx context.Context, id string) (*Server, error) {
	r, err := svc.s.R().GetServer(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "server not found")
	}
	if err != nil {
		return nil, err
	}
	return svc.hydrateServer(ctx, r)
}

// GetServerByAlias looks a server up by alias.
func (svc *Service) GetServerByAlias(ctx context.Context, alias string) (*Server, error) {
	r, err := svc.s.R().GetServerByAlias(ctx, alias)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "server not found")
	}
	if err != nil {
		return nil, err
	}
	return svc.hydrateServer(ctx, r)
}

func (svc *Service) hydrateServer(ctx context.Context, r db.Server) (*Server, error) {
	srv := serverFromRow(r)
	var err error
	if srv.Groups, err = svc.s.R().ListServerGroupNames(ctx, r.ID); err != nil {
		return nil, err
	}
	if srv.Labels, err = groups.Labels(ctx, svc.s.R(), groups.EntityServer, r.ID); err != nil {
		return nil, err
	}
	if srv.Principals, err = svc.s.R().ListHostCAPrincipals(ctx, r.ID); err != nil {
		return nil, err
	}
	hids, err := svc.s.R().ListHostIdentities(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	for _, h := range hids {
		if h.State == "active" {
			srv.ActiveHostID++
		}
	}
	return srv, nil
}

// ListServers returns every server that is not deleted (groups and labels included).
func (svc *Service) ListServers(ctx context.Context) ([]*Server, error) {
	rows, err := svc.s.R().ListServers(ctx)
	if err != nil {
		return nil, err
	}
	return svc.listServers(ctx, rows)
}

// ListServersWithDeleted also returns deleted servers, for naming them in history.
func (svc *Service) ListServersWithDeleted(ctx context.Context) ([]*Server, error) {
	rows, err := svc.s.R().ListServersWithDeleted(ctx)
	if err != nil {
		return nil, err
	}
	return svc.listServers(ctx, rows)
}

func (svc *Service) listServers(ctx context.Context, rows []db.Server) ([]*Server, error) {
	gs, err := svc.s.R().ListAllServerGroups(ctx)
	if err != nil {
		return nil, err
	}
	byServer := map[string][]string{}
	for _, g := range gs {
		byServer[g.ServerID] = append(byServer[g.ServerID], g.Name)
	}
	labels, err := groups.AllLabels(ctx, svc.s.R(), groups.EntityServer)
	if err != nil {
		return nil, err
	}
	counts, err := svc.s.R().CountActiveHostIdentitiesByServer(ctx)
	if err != nil {
		return nil, err
	}
	activeHostIDs := make(map[string]int, len(counts))
	for _, c := range counts {
		activeHostIDs[c.ServerID] = int(c.Active)
	}
	out := make([]*Server, 0, len(rows))
	for _, r := range rows {
		s := serverFromRow(r)
		s.ActiveHostID = activeHostIDs[r.ID]
		s.Groups = append(s.Groups, byServer[r.ID]...)
		if l := labels[r.ID]; l != nil {
			s.Labels = l
		}
		out = append(out, s)
	}
	return out, nil
}

func serverFromRow(r db.Server) *Server {
	s := &Server{
		ID: r.ID, Kind: r.Kind, Alias: r.Alias, DisplayName: r.DisplayName, Description: r.Description, Environment: r.Environment,
		Address: r.Address, Port: int(r.Port), Enabled: r.Enabled == 1, HostCAID: r.HostCaID.String, Version: r.Version,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), UpdatedAt: time.UnixMicro(r.UpdatedAt).UTC(), UpdatedBy: r.UpdatedBy,
		Metadata: map[string]string{}, Groups: []string{}, Labels: map[string]string{}, Principals: []string{},
	}
	_ = json.Unmarshal([]byte(r.MetadataJson), &s.Metadata)
	if r.ApiHostsJson.Valid {
		var a APITarget
		if json.Unmarshal([]byte(r.ApiHostsJson.String), &a) == nil {
			s.API = &a
		}
	}
	if r.DeletedAt.Valid {
		t := time.UnixMicro(r.DeletedAt.Int64).UTC()
		s.DeletedAt, s.Alias, s.Enabled = &t, r.DeletedAlias.String, false
	}
	return s
}

func nullNow(tx *store.Tx) sql.NullInt64 { return sql.NullInt64{Int64: tx.NowMicros(), Valid: true} }

func nullActor(a audit.Actor) sql.NullString { return sql.NullString{String: actorRef(a), Valid: true} }

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
