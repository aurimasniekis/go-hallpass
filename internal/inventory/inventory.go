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

// Capabilities a role can grant (channel types; not a command sandbox, HP-POL-014).
const (
	CapShell = "shell"
	CapExec  = "exec"
	CapPTY   = "pty"
)

// AllCapabilities lists valid capabilities.
var AllCapabilities = []string{CapShell, CapExec, CapPTY}

// Approval channels.
var AllApprovalChannels = []string{"web", "slack", "telegram"}

// Server is a destination host.
type Server struct {
	ID           string            `json:"id"`
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
}

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
}

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
}

func deref[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

func (svc *Service) validateServer(v *apperr.Validation, s *Server) {
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
	if svc.opts.Guard == nil {
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
		Alias: deref(in.Alias, ""), DisplayName: deref(in.DisplayName, ""), Description: deref(in.Description, ""),
		Environment: deref(in.Environment, ""), Address: deref(in.Address, ""), Port: deref(in.Port, 22),
		Enabled: deref(in.Enabled, true), Metadata: deref(in.Metadata, map[string]string{}),
		Groups: deref(in.Groups, []string{}), Labels: deref(in.Labels, map[string]string{}),
	}
	if srv.DisplayName == "" {
		srv.DisplayName = srv.Alias
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
		}); err != nil {
			return err
		}
		if err := svc.setServerGroupsLabels(ctx, tx, id, srv.Groups, srv.Labels); err != nil {
			return err
		}
		if err := svc.bumpPolicy(ctx, tx); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "server.created", Target: audit.Target{Type: "server", ID: id},
			Details: map[string]any{"alias": srv.Alias, "address": srv.Address, "port": srv.Port, "enabled": srv.Enabled}})
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
	cur, err := svc.GetServer(ctx, id)
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
	v := &apperr.Validation{}
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
		if _, err := tx.Q.GetServer(ctx, id); errors.Is(err, sql.ErrNoRows) {
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

// GetServer returns a server with groups, labels and host-CA principals.
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

// ListServers returns every server (groups and labels included).
func (svc *Service) ListServers(ctx context.Context) ([]*Server, error) {
	rows, err := svc.s.R().ListServers(ctx)
	if err != nil {
		return nil, err
	}
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
	out := make([]*Server, 0, len(rows))
	for _, r := range rows {
		s := serverFromRow(r)
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
		ID: r.ID, Alias: r.Alias, DisplayName: r.DisplayName, Description: r.Description, Environment: r.Environment,
		Address: r.Address, Port: int(r.Port), Enabled: r.Enabled == 1, HostCAID: r.HostCaID.String, Version: r.Version,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), UpdatedAt: time.UnixMicro(r.UpdatedAt).UTC(), UpdatedBy: r.UpdatedBy,
		Metadata: map[string]string{}, Groups: []string{}, Labels: map[string]string{}, Principals: []string{},
	}
	_ = json.Unmarshal([]byte(r.MetadataJson), &s.Metadata)
	return s
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
