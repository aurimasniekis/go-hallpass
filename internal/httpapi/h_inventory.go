package httpapi

import (
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/credentials"
	"github.com/aurimasniekis/go-hallpass/internal/groups"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
)

// ---- agents

func (s *Server) ListAgents(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Agents.List(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) CreateAgent(c *gen.Call) (*gen.Result, error) {
	var in agents.CreateInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	a, err := s.d.Agents.Create(c.R.Context(), actor(c), in)
	if err != nil {
		return nil, err
	}
	return created(a)
}

func (s *Server) GetAgent(c *gen.Call) (*gen.Result, error) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	a, err := s.d.Agents.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	keys, err := s.d.Agents.Keys(ctx, id)
	if err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []*agents.Key{}
	}
	return ok(struct {
		*agents.Agent
		Keys []*agents.Key `json:"keys"`
	}{a, keys})
}

func (s *Server) UpdateAgent(c *gen.Call) (*gen.Result, error) {
	var in agents.UpdateInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := ifMatch(c, in.Version)
	if err != nil {
		return nil, err
	}
	in.Version = v
	a, err := s.d.Agents.Update(c.R.Context(), actor(c), c.R.PathValue("id"), in)
	if err != nil {
		return nil, err
	}
	return ok(a)
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func (s *Server) DisableAgent(c *gen.Call) (*gen.Result, error) {
	var in reasonBody
	if err := decode(c, &in, true); err != nil {
		return nil, err
	}
	a, err := s.d.Agents.SetEnabled(c.R.Context(), actor(c), c.R.PathValue("id"), false, in.Reason)
	if err != nil {
		return nil, err
	}
	return ok(a)
}

func (s *Server) EnableAgent(c *gen.Call) (*gen.Result, error) {
	a, err := s.d.Agents.SetEnabled(c.R.Context(), actor(c), c.R.PathValue("id"), true, "")
	if err != nil {
		return nil, err
	}
	return ok(a)
}

func (s *Server) AddAgentKey(c *gen.Call) (*gen.Result, error) {
	var in struct {
		PublicKey string `json:"public_key"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	k, err := s.d.Agents.AddKey(c.R.Context(), actor(c), c.R.PathValue("id"), in.PublicKey)
	if err != nil {
		return nil, err
	}
	return created(k)
}

func (s *Server) RevokeAgentKey(c *gen.Call) (*gen.Result, error) {
	var in reasonBody
	if err := decode(c, &in, true); err != nil {
		return nil, err
	}
	k, err := s.d.Agents.RevokeKey(c.R.Context(), actor(c), c.R.PathValue("id"), c.R.PathValue("kid"), in.Reason)
	if err != nil {
		return nil, err
	}
	return ok(k)
}

func (s *Server) GetAgentEffectiveAccess(c *gen.Call) (*gen.Result, error) {
	snap, err := s.d.Engine.Current(c.R.Context())
	if err != nil {
		return nil, err
	}
	id := c.R.PathValue("id")
	if snap.Agent(id) == nil {
		return nil, apperr.New(apperr.CodeNotFound, "agent not found")
	}
	return ok(effective(snap.Version, policy.PreviewAgent(snap, id)))
}

// ---- agent owners and the self-approval prohibition (HP-POL-012, SR-14)
//
// These handlers are ready for operations getAgentOwners (GET /api/v1/agents/{id}/owners, policy.read),
// setAgentOwners (PUT /api/v1/agents/{id}/owners, policy.write, x-reauth, x-mfa), getSelfApprovalSetting
// (GET /api/v1/policy/self-approval, policy.read) and setSelfApprovalSetting (PUT /api/v1/policy/self-approval,
// policy.write, x-reauth, x-mfa). They are reachable once api/openapi.yaml declares them and gen is regenerated.

// GetAgentOwners returns the operators owning an agent.
func (s *Server) GetAgentOwners(c *gen.Call) (*gen.Result, error) {
	id := c.R.PathValue("id")
	owners, err := s.d.Policy.AgentOwners(c.R.Context(), id)
	if err != nil {
		return nil, err
	}
	return ok(agentOwnersDTO{AgentID: id, Owners: nonNil(owners)})
}

// SetAgentOwners replaces the owners of an agent (audited; bumps the policy version).
func (s *Server) SetAgentOwners(c *gen.Call) (*gen.Result, error) {
	var in agentOwnersInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	ctx, id := c.R.Context(), c.R.PathValue("id")
	if err := s.d.Policy.SetAgentOwners(ctx, actor(c), id, in.Owners); err != nil {
		return nil, err
	}
	owners, err := s.d.Policy.AgentOwners(ctx, id)
	if err != nil {
		return nil, err
	}
	return ok(agentOwnersDTO{AgentID: id, Owners: nonNil(owners)})
}

// GetSelfApprovalSetting reports whether agent owners are barred from approving their agents' requests.
func (s *Server) GetSelfApprovalSetting(c *gen.Call) (*gen.Result, error) {
	on, err := s.d.Policy.ProhibitSelfApproval(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(selfApprovalDTO{ProhibitSelfApproval: on})
}

// SetSelfApprovalSetting turns the self-approval prohibition on or off (audited; turning it off is a security
// relaxation, so the operation requires recent authentication and MFA).
func (s *Server) SetSelfApprovalSetting(c *gen.Call) (*gen.Result, error) {
	var in selfApprovalDTO
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.Policy.SetProhibitSelfApproval(c.R.Context(), actor(c), in.ProhibitSelfApproval); err != nil {
		return nil, err
	}
	return ok(in)
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// ---- groups

func (s *Server) ListGroups(c *gen.Call) (*gen.Result, error) {
	kind, err := queryEnum(c.R, "kind", "agent", "server", "operator")
	if err != nil {
		return nil, err
	}
	var out []groups.Group
	kinds := []string{"agent", "server", "operator"}
	if kind != "" {
		kinds = []string{kind}
	}
	for _, k := range kinds {
		g, err := groups.List(c.R.Context(), s.d.Store.R(), k)
		if err != nil {
			return nil, err
		}
		out = append(out, g...)
	}
	return ok(list(out))
}

// ---- servers

func (s *Server) ListServers(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Inventory.ListServers(c.R.Context())
	if err != nil {
		return nil, err
	}
	out := make([]serverDTO, len(v))
	for i, srv := range v {
		out[i] = s.server(c, srv)
	}
	return ok(list(out))
}

func (s *Server) CreateServer(c *gen.Call) (*gen.Result, error) {
	var in inventory.ServerInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := s.d.Inventory.CreateServer(c.R.Context(), actor(c), in)
	if err != nil {
		return nil, err
	}
	return created(s.server(c, v))
}

func (s *Server) GetServer(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Inventory.GetServer(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(s.server(c, v))
}

func (s *Server) UpdateServer(c *gen.Call) (*gen.Result, error) {
	var in inventory.ServerInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := ifMatch(c, in.Version)
	if err != nil {
		return nil, err
	}
	in.Version = v
	if (in.Address != nil || in.Port != nil) && !s.canSeeAddress(c) {
		return nil, apperr.New(apperr.CodeForbidden, "changing the address needs inventory.address.read")
	}
	srv, err := s.d.Inventory.UpdateServer(c.R.Context(), actor(c), c.R.PathValue("id"), in)
	if err != nil {
		return nil, err
	}
	return ok(s.server(c, srv))
}

func (s *Server) GetServerEffectiveAccess(c *gen.Call) (*gen.Result, error) {
	snap, err := s.d.Engine.Current(c.R.Context())
	if err != nil {
		return nil, err
	}
	id := c.R.PathValue("id")
	if snap.Server(id) == nil {
		return nil, apperr.New(apperr.CodeNotFound, "server not found")
	}
	return ok(effective(snap.Version, policy.PreviewServer(snap, id)))
}

func (s *Server) ListHostIdentities(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Inventory.ListHostIdentities(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) AddHostIdentity(c *gen.Call) (*gen.Result, error) {
	var in struct {
		PublicKey string `json:"public_key"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := s.d.Inventory.AddHostIdentity(c.R.Context(), actor(c), c.R.PathValue("id"), in.PublicKey)
	if err != nil {
		return nil, err
	}
	return created(v)
}

func (s *Server) ScanHostIdentities(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Inventory.ScanHostKeys(c.R.Context(), actor(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) ConfirmHostIdentity(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Inventory.ConfirmHostIdentity(c.R.Context(), actor(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) RetireHostIdentity(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Inventory.RetireHostIdentity(c.R.Context(), actor(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) CreateHostCA(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Name        string `json:"name"`
		PublicKey   string `json:"public_key"`
		MaxValidity int64  `json:"max_validity"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	ca, err := s.d.Inventory.CreateHostCA(c.R.Context(), actor(c), in.Name, in.PublicKey, time.Duration(in.MaxValidity)*time.Second)
	if err != nil {
		return nil, err
	}
	return created(hostCADTO{HostCA: ca, MaxValidity: secs(ca.MaxValidity)})
}

func (s *Server) BindHostCA(c *gen.Call) (*gen.Result, error) {
	var in struct {
		HostCAID   string   `json:"host_ca_id"`
		Principals []string `json:"principals"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.Inventory.BindHostCA(c.R.Context(), actor(c), c.R.PathValue("id"), in.HostCAID, in.Principals); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) AddHostDuplicateException(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Fingerprint   string `json:"fingerprint"`
		ServerA       string `json:"server_a"`
		ServerB       string `json:"server_b"`
		Justification string `json:"justification"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.Inventory.AddDuplicateException(c.R.Context(), actor(c), in.Fingerprint, in.ServerA, in.ServerB, in.Justification); err != nil {
		return nil, err
	}
	return noContent()
}

// ---- roles

func (s *Server) ListRoles(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Inventory.ListRoles(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	out := make([]roleDTO, len(v))
	for i, r := range v {
		out[i] = role(r)
	}
	return ok(list(out))
}

func (s *Server) CreateRole(c *gen.Call) (*gen.Result, error) {
	var in roleInputDTO
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	r, err := s.d.Inventory.CreateRole(c.R.Context(), actor(c), c.R.PathValue("id"), in.input())
	if err != nil {
		return nil, err
	}
	return created(role(r))
}

func (s *Server) GetRole(c *gen.Call) (*gen.Result, error) {
	r, err := s.d.Inventory.GetRole(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(role(r))
}

func (s *Server) UpdateRole(c *gen.Call) (*gen.Result, error) {
	var in roleInputDTO
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := ifMatch(c, in.Version)
	if err != nil {
		return nil, err
	}
	in.Version = v
	r, err := s.d.Inventory.UpdateRole(c.R.Context(), actor(c), c.R.PathValue("id"), in.input())
	if err != nil {
		return nil, err
	}
	return ok(role(r))
}

// ---- credentials

func (s *Server) ListCredentials(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Credentials.List(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) GenerateCredential(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Credentials.Generate(c.R.Context(), actor(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return created(v)
}

func (s *Server) ImportCredential(c *gen.Call) (*gen.Result, error) {
	var in struct {
		PEM string `json:"private_key_pem"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := s.d.Credentials.Import(c.R.Context(), actor(c), c.R.PathValue("id"), in.PEM)
	if err != nil {
		return nil, err
	}
	return created(v)
}

func (s *Server) ProbeCredential(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Credentials.Probe(c.R.Context(), actor(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) ActivateCredential(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Credentials.Activate(c.R.Context(), actor(c), c.R.PathValue("id"), c.R.URL.Query().Get("force") == "true")
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) RevokeCredential(c *gen.Call) (*gen.Result, error) {
	var in reasonBody
	if err := decode(c, &in, true); err != nil {
		return nil, err
	}
	v, err := s.d.Credentials.Revoke(c.R.Context(), actor(c), c.R.PathValue("id"), in.Reason)
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) ListUserCAs(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Credentials.ListUserCAs(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) CreateUserCA(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := s.d.Credentials.CreateUserCA(c.R.Context(), actor(c), in.Name)
	if err != nil {
		return nil, err
	}
	return created(v)
}

func (s *Server) BindRoleCert(c *gen.Call) (*gen.Result, error) {
	var in struct {
		UserCAID   string   `json:"user_ca_id"`
		Principals []string `json:"principals"`
		TTL        int64    `json:"ttl"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.Credentials.BindRoleCert(c.R.Context(), actor(c), credentials.CertBinding{RoleID: c.R.PathValue("id"), UserCAID: in.UserCAID,
		Principals: in.Principals, TTL: time.Duration(in.TTL) * time.Second}); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) UnbindRoleCert(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Credentials.UnbindRoleCert(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}
