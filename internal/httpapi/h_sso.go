package httpapi

import (
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/oidc"
)

func (s *Server) provider(p *oidc.Provider) providerDTO {
	return providerDTO{Provider: p, RedirectURI: s.d.OIDC.RedirectURI()}
}

func (s *Server) ListOIDCProviders(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.OIDC.ListProviders(c.R.Context())
	if err != nil {
		return nil, err
	}
	out := make([]providerDTO, len(v))
	for i, p := range v {
		out[i] = s.provider(p)
	}
	return ok(list(out))
}

func (s *Server) CreateOIDCProvider(c *gen.Call) (*gen.Result, error) {
	var in oidc.ProviderInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	p, err := s.d.OIDC.CreateProvider(c.R.Context(), actor(c), in)
	if err != nil {
		return nil, err
	}
	return created(s.provider(p))
}

func (s *Server) GetOIDCProvider(c *gen.Call) (*gen.Result, error) {
	p, err := s.d.OIDC.GetProvider(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(s.provider(p))
}

func (s *Server) UpdateOIDCProvider(c *gen.Call) (*gen.Result, error) {
	var in oidc.ProviderInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := ifMatch(c, in.Version)
	if err != nil {
		return nil, err
	}
	in.Version = v
	p, err := s.d.OIDC.UpdateProvider(c.R.Context(), actor(c), c.R.PathValue("id"), in)
	if err != nil {
		return nil, err
	}
	return ok(s.provider(p))
}

func (s *Server) DeleteOIDCProvider(c *gen.Call) (*gen.Result, error) {
	if err := s.d.OIDC.DeleteProvider(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) ListOIDCMappings(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.OIDC.ListMappings(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) AddOIDCMapping(c *gen.Call) (*gen.Result, error) {
	var in struct {
		GroupValue string `json:"group_value"`
		Role       string `json:"role"`
		GroupID    string `json:"group_id"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	m, err := s.d.OIDC.AddMapping(c.R.Context(), actor(c), c.R.PathValue("id"), in.GroupValue, in.Role, in.GroupID)
	if err != nil {
		return nil, err
	}
	return created(m)
}

func (s *Server) DeleteOIDCMapping(c *gen.Call) (*gen.Result, error) {
	if err := s.d.OIDC.DeleteMapping(c.R.Context(), actor(c), c.R.PathValue("id"), c.R.PathValue("mid")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) GetOIDCTestLogin(c *gen.Call) (*gen.Result, error) {
	key := c.Principal.Operator.ID + "|" + c.R.PathValue("id")
	s.testMu.Lock()
	e, found := s.testResults[key]
	s.testMu.Unlock()
	if !found || s.o.Clock.Now().Sub(e.at) > 10*time.Minute {
		return nil, apperr.New(apperr.CodeNotFound, "no recent test login for this provider; run one first")
	}
	return ok(e.res)
}

func (s *Server) GetAuthSettings(c *gen.Call) (*gen.Result, error) {
	off, err := s.d.Auth.LocalLoginDisabled(c.R.Context())
	if err != nil {
		return nil, err
	}
	direct, err := s.d.OIDC.DirectProvider(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(map[string]any{"local_login_disabled": off, "direct_provider": direct})
}

func (s *Server) PutAuthSettings(c *gen.Call) (*gen.Result, error) {
	var in struct {
		LocalLoginDisabled bool `json:"local_login_disabled"`
		// Omitted: unchanged (clients that predate the setting keep it).
		DirectProvider *string `json:"direct_provider"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	// The direct provider first: an unknown or disabled slug then fails before anything changes.
	if in.DirectProvider != nil {
		if err := s.d.OIDC.SetDirectProvider(c.R.Context(), actor(c), *in.DirectProvider); err != nil {
			return nil, err
		}
	}
	if err := s.d.OIDC.SetLocalLoginDisabled(c.R.Context(), actor(c), in.LocalLoginDisabled); err != nil {
		return nil, err
	}
	return s.GetAuthSettings(c)
}
