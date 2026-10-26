package httpapi

import (
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/opauth"
)

func (s *Server) ListAPITokens(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Auth.ListAPITokens(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) CreateAPIToken(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Name          string `json:"name"`
		Role          string `json:"role"`
		ExpiresInDays int    `json:"expires_in_days"`
		NeverExpires  bool   `json:"never_expires"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	t, token, err := s.d.Auth.CreateAPIToken(c.R.Context(), c.Principal, in.Name, in.Role, time.Duration(in.ExpiresInDays)*24*time.Hour, in.NeverExpires)
	if err != nil {
		return nil, err
	}
	return created(struct {
		Token    string           `json:"token"`
		APIToken *opauth.APIToken `json:"api_token"`
	}{token, t})
}

// visibleAPIToken returns a token's metadata; an API token sees only the tokens it issued (ADR-0058).
func (s *Server) visibleAPIToken(c *gen.Call) (*opauth.APIToken, error) {
	t, err := s.d.Auth.GetAPIToken(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if c.Principal.TokenID != "" && t.ParentTokenID != c.Principal.TokenID {
		return nil, apperr.New(apperr.CodeNotFound, "API token not found")
	}
	return t, nil
}

func (s *Server) GetAPIToken(c *gen.Call) (*gen.Result, error) {
	t, err := s.visibleAPIToken(c)
	if err != nil {
		return nil, err
	}
	return ok(t)
}

func (s *Server) RevokeAPIToken(c *gen.Call) (*gen.Result, error) {
	if _, err := s.visibleAPIToken(c); err != nil {
		return nil, err
	}
	t, err := s.d.Auth.RevokeAPIToken(c.R.Context(), actor(c), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(t)
}
