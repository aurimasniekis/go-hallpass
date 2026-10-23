package httpapi

import (
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/sshban"
)

// ---- SSH source bans (HP-SSH-026)

func (s *Server) ListSSHBans(c *gen.Call) (*gen.Result, error) {
	if s.d.Bans == nil {
		return ok(list([]sshban.Ban{}))
	}
	v, err := s.d.Bans.List(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) LiftSSHBan(c *gen.Call) (*gen.Result, error) {
	if s.d.Bans == nil {
		return nil, apperr.New(apperr.CodeNotFound, "ban not found")
	}
	if err := s.d.Bans.Lift(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}
