package httpapi

import (
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/notify"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

func (s *Server) ListIntegrations(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Notify.ListIntegrations(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) CreateIntegration(c *gen.Call) (*gen.Result, error) {
	var in notify.IntegrationInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := s.d.Notify.CreateIntegration(c.R.Context(), actor(c), in)
	if err != nil {
		return nil, err
	}
	return created(v)
}

func (s *Server) GetIntegration(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Notify.GetIntegration(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) UpdateIntegration(c *gen.Call) (*gen.Result, error) {
	var in notify.IntegrationInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := ifMatch(c, in.Version)
	if err != nil {
		return nil, err
	}
	in.Version = v
	out, err := s.d.Notify.UpdateIntegration(c.R.Context(), actor(c), c.R.PathValue("id"), in)
	if err != nil {
		return nil, err
	}
	return ok(out)
}

func (s *Server) DeleteIntegration(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Notify.DeleteIntegration(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) ListNotificationRoutes(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Notify.ListRoutes(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) CreateNotificationRoute(c *gen.Call) (*gen.Result, error) {
	var in notify.RouteInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	v, err := s.d.Notify.CreateRoute(c.R.Context(), actor(c), in)
	if err != nil {
		return nil, err
	}
	return created(v)
}

func (s *Server) DeleteNotificationRoute(c *gen.Call) (*gen.Result, error) {
	if err := s.d.Notify.DeleteRoute(c.R.Context(), actor(c), c.R.PathValue("id")); err != nil {
		return nil, err
	}
	return noContent()
}

type deliveryDTO struct {
	ID          string    `json:"id"`
	Provider    string    `json:"provider"`
	Destination string    `json:"destination"`
	Kind        string    `json:"kind"`
	SubjectType string    `json:"subject_type,omitempty"`
	SubjectID   string    `json:"subject_id,omitempty"`
	State       string    `json:"state"`
	Attempts    int64     `json:"attempts"`
	MaxAttempts int64     `json:"max_attempts"`
	NextAt      time.Time `json:"next_at"`
	LastError   string    `json:"last_error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s *Server) ListNotificationDeliveries(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	state, err := queryEnum(c.R, "state", "queued", "sending", "delivered", "dead")
	if err != nil {
		return nil, err
	}
	rows, err := s.d.Store.R().ListDeliveries(c.R.Context(), db.ListDeliveriesParams{State: nullStr(state), Lim: lim})
	if err != nil {
		return nil, err
	}
	out := make([]deliveryDTO, len(rows))
	for i, r := range rows {
		out[i] = deliveryDTO{ID: r.ID, Provider: r.Provider, Destination: r.Destination, Kind: r.Kind, SubjectType: r.SubjectType.String,
			SubjectID: r.SubjectID.String, State: r.State, Attempts: r.Attempts, MaxAttempts: r.MaxAttempts, NextAt: micros(r.NextAt),
			LastError: r.LastError.String, CreatedAt: micros(r.CreatedAt), UpdatedAt: micros(r.UpdatedAt)}
	}
	return ok(list(out))
}

func (s *Server) CreateProviderLinkCode(c *gen.Call) (*gen.Result, error) {
	var in struct {
		Provider string `json:"provider"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	code, exp, err := s.d.Notify.IssueLinkCode(c.R.Context(), c.Principal.Operator.ID, in.Provider)
	if err != nil {
		return nil, err
	}
	return ok(map[string]any{"code": code, "expires_at": exp.UTC()})
}

func (s *Server) ListMyProviderLinks(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Notify.ProviderLinks(c.R.Context(), c.Principal.Operator.ID)
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) UnlinkMyProviderLink(c *gen.Call) (*gen.Result, error) {
	q := c.R.URL.Query()
	if err := s.d.Notify.UnlinkProviderUser(c.R.Context(), actor(c), c.Principal.Operator.ID, q.Get("provider"), q.Get("workspace"), q.Get("user_id")); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) ListOperatorProviderLinks(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Notify.ProviderLinks(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

func (s *Server) LinkOperatorProvider(c *gen.Call) (*gen.Result, error) {
	var in notify.ProviderLink
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	if err := s.d.Notify.LinkProviderUser(c.R.Context(), actor(c), c.R.PathValue("id"), in); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) UnlinkOperatorProvider(c *gen.Call) (*gen.Result, error) {
	q := c.R.URL.Query()
	if err := s.d.Notify.UnlinkProviderUser(c.R.Context(), actor(c), c.R.PathValue("id"), q.Get("provider"), q.Get("workspace"), q.Get("user_id")); err != nil {
		return nil, err
	}
	return noContent()
}
