package httpapi

import (
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// ---- destination-side audit (HP-REC-012)

func (s *Server) ListDestinationCollectors(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Destaudit.ListCollectors(c.R.Context(), c.R.URL.Query().Get("server_id"))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

// RegisterDestinationCollector enrolls a collector key. A collector can attach records to every session on its
// server, so this needs credentials.manage with recent authentication and MFA.
func (s *Server) RegisterDestinationCollector(c *gen.Call) (*gen.Result, error) {
	var in struct {
		ServerID  string `json:"server_id"`
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	ctx := c.R.Context()
	if _, err := s.d.Inventory.GetServer(ctx, in.ServerID); err != nil {
		return nil, notFound(err, "server")
	}
	v, err := s.d.Destaudit.RegisterCollector(ctx, actor(c), destaudit.RegisterInput{ServerID: in.ServerID, Name: in.Name, PublicKey: in.PublicKey})
	if err != nil {
		return nil, err
	}
	return created(v)
}

func (s *Server) GetDestinationCollector(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.Destaudit.GetCollector(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) RevokeDestinationCollector(c *gen.Call) (*gen.Result, error) {
	var in reasonBody
	if err := decode(c, &in, true); err != nil {
		return nil, err
	}
	v, err := s.d.Destaudit.RevokeCollector(c.R.Context(), actor(c), c.R.PathValue("id"), in.Reason)
	if err != nil {
		return nil, err
	}
	return ok(v)
}

// ListSessionDestinationRecords returns record metadata only; exec details need recording.play.
func (s *Server) ListSessionDestinationRecords(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	ctx, id := c.R.Context(), c.R.PathValue("id")
	if _, err := s.d.Store.R().GetSession(ctx, id); err != nil {
		return nil, notFound(err, "session")
	}
	v, err := s.d.Destaudit.SessionRecords(ctx, id, int(lim))
	if err != nil {
		return nil, err
	}
	return ok(list(v))
}

// GetDestinationRecord decrypts one record's exec details; like playback, every access is audited (HP-REC-014).
func (s *Server) GetDestinationRecord(c *gen.Call) (*gen.Result, error) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	v, err := s.d.Destaudit.RecordDetails(ctx, id)
	if err != nil {
		return nil, err
	}
	err = s.d.Store.W().TxNamed(ctx, "api.destaudit_record_read", func(tx *store.Tx) error {
		_, err := s.d.Audit.Append(ctx, tx, audit.Event{Actor: actor(c), Action: "destaudit.record.read", Target: audit.Target{Type: "destaudit_record", ID: id},
			SourceIP: s.clientIP(c.R), Details: map[string]any{"session_id": v.SessionID, "collector_id": v.CollectorID}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return ok(v)
}
