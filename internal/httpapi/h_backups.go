package httpapi

import (
	"net/http"

	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/remotebackup"
)

func (s *Server) GetBackupStatus(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.RemoteBackup.Status(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) GetBackupTarget(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.RemoteBackup.GetTarget(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) PutBackupTarget(c *gen.Call) (*gen.Result, error) {
	var in remotebackup.TargetInput
	if err := decode(c, &in, false); err != nil {
		return nil, err
	}
	// Creating needs no version; changing an existing target needs If-Match or version in the body.
	if c.R.Header.Get("If-Match") != "" || in.Version > 0 {
		v, err := ifMatch(c, in.Version)
		if err != nil {
			return nil, err
		}
		in.Version = v
	}
	v, err := s.d.RemoteBackup.PutTarget(c.R.Context(), actor(c), in)
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) DeleteBackupTarget(c *gen.Call) (*gen.Result, error) {
	if err := s.d.RemoteBackup.DeleteTarget(c.R.Context(), actor(c)); err != nil {
		return nil, err
	}
	return noContent()
}

func (s *Server) TestBackupTarget(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.RemoteBackup.TestTarget(c.R.Context())
	if err != nil {
		return nil, err
	}
	return ok(v)
}

func (s *Server) ListBackupRuns(c *gen.Call) (*gen.Result, error) {
	lim, err := pageLimit(c.R)
	if err != nil {
		return nil, err
	}
	cur, err := decodeCursor(c.R.URL.Query().Get("cursor"))
	if err != nil {
		return nil, err
	}
	before := ""
	if cur != nil {
		before = cur.ID
	}
	runs, err := s.d.RemoteBackup.ListRuns(c.R.Context(), before, lim+1)
	if err != nil {
		return nil, err
	}
	out := page[*remotebackup.Run]{Items: []*remotebackup.Run{}}
	for i, r := range runs {
		if int64(i) == lim {
			out.NextCursor = encodeCursor(cursor{ID: runs[i-1].ID})
			break
		}
		out.Items = append(out.Items, r)
	}
	return ok(out)
}

func (s *Server) StartBackupRun(c *gen.Call) (*gen.Result, error) {
	v, err := s.d.RemoteBackup.RunNow(c.R.Context(), actor(c))
	if err != nil {
		return nil, err
	}
	return &gen.Result{Status: http.StatusAccepted, Body: v}, nil
}
