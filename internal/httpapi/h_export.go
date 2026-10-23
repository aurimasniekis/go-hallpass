package httpapi

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/httpapi/gen"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// bundleManifest describes a ciphertext export bundle. The segment files are the HPREC1 files exactly as stored:
// encrypted, with their data keys wrapped by the gateway's recording key, so reading them needs a Hallpass keyring
// (the KEK). The hashes let a recipient check integrity without keys.
type bundleManifest struct {
	Format     string          `json:"format"` // "hallpass-export-bundle/v1"
	SessionID  string          `json:"session_id"`
	ExportedAt time.Time       `json:"exported_at"`
	ExportedBy string          `json:"exported_by"`
	Segments   []bundleSegment `json:"segments"`
}

type bundleSegment struct {
	SegmentID        string `json:"segment_id"`
	ChannelID        string `json:"channel_id"`
	Ordinal          int64  `json:"ordinal"`
	State            string `json:"state"`
	KeyID            string `json:"key_id"`
	File             string `json:"file,omitempty"` // path inside the bundle; empty when the file is unavailable
	Bytes            int64  `json:"bytes"`
	FileSHA256       string `json:"file_sha256,omitempty"`       // SHA-256 of the exported file bytes
	HeaderSHA256     string `json:"header_sha256,omitempty"`     // HPREC1 header hash recorded at open
	CiphertextSHA256 string `json:"ciphertext_sha256,omitempty"` // frames-region digest recorded at finalization
	Partial          bool   `json:"partial,omitempty"`           // not finalized: the authenticated prefix only
}

// exportBundle streams a tar of the session's encrypted segment files plus manifest.json (HP-REC-014 default
// export). Nothing is decrypted.
func (s *Server) exportBundle(c *gen.Call, sessionID string) (*gen.Result, error) {
	ctx := c.R.Context()
	segs, err := s.d.Store.R().SegmentsForSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	m := bundleManifest{Format: "hallpass-export-bundle/v1", SessionID: sessionID, ExportedAt: s.o.Clock.Now().UTC(),
		ExportedBy: actor(c).ID, Segments: []bundleSegment{}}
	type fileRef struct {
		name, path string
		size       int64
	}
	var files []fileRef
	for _, seg := range segs {
		if seg.State == "deleted" {
			continue
		}
		bs := bundleSegment{SegmentID: seg.ID, ChannelID: seg.ChannelID, Ordinal: seg.Ordinal, State: seg.State, KeyID: seg.KeyID}
		if len(seg.CiphertextSha256) > 0 {
			bs.CiphertextSHA256 = hex.EncodeToString(seg.CiphertextSha256)
		}
		if len(seg.HeaderSha256) > 0 {
			bs.HeaderSHA256 = hex.EncodeToString(seg.HeaderSha256)
		}
		for _, p := range []string{seg.Path, seg.Path + hprec.PartialSuffix} {
			fi, err := os.Stat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			sum, err := fileSHA256(p, fi.Size())
			if err != nil {
				continue
			}
			bs.File, bs.Bytes, bs.Partial, bs.FileSHA256 = "segments/"+seg.ID+".hprec", fi.Size(), p != seg.Path, sum
			files = append(files, fileRef{name: bs.File, path: p, size: fi.Size()})
			break
		}
		m.Segments = append(m.Segments, bs)
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	err = s.d.Store.W().TxNamed(ctx, "api.recording_exported", func(tx *store.Tx) error {
		_, err := s.d.Audit.Append(ctx, tx, audit.Event{Actor: actor(c), Action: "recording.exported", Target: audit.Target{Type: "access_session", ID: sessionID},
			SourceIP: s.clientIP(c.R), Details: map[string]any{"format": "bundle", "segments": len(m.Segments), "files": len(files)}})
		return err
	})
	if err != nil {
		return nil, err
	}

	w := c.W
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "hallpass-session-" + sessionID + ".tar"}))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	tw := tar.NewWriter(w)
	mod := m.ExportedAt
	if err := writeTarFile(tw, "manifest.json", int64(len(manifest)), mod, bytes.NewReader(manifest)); err != nil {
		s.log.Warn("export bundle aborted", slog.String("session_id", sessionID), obs.Err(err))
		return nil, nil
	}
	for _, f := range files {
		if err := s.copySegment(tw, f.name, f.path, f.size, mod); err != nil {
			// Headers are sent: the truncated tar (no end-of-archive marker) tells the client the bundle is incomplete.
			s.log.Warn("export bundle aborted", slog.String("session_id", sessionID), obs.Err(err))
			return nil, nil
		}
	}
	if err := tw.Close(); err != nil {
		s.log.Warn("export bundle aborted", slog.String("session_id", sessionID), obs.Err(err))
	}
	return nil, nil
}

// copySegment adds the first size bytes of a segment file. An open segment may still grow; its exported prefix can
// end mid-frame, which hprec.Verify reports as a truncated (not corrupt) file.
func (s *Server) copySegment(tw *tar.Writer, name, path string, size int64, mod time.Time) error {
	f, err := os.Open(path) //nolint:gosec // path comes from the segment row, under the recordings directory
	if err != nil {
		return err
	}
	defer f.Close()
	return writeTarFile(tw, name, size, mod, io.LimitReader(f, size))
}

// fileSHA256 hashes the first size bytes of a file (the part that will be exported).
func fileSHA256(path string, size int64) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the segment row, under the recordings directory
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, size)); err != nil || n != size {
		return "", errors.Join(err, io.ErrUnexpectedEOF)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeTarFile(tw *tar.Writer, name string, size int64, mod time.Time, r io.Reader) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: mod, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	n, err := io.Copy(tw, r)
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	return err
}
