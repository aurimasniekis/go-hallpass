// Package layout defines where recording segment files live under <data_dir>/recordings (PLAN §13.5, SR-16).
//
// A segment's location is derived only from its validated session and segment IDs:
// <recordings>/<shard>/<session_id>/<segment_id>.hprec, where shard is the last two characters of the session ID.
// The path column stored in the database is never trusted for file I/O, so a tampered row (or a tampered backup)
// cannot point retention, replay, slot maintenance, backup or restore at a file outside the recordings directory.
package layout

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Ext is the file extension of a finalized segment.
const Ext = ".hprec"

// ErrInvalidID means a session or segment ID is not a well-formed, canonical HallPass identifier.
var ErrInvalidID = errors.New("recording layout: invalid segment or session id")

func canonical(prefix, id string) bool {
	p, err := ids.Parse(prefix, id)
	return err == nil && p == id
}

// RelPath returns the segment's path relative to the recordings directory. It fails unless both IDs are canonical
// identifiers ("ses_…" and "seg_…"), which contain only lowercase base32 characters and so can never form "..", a
// separator or an absolute path.
func RelPath(sessionID, segmentID string) (string, error) {
	if !canonical(ids.Session, sessionID) || !canonical(ids.Segment, segmentID) {
		return "", fmt.Errorf("%w: session %q segment %q", ErrInvalidID, sessionID, segmentID)
	}
	rel := filepath.Join(sessionID[len(sessionID)-2:], sessionID, segmentID+Ext)
	if !filepath.IsLocal(rel) { // defense in depth; cannot happen for canonical IDs
		return "", fmt.Errorf("%w: %q is not local", ErrInvalidID, rel)
	}
	return rel, nil
}

// Path returns the segment's absolute path under recDir (the recordings directory).
func Path(recDir, sessionID, segmentID string) (string, error) {
	rel, err := RelPath(sessionID, segmentID)
	if err != nil {
		return "", err
	}
	return filepath.Join(recDir, rel), nil
}

// Matches reports whether a stored path names the segment's canonical location under some data directory's
// recordings/ tree: absolute, clean, and ending in /recordings/<shard>/<session>/<segment>.hprec. The data directory
// prefix itself is not checked, so a data directory that was moved (or restored elsewhere) still matches, while a path
// pointing anywhere else (another file, a traversal, another segment's file) does not. Stored paths are only compared,
// never opened.
func Matches(stored, sessionID, segmentID string) bool {
	rel, err := RelPath(sessionID, segmentID)
	if err != nil {
		return false
	}
	suffix := string(filepath.Separator) + filepath.Join(store.RecordingsDir, rel)
	return filepath.IsAbs(stored) && filepath.Clean(stored) == stored && strings.HasSuffix(stored, suffix)
}
