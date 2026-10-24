package backup

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/recording/layout"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// RestoreOptions configure Restore.
type RestoreOptions struct {
	// Force moves existing database files, recordings and quarantine aside (to backups/pre-restore-<time>/ inside
	// the data directory) instead of refusing a non-empty target. Nothing is deleted.
	Force bool
	// KEKID is the ID of the KEK the operator will run with. When set, it must equal the backup's kek_id.
	KEKID string
	// AllowNetworkFS skips the network-filesystem refusal (development only).
	AllowNetworkFS bool
	Clock          clock.Clock
}

// RestoreResult is the outcome of Restore.
type RestoreResult struct {
	Manifest *Manifest
	DataDir  string
	Files    int
	Bytes    int64
	// MovedAside is where existing data was moved with Force ("" if nothing was moved).
	MovedAside string
	Warnings   []string
}

// Restore verifies the backup in backupDir and installs it into dataDir. It needs no network access and no KEK
// material (only the KEK ID to compare). It takes the data-directory lock, so the server must be stopped, and
// refuses a target that already holds data unless opts.Force is set. Files are copied into a staging directory
// inside dataDir, re-hashed against the manifest while copying, and renamed into place; recording paths in the
// restored database are rewritten to the new data directory. Startup reconciliation then marks segments that were
// open at snapshot time interrupted.
func Restore(ctx context.Context, backupDir, dataDir string, opts RestoreOptions) (*RestoreResult, error) {
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	rep, err := Verify(ctx, backupDir)
	if err != nil {
		return nil, err
	}
	m := rep.Manifest
	if opts.KEKID != "" && opts.KEKID != m.KEKID {
		return nil, fmt.Errorf("%w: backup needs KEK %s, supplied KEK is %s", ErrKEKMismatch, m.KEKID, opts.KEKID)
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := store.PrepareDataDir(dataDir); err != nil {
		return nil, err
	}
	if !opts.AllowNetworkFS {
		if err := store.CheckLocalFilesystem(dataDir); err != nil {
			return nil, err
		}
	}
	lock, err := store.AcquireLock(filepath.Join(dataDir, store.LockFile))
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Release() }()

	res := &RestoreResult{Manifest: m, DataDir: dataDir, Warnings: rep.Warnings}
	if err := prepareTarget(dataDir, opts, res); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(dataDir, ".restore-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	for _, f := range m.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		src := filepath.Join(backupDir, filepath.FromSlash(f.Path))
		size, sum, err := copyHashed(src, filepath.Join(staging, filepath.FromSlash(f.Path)), nil)
		if err != nil {
			return nil, err
		}
		if size != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, fmt.Errorf("%w: %s changed after verification", ErrInvalid, f.Path)
		}
		res.Files++
		res.Bytes += size
	}
	if err := rewritePaths(ctx, filepath.Join(staging, DBFile), dataDir); err != nil {
		return nil, err
	}
	if err := fsyncTree(staging); err != nil {
		return nil, err
	}
	if err := install(staging, dataDir); err != nil {
		return nil, err
	}
	return res, nil
}

// prepareTarget checks that dataDir holds no data, or moves existing data aside when opts.Force is set.
func prepareTarget(dataDir string, opts RestoreOptions, res *RestoreResult) error {
	var found []string
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		switch name := e.Name(); name {
		case store.LockFile:
		case store.BackupsDir, store.RecordingsDir, store.QuarantineDir:
			if !emptyDir(filepath.Join(dataDir, name)) {
				found = append(found, name+"/")
			}
		default:
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return nil
	}
	if !opts.Force {
		return fmt.Errorf("%w: %s contains %s (use --force to move existing data aside)", ErrNotEmpty, dataDir, strings.Join(found, ", "))
	}
	aside := filepath.Join(dataDir, store.BackupsDir, "pre-restore-"+opts.Clock.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(aside, 0o700); err != nil {
		return err
	}
	for _, name := range []string{store.DBFile, store.DBFile + "-wal", store.DBFile + "-shm", store.RecordingsDir, store.QuarantineDir} {
		err := os.Rename(filepath.Join(dataDir, name), filepath.Join(aside, name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("move %s aside: %w", name, err)
		}
	}
	res.MovedAside = aside
	res.Warnings = append(res.Warnings, "existing data moved to "+aside)
	return store.FsyncDir(dataDir)
}

func emptyDir(p string) bool {
	entries, err := os.ReadDir(p)
	return err == nil && len(entries) == 0
}

// rewritePaths points recording_segments.path at each segment's canonical location in the restore target, derived
// from the row's IDs (Verify has already refused rows whose path was not their canonical location in the source).
// Paths are stored absolute, so a restore into a different data directory would otherwise leave every segment
// "missing". The running gateway derives locations from IDs too and never trusts the stored path (SR-16).
func rewritePaths(ctx context.Context, dbPath, newDataDir string) error {
	recDir := filepath.Join(newDataDir, store.RecordingsDir)
	q := url.Values{}
	q.Add("_pragma", "journal_mode(DELETE)")
	q.Add("_pragma", "trusted_schema(0)")
	d, err := sql.Open("sqlite", "file:"+dbPath+"?"+q.Encode())
	if err != nil {
		return err
	}
	defer d.Close()
	d.SetMaxOpenConns(1)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rewrite recording paths: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	todo, err := segmentPaths(ctx, tx)
	if err != nil {
		return fmt.Errorf("rewrite recording paths: %w", err)
	}
	for id, r := range todo {
		p, err := layout.Path(recDir, r.sessionID, id)
		if err != nil {
			return fmt.Errorf("%w: segment %s: %w", ErrInvalid, id, err)
		}
		if p == r.path {
			continue
		}
		if _, err := tx.ExecContext(ctx, "UPDATE recording_segments SET path = ? WHERE id = ?", p, id); err != nil {
			return fmt.Errorf("rewrite recording path of %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := d.Close(); err != nil {
		return err
	}
	return fsyncPath(dbPath)
}

type pathRow struct{ sessionID, path string }

func segmentPaths(ctx context.Context, tx *sql.Tx) (map[string]pathRow, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, access_session_id, path FROM recording_segments")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]pathRow{}
	for rows.Next() {
		var id string
		var r pathRow
		if err := rows.Scan(&id, &r.sessionID, &r.path); err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, rows.Err()
}

// install renames the staged recordings tree and database into dataDir (database last, so an interrupted restore
// never leaves a database without its recordings).
func install(staging, dataDir string) error {
	recDst := filepath.Join(dataDir, store.RecordingsDir)
	recSrc := filepath.Join(staging, store.RecordingsDir)
	if _, err := os.Stat(recSrc); err == nil {
		if err := os.Remove(recDst); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("replace empty recordings directory: %w", err)
		}
		if err := os.Rename(recSrc, recDst); err != nil {
			return fmt.Errorf("install recordings: %w", err)
		}
	}
	for _, sub := range []string{store.RecordingsDir, store.QuarantineDir, store.BackupsDir} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0o700); err != nil {
			return err
		}
	}
	if err := os.Rename(filepath.Join(staging, DBFile), filepath.Join(dataDir, store.DBFile)); err != nil {
		return fmt.Errorf("install database: %w", err)
	}
	return store.FsyncDir(dataDir)
}
