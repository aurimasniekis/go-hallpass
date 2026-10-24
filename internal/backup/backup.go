// Package backup creates, verifies and restores consistent HallPass backups and exports integrity-chain anchors
// (PLAN §13.8, §13.10, §18.5–18.16, ADR-0023, HP-OPS-003/004, HP-CRY-007/008/009).
//
// A backup directory holds a VACUUM INTO copy of the database, the recording segment files the snapshot refers to
// (ciphertext only, exactly as stored), manifest.json listing every file with its size and SHA-256, and
// manifest.sha256. The KEK is never part of a backup: restoring requires the operator to supply it separately.
package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/recording/layout"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Backup layout and manifest constants.
const (
	// Format identifies a HallPass backup manifest.
	Format = "hallpass-backup"
	// FormatVersion is the manifest version written and accepted by this package.
	FormatVersion = 1
	// ManifestFile lists every file of the backup with its size and SHA-256.
	ManifestFile = "manifest.json"
	// ManifestSumFile holds the SHA-256 of ManifestFile in sha256sum format.
	ManifestSumFile = "manifest.sha256"
	// DBFile is the database snapshot inside a backup directory.
	DBFile = store.DBFile
	// KEKNotice is recorded in every manifest.
	KEKNotice = "The master key (KEK) is NOT included in this backup. Restoring requires the KEK identified by kek_id, " +
		"backed up separately. Without it the encrypted data in this backup is unrecoverable."
)

// File kinds in a manifest.
const (
	KindDatabase = "database"
	KindSegment  = "segment"
)

// Errors.
var (
	// ErrInvalid means a backup failed verification.
	ErrInvalid = errors.New("backup verification failed")
	// ErrNotEmpty means the restore target already holds data and Force was not set.
	ErrNotEmpty = errors.New("restore target data directory is not empty")
	// ErrKEKMismatch means the supplied KEK is not the one the backup's keyring is wrapped with.
	ErrKEKMismatch = errors.New("the supplied master key (KEK) does not match the backup")
	// ErrExists means the backup destination already exists.
	ErrExists = errors.New("backup destination already exists")
)

// Manifest describes a backup (PLAN §13.10).
type Manifest struct {
	Format          string         `json:"format"`
	Version         int            `json:"version"`
	CreatedAt       time.Time      `json:"created_at"`
	HallpassVersion string         `json:"hallpass_version"`
	SchemaVersion   int64          `json:"schema_version"`
	KEKID           string         `json:"kek_id"`
	KEKIncluded     bool           `json:"kek_included"`
	KEKNotice       string         `json:"kek_notice"`
	SourceDataDir   string         `json:"source_data_dir"`
	ChainHead       Anchor         `json:"chain_head"`
	Segments        SegmentSummary `json:"segments"`
	Files           []File         `json:"files"`
	Warnings        []string       `json:"warnings,omitempty"`
}

// File is one file of a backup. Path is slash-separated and relative to the backup directory.
type File struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Kind      string `json:"kind"`
	SegmentID string `json:"segment_id,omitempty"`
	// State is the segment state in the snapshot.
	State string `json:"state,omitempty"`
	// OpenAtSnapshot marks a segment that was still being written at snapshot time. Its partial file is copied as
	// is and startup reconciliation after restore marks it interrupted (or finalized if it was complete).
	OpenAtSnapshot bool `json:"open_at_snapshot,omitempty"`
	// Problem records a mismatch between the segment file and the snapshot found while creating the backup. The file
	// is kept so that the restored system reports the same problem.
	Problem string `json:"problem,omitempty"`
}

// SegmentSummary counts segments by how the backup treated them.
type SegmentSummary struct {
	Copied         int `json:"copied"`
	OpenAtSnapshot int `json:"open_at_snapshot"`
	// Skipped segments have no file by design (deleted by retention, failed, or already missing).
	Skipped int `json:"skipped"`
	// Missing lists segments whose file should exist but was absent when the backup was taken.
	Missing []string `json:"missing,omitempty"`
}

// Snapshotter writes a consistent copy of the database. OpenReadOnly returns one that needs no data-directory lock
// and never blocks the store writer (VACUUM INTO runs in a WAL read transaction), so it is preferred both for the
// CLI and inside the server. *store.Store also implements it, but its Snapshot runs on the single writer connection
// and blocks all writes for the duration of the VACUUM INTO.
type Snapshotter interface {
	Snapshot(ctx context.Context, dest string) error
	// Dir is the absolute data directory.
	Dir() string
}

// Options configure Create.
type Options struct {
	Clock clock.Clock
}

// Result is the outcome of Create.
type Result struct {
	Dir      string
	Manifest *Manifest
	// Problems lists segment files that did not match the snapshot (copied anyway, flagged in the manifest).
	Problems []string
	Bytes    int64
}

// Create writes a backup of src to dest, which must not exist. The database is snapshotted first (VACUUM INTO)
// and segment files are copied afterwards according to the snapshot's view, so no store transaction or writer
// is held during file copies. The backup is assembled in a temporary sibling directory, fsynced and renamed into
// place, so dest either holds a complete backup or does not exist.
func Create(ctx context.Context, src Snapshotter, dest string, opts Options) (*Result, error) {
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	dest, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, dest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create backup parent: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dest)+".tmp-")
	if err != nil {
		return nil, fmt.Errorf("create backup staging dir: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o700); err != nil { //nolint:gosec // G302: a directory needs the search bit; owner only
		return nil, err
	}
	m := &Manifest{Format: Format, Version: FormatVersion, CreatedAt: opts.Clock.Now().UTC(), HallpassVersion: buildinfo.Get().Version,
		KEKNotice: KEKNotice, SourceDataDir: src.Dir()}

	dbPath := filepath.Join(tmp, DBFile)
	if err := src.Snapshot(ctx, dbPath); err != nil {
		return nil, fmt.Errorf("database snapshot: %w", err)
	}
	info, err := readSnapshot(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	m.SchemaVersion, m.ChainHead = info.schema, info.head
	switch len(info.kekIDs) {
	case 0:
		m.Warnings = append(m.Warnings, "the database has no keyring yet; no kek_id recorded")
	case 1:
		m.KEKID = info.kekIDs[0]
	default:
		return nil, fmt.Errorf("keyring keys are wrapped under several KEKs (%s); finish `hallpass keys rotate-kek` first", strings.Join(info.kekIDs, ", "))
	}
	size, sum, err := hashFile(dbPath)
	if err != nil {
		return nil, err
	}
	m.Files = append(m.Files, File{Path: DBFile, Size: size, SHA256: hex.EncodeToString(sum[:]), Kind: KindDatabase})
	res := &Result{Dir: dest, Manifest: m, Bytes: size}

	recDir := filepath.Join(src.Dir(), store.RecordingsDir)
	for _, seg := range info.segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, problem, err := copySegment(seg, recDir, tmp)
		if err != nil {
			return nil, err
		}
		switch {
		case f == nil && problem == "":
			m.Segments.Skipped++
		case f == nil:
			m.Segments.Missing = append(m.Segments.Missing, seg.id)
			m.Warnings = append(m.Warnings, problem)
		default:
			m.Files = append(m.Files, *f)
			res.Bytes += f.Size
			m.Segments.Copied++
			if f.OpenAtSnapshot {
				m.Segments.OpenAtSnapshot++
			}
			if f.Problem != "" {
				res.Problems = append(res.Problems, fmt.Sprintf("segment %s: %s", seg.id, f.Problem))
			}
		}
	}
	if err := writeManifest(tmp, m); err != nil {
		return nil, err
	}
	if err := fsyncTree(tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return nil, fmt.Errorf("install backup: %w", err)
	}
	ok = true
	if err := store.FsyncDir(parent); err != nil {
		return nil, err
	}
	return res, nil
}

// segmentRow is the part of a recording_segments row a backup needs.
type segmentRow struct {
	id, sessionID, channelID, path, state string
	header, ciphertext                    []byte
	bytes                                 sql.NullInt64
}

type snapshotInfo struct {
	schema   int64
	kekIDs   []string
	head     Anchor
	segments []segmentRow
}

// readSnapshot reads what the manifest needs from the snapshot copy (the database view at time T).
func readSnapshot(ctx context.Context, dbPath string) (*snapshotInfo, error) {
	d, err := openImmutable(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	info := &snapshotInfo{}
	if info.schema, _, err = store.SchemaVersions(ctx, d, store.EmbeddedMigrations()); err != nil {
		return nil, fmt.Errorf("schema version: %w", err)
	}
	if info.kekIDs, err = kekIDs(ctx, d); err != nil {
		return nil, err
	}
	if info.head, err = chainHead(ctx, d); err != nil {
		return nil, err
	}
	if info.segments, err = segmentRows(ctx, d); err != nil {
		return nil, err
	}
	return info, nil
}

// kekIDs lists the KEKs wrapping the keys a restored keyring loads. Retired keys are never loaded, so a retired row
// left under an older KEK does not make the backup ambiguous (SR-18).
func kekIDs(ctx context.Context, d *sql.DB) ([]string, error) {
	rows, err := d.QueryContext(ctx, "SELECT DISTINCT wrap_kek_id FROM keyring_keys WHERE state != 'retired' ORDER BY 1")
	if err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func chainHead(ctx context.Context, d *sql.DB) (Anchor, error) {
	var a Anchor
	var hash []byte
	var at int64
	err := d.QueryRowContext(ctx, "SELECT seq, hash, at FROM integrity_chain ORDER BY seq DESC LIMIT 1").Scan(&a.Seq, &hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return Anchor{}, nil
	}
	if err != nil {
		return Anchor{}, fmt.Errorf("read chain head: %w", err)
	}
	return newAnchor(a.Seq, hash, at), nil
}

func segmentRows(ctx context.Context, d *sql.DB) ([]segmentRow, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, access_session_id, channel_id, path, state, header_sha256, ciphertext_sha256, bytes
		FROM recording_segments ORDER BY opened_at, id`)
	if err != nil {
		return nil, fmt.Errorf("read segments: %w", err)
	}
	defer rows.Close()
	var out []segmentRow
	for rows.Next() {
		var s segmentRow
		if err := rows.Scan(&s.id, &s.sessionID, &s.channelID, &s.path, &s.state, &s.header, &s.ciphertext, &s.bytes); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// copySegment copies one segment file into the backup according to its snapshot state. It returns (nil, "", nil)
// for segments without a file by design, and (nil, warning, nil) when an expected file is absent.
// Only the segment's canonical location (derived from its IDs) is read; a row whose stored path does not name that
// location is refused, because restore and verify would refuse it too (SR-16).
func copySegment(seg segmentRow, recDir, tmp string) (*File, string, error) {
	final, err := layout.Path(recDir, seg.sessionID, seg.id)
	if err != nil {
		return nil, "", fmt.Errorf("segment %s: %w", seg.id, err)
	}
	if !layout.Matches(seg.path, seg.sessionID, seg.id) {
		return nil, "", fmt.Errorf("segment %s: stored path %s is not its location under a recordings directory (%s)", seg.id, seg.path, final)
	}
	var candidates []string
	switch seg.state {
	case "finalized", "interrupted":
		candidates = []string{final}
	case "open":
		// Prefer the partial file; if the segment was finalized after the snapshot, its final file is copied and
		// reconciliation after restore finalizes the row.
		candidates = []string{final + hprec.PartialSuffix, final}
	default: // deleted, failed, missing
		return nil, "", nil
	}
	for _, src := range candidates {
		rel, err := filepath.Rel(recDir, src)
		if err != nil || !filepath.IsLocal(rel) {
			return nil, "", fmt.Errorf("segment %s: path %s is outside the recordings directory %s", seg.id, src, recDir)
		}
		relSlash := path.Join(store.RecordingsDir, filepath.ToSlash(rel))
		var h *segHasher
		var extra io.Writer // stays a nil interface for open segments
		if seg.state != "open" {
			h = newSegHasher(seg.bytes)
			extra = h
		}
		size, sum, err := copyHashed(src, filepath.Join(tmp, filepath.FromSlash(relSlash)), extra)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("copy segment %s: %w", seg.id, err)
		}
		f := &File{Path: relSlash, Size: size, SHA256: hex.EncodeToString(sum[:]), Kind: KindSegment, SegmentID: seg.id, State: seg.state,
			OpenAtSnapshot: seg.state == "open"}
		if h != nil {
			f.Problem = h.check(seg.header, seg.ciphertext)
		}
		return f, "", nil
	}
	return nil, fmt.Sprintf("segment %s (%s): file %s missing at backup time", seg.id, seg.state, seg.path), nil
}

func writeManifest(dir string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := writeFileSync(filepath.Join(dir, ManifestFile), b); err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	return writeFileSync(filepath.Join(dir, ManifestSumFile), []byte(hex.EncodeToString(sum[:])+"  "+ManifestFile+"\n"))
}

// ReadOnlySource snapshots a data directory through a read-only connection without taking the data-directory
// lock, so `hallpass backup` works while the server is running (PLAN §4.4).
type ReadOnlySource struct {
	dir string
	db  *sql.DB
}

// OpenReadOnly opens the database of dataDir read-only.
func OpenReadOnly(ctx context.Context, dataDir string) (*ReadOnlySource, error) {
	dir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(dir, store.DBFile)
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("open database %s: %w", p, err)
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", store.DefaultBusyTimeout.Milliseconds()))
	q.Add("_pragma", "trusted_schema(0)")
	d, err := sql.Open("sqlite", "file:"+p+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(2)
	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("open database %s: %w", p, err)
	}
	return &ReadOnlySource{dir: dir, db: d}, nil
}

// Dir implements Snapshotter.
func (r *ReadOnlySource) Dir() string { return r.dir }

// DB returns the read-only connection pool (anchors export and verification).
func (r *ReadOnlySource) DB() *sql.DB { return r.db }

// Close closes the connection pool.
func (r *ReadOnlySource) Close() error { return r.db.Close() }

// Snapshot implements Snapshotter with VACUUM INTO on the read-only connection. dest must not exist.
func (r *ReadOnlySource) Snapshot(ctx context.Context, dest string) error {
	dest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("snapshot target %s already exists", dest)
	}
	if strings.ContainsAny(dest, "'\x00") {
		return fmt.Errorf("snapshot path %q contains unsupported characters", dest)
	}
	// VACUUM INTO takes no bind parameter for the file name; dest is absolute and checked for quotes and NUL above.
	if _, err := r.db.ExecContext(ctx, "VACUUM INTO '"+dest+"'"); err != nil { //nolint:gosec // G202: see above
		_ = os.Remove(dest)
		return fmt.Errorf("vacuum into %s: %w", dest, err)
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		return err
	}
	if err := fsyncPath(dest); err != nil {
		return err
	}
	return store.FsyncDir(filepath.Dir(dest))
}

// openImmutable opens a database file that nothing else writes (a snapshot or backup copy) without creating
// journal, WAL or shm files.
func openImmutable(ctx context.Context, p string) (*sql.DB, error) {
	q := url.Values{}
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	q.Add("_pragma", "trusted_schema(0)")
	d, err := sql.Open("sqlite", "file:"+p+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("open %s: %w", p, err)
	}
	return d, nil
}
