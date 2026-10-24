package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/recording/hprec"
	"github.com/aurimasniekis/go-hallpass/internal/recording/layout"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Report is the outcome of Verify.
type Report struct {
	Manifest *Manifest `json:"manifest,omitempty"`
	Files    int       `json:"files"`
	Bytes    int64     `json:"bytes"`
	// ChainLength is the number of integrity-chain entries whose hash links were checked (without the KEK; MACs are
	// checked by `hallpass verify` after restore).
	ChainLength int64 `json:"chain_length"`
	// BinarySchema is the newest schema version this binary supports.
	BinarySchema int64 `json:"binary_schema"`
	// Warnings are known conditions recorded when the backup was created (missing or mismatching segment files).
	Warnings []string `json:"warnings,omitempty"`
	// Problems make the backup unusable as is.
	Problems []string `json:"problems,omitempty"`
	OK       bool     `json:"ok"`

	schemaTooNew bool
}

func (r *Report) problem(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

// Verify checks a backup directory without the KEK: the manifest checksum and format, the size and SHA-256 of every
// listed file, that no unlisted files are present, PRAGMA integrity_check on the database copy, that the schema
// version, kek_id and chain head match the manifest, the integrity-chain hash links, and every segment file against
// the header and ciphertext hashes in the database copy. The returned error wraps ErrInvalid when the backup must
// not be restored; the report is returned either way when the manifest could be read.
func Verify(ctx context.Context, dir string) (*Report, error) {
	rep := &Report{}
	m, err := readManifest(dir)
	if err != nil {
		rep.problem("%v", err)
		return rep, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	rep.Manifest = m
	rep.Warnings = append(rep.Warnings, m.Warnings...)
	listed := checkFiles(dir, m, rep)
	checkUnlisted(dir, listed, rep)
	if _, ok := listed[DBFile]; ok && len(rep.Problems) == 0 {
		checkDatabase(ctx, filepath.Join(dir, DBFile), m, rep)
	}
	rep.OK = len(rep.Problems) == 0
	switch {
	case rep.schemaTooNew:
		return rep, fmt.Errorf("%w: %w: %s", ErrInvalid, store.ErrSchemaTooNew, strings.Join(rep.Problems, "; "))
	case !rep.OK:
		return rep, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(rep.Problems, "; "))
	}
	return rep, nil
}

// readManifest reads and checks manifest.json against manifest.sha256.
func readManifest(dir string) (*Manifest, error) {
	b, err := readSmall(filepath.Join(dir, ManifestFile), 64<<20)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	sumLine, err := readSmall(filepath.Join(dir, ManifestSumFile), 1024)
	if err != nil {
		return nil, fmt.Errorf("read manifest checksum: %w", err)
	}
	fields := strings.Fields(string(sumLine))
	sum := sha256.Sum256(b)
	if len(fields) != 2 || fields[1] != ManifestFile || fields[0] != hex.EncodeToString(sum[:]) {
		return nil, errors.New("manifest.json does not match manifest.sha256")
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	switch {
	case m.Format != Format:
		return nil, fmt.Errorf("not a HallPass backup (format %q)", m.Format)
	case m.Version != FormatVersion:
		return nil, fmt.Errorf("unsupported backup format version %d (this binary reads %d)", m.Version, FormatVersion)
	case m.KEKIncluded:
		return nil, errors.New("manifest claims to include the KEK; HallPass backups never contain it")
	}
	return &m, nil
}

func readSmall(p string, limit int64) ([]byte, error) {
	f, err := openRegular(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, limit)
	}
	return b, nil
}

// validPath reports whether a manifest path is a clean relative path to the database or under recordings/.
func validPath(p string) bool {
	if p == DBFile {
		return true
	}
	return strings.HasPrefix(p, store.RecordingsDir+"/") && path.Clean(p) == p && filepath.IsLocal(filepath.FromSlash(p)) &&
		!strings.ContainsAny(p, "\\\x00")
}

// checkFiles hashes every listed file and returns the set of listed paths.
func checkFiles(dir string, m *Manifest, rep *Report) map[string]*File {
	listed := map[string]*File{}
	dbs := 0
	for i := range m.Files {
		f := &m.Files[i]
		if !validPath(f.Path) {
			rep.problem("manifest lists an invalid path %q", f.Path)
			continue
		}
		if _, dup := listed[f.Path]; dup {
			rep.problem("manifest lists %s twice", f.Path)
			continue
		}
		listed[f.Path] = f
		if f.Kind == KindDatabase {
			dbs++
		}
		if (f.Kind == KindDatabase) != (f.Path == DBFile) || (f.Kind == KindSegment) == (f.SegmentID == "") {
			rep.problem("manifest entry %s has an inconsistent kind", f.Path)
			continue
		}
		size, sum, err := hashFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			rep.problem("%s is missing", f.Path)
			continue
		case err != nil:
			rep.problem("%s: %v", f.Path, err)
			continue
		}
		if size != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
			rep.problem("%s does not match the manifest (size or SHA-256 differs)", f.Path)
			continue
		}
		rep.Files++
		rep.Bytes += size
	}
	if dbs != 1 {
		rep.problem("manifest must list exactly one database file, found %d", dbs)
	}
	return listed
}

// checkUnlisted reports files in the backup directory that the manifest does not list, and anything that is not
// a regular file or directory.
func checkUnlisted(dir string, listed map[string]*File, rep *Report) {
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			rep.problem("%s is not a regular file", rel)
		case rel == ManifestFile || rel == ManifestSumFile:
		case listed[rel] == nil:
			rep.problem("%s is not listed in the manifest", rel)
		}
		return nil
	})
	if err != nil {
		rep.problem("scan backup directory: %v", err)
	}
}

// checkDatabase checks the database copy and the segment files against it.
func checkDatabase(ctx context.Context, dbPath string, m *Manifest, rep *Report) {
	d, err := openImmutable(ctx, dbPath)
	if err != nil {
		rep.problem("database copy: %v", err)
		return
	}
	defer d.Close()
	if err := integrityCheck(ctx, d); err != nil {
		rep.problem("database copy: %v", err)
		return
	}
	schema, latest, err := store.SchemaVersions(ctx, d, store.EmbeddedMigrations())
	rep.BinarySchema = latest
	switch {
	case err != nil:
		rep.problem("database copy schema version: %v", err)
		return
	case schema != m.SchemaVersion:
		rep.problem("database copy is at schema version %d but the manifest says %d", schema, m.SchemaVersion)
	case schema > latest:
		rep.schemaTooNew = true
		rep.problem("backup schema version %d is newer than this binary supports (%d); restore with a newer hallpass", schema, latest)
	}
	ids, err := kekIDs(ctx, d)
	if err != nil {
		rep.problem("%v", err)
	} else if strings.Join(ids, ",") != m.KEKID {
		rep.problem("keyring in the database copy is wrapped under KEK %q but the manifest says %q", strings.Join(ids, ","), m.KEKID)
	}
	n, head, err := checkChain(ctx, d, 0)
	rep.ChainLength = n
	switch {
	case err != nil:
		rep.problem("integrity chain in the database copy: %v", err)
	case head.Seq != m.ChainHead.Seq || head.Hash != m.ChainHead.Hash:
		rep.problem("integrity chain head %d %s differs from the manifest (%d %s)", head.Seq, head.Hash, m.ChainHead.Seq, m.ChainHead.Hash)
	default:
		// Not a restore blocker: `hallpass verify` reports it on the restored system.
		if p, err := headRecordProblem(ctx, d, head); err != nil {
			rep.problem("%v", err)
		} else if p != "" {
			rep.Warnings = append(rep.Warnings, p)
		}
	}
	checkSegments(ctx, d, dbPath, m, rep)
}

func integrityCheck(ctx context.Context, d *sql.DB) error {
	rows, err := d.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	var msgs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
		msgs = append(msgs, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(msgs) != 1 || msgs[0] != "ok" {
		if len(msgs) > 5 {
			msgs = append(msgs[:5], "…")
		}
		return fmt.Errorf("%w: integrity_check reported: %s", store.ErrCorrupt, strings.Join(msgs, "; "))
	}
	return nil
}

// checkSegments compares segment files with the database copy and checks that every segment that should have a
// file is either in the backup or recorded as missing.
func checkSegments(ctx context.Context, d *sql.DB, dbPath string, m *Manifest, rep *Report) {
	rows, err := segmentRows(ctx, d)
	if err != nil {
		rep.problem("%v", err)
		return
	}
	byID := make(map[string]segmentRow, len(rows))
	for _, r := range rows {
		byID[r.id] = r
		// SR-16: every row must have valid IDs and name its canonical location; restore rewrites paths from the IDs.
		if _, err := layout.RelPath(r.sessionID, r.id); err != nil {
			rep.problem("segment %s: %v", r.id, err)
		} else if !layout.Matches(r.path, r.sessionID, r.id) {
			rep.problem("segment %s: stored path %q is not its location under recordings/", r.id, r.path)
		}
		if r.state == "deleted" {
			if _, _, ok, err := tombstoneOf(ctx, d, r.id); err != nil {
				rep.problem("%v", err)
			} else if !ok {
				if has, _ := hasTable(ctx, d, "recording_tombstones"); has {
					rep.Warnings = append(rep.Warnings, fmt.Sprintf("segment %s is deleted without a retention tombstone", r.id))
				}
			}
		}
	}
	backupDir := filepath.Dir(dbPath)
	inBackup := map[string]bool{}
	for _, f := range m.Files {
		if f.Kind != KindSegment {
			continue
		}
		inBackup[f.SegmentID] = true
		row, ok := byID[f.SegmentID]
		if !ok {
			rep.problem("segment file %s has no row in the database copy", f.Path)
			continue
		}
		if rel, err := layout.RelPath(row.sessionID, row.id); err == nil {
			want := path.Join(store.RecordingsDir, filepath.ToSlash(rel))
			if f.Path != want && (!f.OpenAtSnapshot || f.Path != want+hprec.PartialSuffix) {
				rep.problem("segment %s: backup file path %s is not its location %s", f.SegmentID, f.Path, want)
				continue
			}
		}
		if f.OpenAtSnapshot != (row.state == "open") {
			rep.problem("segment %s: manifest and database copy disagree about its state", f.SegmentID)
			continue
		}
		if f.OpenAtSnapshot {
			continue
		}
		h := newSegHasher(row.bytes)
		if _, _, err := hashFile(filepath.Join(backupDir, filepath.FromSlash(f.Path)), h); err != nil {
			rep.problem("%s: %v", f.Path, err)
			continue
		}
		switch problem := h.check(row.header, row.ciphertext); problem {
		case "":
		case f.Problem:
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("segment %s: %s (already so when the backup was taken)", f.SegmentID, problem))
		default:
			rep.problem("segment %s: %s", f.SegmentID, problem)
		}
	}
	missing := map[string]bool{}
	for _, id := range m.Segments.Missing {
		missing[id] = true
	}
	for _, r := range rows {
		switch r.state {
		case "finalized", "interrupted", "open":
			if !inBackup[r.id] && !missing[r.id] {
				rep.problem("segment %s (%s) is neither in the backup nor recorded as missing", r.id, r.state)
			}
		}
	}
}
