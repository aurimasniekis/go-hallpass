package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/s3client"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// Remote backups (ADR-0054) store the same content as a local backup in S3-compatible object storage:
//
//	<prefix>snapshots/<backup_id>/db.hpbak        the database snapshot, sealed (HPBAK1)
//	<prefix>snapshots/<backup_id>/manifest.hpbak  the manifest, sealed; written last, so it marks a complete backup
//	<prefix>snapshots/<backup_id>/recordings/…    segments open at snapshot time (.partial), as stored
//	<prefix>recordings/<shard>/<session>/<id>.hprec  finalized and interrupted segments, as stored, shared by backups
//
// Segment files are already ciphertext and are uploaded once; a later backup reuses them unless the segment's data
// key was rewrapped since (its key ID changed). Downloading rebuilds an ordinary backup directory that `hallpass
// restore` accepts.
const (
	RemoteSnapshotsDir  = "snapshots/"
	RemoteRecordingsDir = "recordings/"
	remoteDBObject      = "db.hpbak"
	remoteManifest      = "manifest.hpbak"
)

// ObjectStore is the object storage a remote backup uses (satisfied by *s3client.Client).
type ObjectStore interface {
	Put(ctx context.Context, key string, body io.Reader, size int64, payloadSHA256 string) error
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	List(ctx context.Context, prefix string) ([]s3client.Object, error)
	Delete(ctx context.Context, key string) error
}

// RemoteSnapshotPrefix returns the key prefix of one backup's objects.
func RemoteSnapshotPrefix(prefix, backupID string) string {
	return prefix + RemoteSnapshotsDir + backupID + "/"
}

// RemoteSegment is a segment file a remote backup references.
type RemoteSegment struct {
	SegmentID string
	KeyID     string
	// Object is the key below the prefix.
	Object string
	Size   int64
	SHA256 string
	// Uploaded is true when this run uploaded it (false: reused from an earlier backup).
	Uploaded bool
}

// RemoteOptions configure CreateRemote.
type RemoteOptions struct {
	// Prefix is the key prefix ("" or ending in "/").
	Prefix   string
	BackupID string
	// StageDir is a local directory for the snapshot and sealed files (removed afterwards).
	StageDir string
	Clock    clock.Clock
	// Stored reports whether the bucket already holds this version (key ID) of a finalized or interrupted segment.
	Stored func(segmentID, keyID string) bool
}

// RemoteResult is the outcome of CreateRemote.
type RemoteResult struct {
	Manifest      *Manifest
	DBBytes       int64
	UploadedBytes int64
	// Segments lists the shared segment objects the backup references (finalized and interrupted).
	Segments []RemoteSegment
	Problems []string
}

// CreateRemote snapshots src and uploads a complete backup. The database snapshot and the manifest are sealed under
// kek; segment files are uploaded as stored. Nothing is uploaded under the backup's manifest key unless every other
// object of the backup is stored.
func CreateRemote(ctx context.Context, src Snapshotter, kek keyring.KeyWrapper, objs ObjectStore, o RemoteOptions) (*RemoteResult, error) {
	if err := ValidatePrefix(o.Prefix); err != nil {
		return nil, err
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Stored == nil {
		o.Stored = func(string, string) bool { return false }
	}
	stage, err := os.MkdirTemp(o.StageDir, ".remote-"+o.BackupID+"-")
	if err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()

	dbPath := filepath.Join(stage, DBFile)
	if err := src.Snapshot(ctx, dbPath); err != nil {
		return nil, fmt.Errorf("database snapshot: %w", err)
	}
	info, err := readSnapshot(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	m := &Manifest{Format: Format, Version: FormatVersion, CreatedAt: o.Clock.Now().UTC(), HallpassVersion: buildinfo.Get().Version,
		KEKNotice: KEKNotice, SourceDataDir: src.Dir(), SchemaVersion: info.schema, ChainHead: info.head}
	switch len(info.kekIDs) {
	case 0:
		m.Warnings = append(m.Warnings, "the database has no keyring yet; no kek_id recorded")
	case 1:
		m.KEKID = info.kekIDs[0]
		if m.KEKID != kek.ID() {
			return nil, fmt.Errorf("%w: the keyring is wrapped under KEK %s, the server holds %s", ErrKEKMismatch, m.KEKID, kek.ID())
		}
	default:
		return nil, fmt.Errorf("keyring keys are wrapped under several KEKs (%s); finish `hallpass keys rotate-kek` first", strings.Join(info.kekIDs, ", "))
	}
	res := &RemoteResult{Manifest: m}
	snap := RemoteSnapshotPrefix("", o.BackupID) // object keys in the manifest are relative to the prefix

	recDir := filepath.Join(src.Dir(), store.RecordingsDir)
	for _, seg := range info.segments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, rs, problem, err := uploadSegment(ctx, objs, seg, recDir, o.Prefix, snap, o.Stored)
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
			m.Segments.Copied++
			if f.OpenAtSnapshot {
				m.Segments.OpenAtSnapshot++
			}
			if f.Problem != "" {
				res.Problems = append(res.Problems, fmt.Sprintf("segment %s: %s", seg.id, f.Problem))
			}
			if rs != nil {
				res.Segments = append(res.Segments, *rs)
				if rs.Uploaded {
					res.UploadedBytes += rs.Size
				}
			} else {
				res.UploadedBytes += f.Size
			}
		}
	}

	size, sum, err := hashFile(dbPath)
	if err != nil {
		return nil, err
	}
	res.DBBytes = size
	dbKey := snap + remoteDBObject
	n, err := putSealed(ctx, objs, o.Prefix+dbKey, dbPath, kek, SealedKindDatabase, o.BackupID)
	if err != nil {
		return nil, fmt.Errorf("upload database snapshot: %w", err)
	}
	res.UploadedBytes += n
	m.Files = append([]File{{Path: DBFile, Size: size, SHA256: hex.EncodeToString(sum[:]), Kind: KindDatabase, Object: dbKey}}, m.Files...)

	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	mPath := filepath.Join(stage, ManifestFile)
	if err := writeFileSync(mPath, append(mb, '\n')); err != nil {
		return nil, err
	}
	if n, err = putSealed(ctx, objs, o.Prefix+snap+remoteManifest, mPath, kek, SealedKindManifest, o.BackupID); err != nil {
		return nil, fmt.Errorf("upload manifest: %w", err)
	}
	res.UploadedBytes += n
	return res, nil
}

// uploadSegment uploads one segment file as the snapshot sees it. Finalized and interrupted segments go to the shared
// recordings/ prefix (skipped when already stored); a segment open at snapshot time goes below the snapshot.
func uploadSegment(ctx context.Context, objs ObjectStore, seg segmentRow, recDir, prefix, snap string, stored func(string, string) bool) (*File, *RemoteSegment, string, error) {
	candidates, err := segmentCandidates(seg, recDir)
	if err != nil || candidates == nil {
		return nil, nil, "", err
	}
	for _, src := range candidates {
		relSlash, err := segmentRelPath(seg, recDir, src)
		if err != nil {
			return nil, nil, "", err
		}
		var h *segHasher
		var extra []io.Writer
		if seg.state != "open" {
			h = newSegHasher(seg.bytes)
			extra = append(extra, h)
		}
		size, sum, err := hashFile(src, extra...)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, "", fmt.Errorf("read segment %s: %w", seg.id, err)
		}
		f := &File{Path: relSlash, Size: size, SHA256: hex.EncodeToString(sum[:]), Kind: KindSegment, SegmentID: seg.id, State: seg.state,
			OpenAtSnapshot: seg.state == "open"}
		if h != nil {
			f.Problem = h.check(seg.header, seg.ciphertext)
		}
		if seg.state == "open" {
			f.Object = snap + relSlash
			if err := putFile(ctx, objs, prefix+f.Object, src, size, f.SHA256); err != nil {
				return nil, nil, "", fmt.Errorf("upload segment %s: %w", seg.id, err)
			}
			return f, nil, "", nil
		}
		f.Object = relSlash // recordings/… is also the shared key below the prefix
		rs := &RemoteSegment{SegmentID: seg.id, KeyID: seg.keyID, Object: f.Object, Size: size, SHA256: f.SHA256}
		if !stored(seg.id, seg.keyID) {
			if err := putFile(ctx, objs, prefix+f.Object, src, size, f.SHA256); err != nil {
				return nil, nil, "", fmt.Errorf("upload segment %s: %w", seg.id, err)
			}
			rs.Uploaded = true
		}
		return f, rs, "", nil
	}
	return nil, nil, fmt.Sprintf("segment %s (%s): file %s missing at backup time", seg.id, seg.state, seg.path), nil
}

// putFile uploads a file whose size and SHA-256 are known. A file that changed in between fails the upload (S3 checks
// the payload hash), which happens only for a segment rewrapped mid-backup; the next backup uploads it.
func putFile(ctx context.Context, objs ObjectStore, key, src string, size int64, sha string) error {
	f, err := openRegular(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return objs.Put(ctx, key, io.LimitReader(f, size), size, sha)
}

// putSealed seals src into the staging directory and uploads it, returning the uploaded size.
func putSealed(ctx context.Context, objs ObjectStore, key, src string, kek keyring.KeyWrapper, kind, backupID string) (int64, error) {
	in, err := openRegular(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	sealedPath := src + ".hpbak"
	out, err := os.OpenFile(sealedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // our staging directory
	if err != nil {
		return 0, err
	}
	err = Seal(out, in, kek, kind, backupID)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	size, sum, err := hashFile(sealedPath)
	if err != nil {
		return 0, err
	}
	if err := putFile(ctx, objs, key, sealedPath, size, hex.EncodeToString(sum[:])); err != nil {
		return 0, err
	}
	return size, nil
}

// ValidatePrefix accepts "" or a slash-terminated prefix of safe characters.
func ValidatePrefix(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > 256 || !strings.HasSuffix(p, "/") || strings.HasPrefix(p, "/") || strings.Contains(p, "//") {
		return errors.New("prefix must be empty or like hallpass/ (no leading slash, ends with a slash)")
	}
	for _, c := range p {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("-_./", c) {
			return fmt.Errorf("prefix contains %q; use letters, digits, - _ . /", c)
		}
	}
	for _, part := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
		if part == "." || part == ".." {
			return errors.New("prefix must not contain . or .. segments")
		}
	}
	return nil
}

// RemoteBackup is a backup found in the bucket.
type RemoteBackup struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	// Complete is true when the manifest exists (every other object was stored first).
	Complete bool  `json:"complete"`
	Bytes    int64 `json:"bytes"`
}

// ListRemote lists the backups below prefix, newest first.
func ListRemote(ctx context.Context, objs ObjectStore, prefix string) ([]RemoteBackup, error) {
	list, err := objs.List(ctx, prefix+RemoteSnapshotsDir)
	if err != nil {
		return nil, err
	}
	by := map[string]*RemoteBackup{}
	for _, o := range list {
		rest := strings.TrimPrefix(o.Key, prefix+RemoteSnapshotsDir)
		id, obj, ok := strings.Cut(rest, "/")
		if !ok || id == "" {
			continue
		}
		b := by[id]
		if b == nil {
			b = &RemoteBackup{ID: id}
			by[id] = b
		}
		b.Bytes += o.Size
		if obj == remoteManifest {
			b.Complete, b.CreatedAt = true, o.LastModified
		}
	}
	out := make([]RemoteBackup, 0, len(by))
	for _, b := range by {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// DeleteRemote removes one backup's own objects (shared recording objects are left to the caller's sweep).
func DeleteRemote(ctx context.Context, objs ObjectStore, prefix, backupID string) error {
	if backupID == "" || strings.ContainsAny(backupID, "/.") {
		return fmt.Errorf("invalid backup ID %q", backupID)
	}
	list, err := objs.List(ctx, RemoteSnapshotPrefix(prefix, backupID))
	if err != nil {
		return err
	}
	// The manifest goes first, so an interrupted delete never leaves a "complete" backup with missing objects.
	sort.SliceStable(list, func(i, j int) bool { return strings.HasSuffix(list[i].Key, "/"+remoteManifest) })
	for _, o := range list {
		if err := objs.Delete(ctx, o.Key); err != nil {
			return err
		}
	}
	return nil
}

// ReadRemoteManifest downloads and opens one backup's manifest.
func ReadRemoteManifest(ctx context.Context, objs ObjectStore, kek keyring.KeyWrapper, prefix, backupID string) (*Manifest, error) {
	rc, _, err := objs.Get(ctx, RemoteSnapshotPrefix(prefix, backupID)+remoteManifest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	r, _, err := OpenSealed(rc, kek, SealedKindManifest, backupID)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(r, 512<<20))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: manifest: %w", ErrInvalid, err)
	}
	if m.Format != Format || m.Version != FormatVersion {
		return nil, fmt.Errorf("%w: not a HallPass backup manifest", ErrInvalid)
	}
	return &m, nil
}

// DownloadRemote rebuilds backup backupID as an ordinary backup directory at dest (which must not exist), checking
// every file against the manifest. Run Verify on it, then Restore.
func DownloadRemote(ctx context.Context, objs ObjectStore, kek keyring.KeyWrapper, prefix, backupID, dest string) (*Manifest, error) {
	dest, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, dest)
	}
	m, err := ReadRemoteManifest(ctx, objs, kek, prefix, backupID)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dest)+".tmp-")
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	for _, f := range m.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.Object == "" || !filepath.IsLocal(filepath.FromSlash(f.Path)) || path.Clean(f.Path) != f.Path {
			return nil, fmt.Errorf("%w: manifest entry %q", ErrInvalid, f.Path)
		}
		if err := downloadFile(ctx, objs, kek, prefix, backupID, f, filepath.Join(tmp, filepath.FromSlash(f.Path))); err != nil {
			return nil, err
		}
	}
	local := *m
	local.Files = append([]File(nil), m.Files...)
	for i := range local.Files {
		local.Files[i].Object = ""
	}
	if err := writeManifest(tmp, &local); err != nil {
		return nil, err
	}
	if err := fsyncTree(tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return nil, err
	}
	ok = true
	return m, store.FsyncDir(parent)
}

func downloadFile(ctx context.Context, objs ObjectStore, kek keyring.KeyWrapper, prefix, backupID string, f File, dst string) error {
	rc, _, err := objs.Get(ctx, prefix+f.Object)
	if err != nil {
		return fmt.Errorf("download %s: %w", f.Object, err)
	}
	defer rc.Close()
	var r io.Reader = rc
	if f.Kind == KindDatabase {
		if r, _, err = OpenSealed(rc, kek, SealedKindDatabase, backupID); err != nil {
			return fmt.Errorf("database snapshot: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside our staging directory
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, f.Size+1))
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download %s: %w", f.Object, err)
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%w: %s does not match the manifest (size or SHA-256)", ErrInvalid, f.Path)
	}
	return nil
}
