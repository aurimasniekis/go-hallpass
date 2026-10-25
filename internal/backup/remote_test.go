package backup_test

import (
	"bytes"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/backup"
	"github.com/aurimasniekis/go-hallpass/internal/s3client"
	"github.com/aurimasniekis/go-hallpass/internal/s3client/s3test"
)

func remoteStore(t *testing.T) (*s3test.Server, *s3client.Client) {
	t.Helper()
	srv := s3test.New(t, "AKIDTEST")
	c, err := s3client.New(s3client.Config{Endpoint: srv.URL, Bucket: "hp-backups", PathStyle: true, AccessKeyID: "AKIDTEST",
		SecretAccessKey: "secret", CABundlePEM: srv.CAPEM(), AllowPrivateNetwork: true})
	must(t, err)
	return srv, c
}

// A remote backup uploads a sealed snapshot and manifest plus each segment once; a download rebuilds an ordinary
// backup directory that verifies and restores.
func TestRemoteRoundTrip(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"uptime", "df -h", "id"} {
		f.finished(c)
	}
	ctx := f.ctx
	srv, objs := remoteStore(t)
	kek := f.a.Keyring.Wrapper()
	stored := map[string]string{}
	opts := func(id string) backup.RemoteOptions {
		return backup.RemoteOptions{Prefix: "hallpass/", BackupID: id, StageDir: t.TempDir(),
			Stored: func(seg, key string) bool { return stored[seg] == key }}
	}

	res, err := backup.CreateRemote(ctx, f.a.Store, kek, objs, opts("bkp_1"))
	must(t, err)
	if len(res.Segments) != 3 || len(res.Problems) != 0 || res.Manifest.KEKID != kek.ID() {
		t.Fatalf("result %+v", res)
	}
	for _, s := range res.Segments {
		if !s.Uploaded || !strings.HasPrefix(s.Object, backup.RemoteRecordingsDir) {
			t.Fatalf("segment %+v", s)
		}
		stored[s.SegmentID] = s.KeyID
	}
	keys := srv.Keys("hp-backups")
	if len(keys) != 5 {
		t.Fatalf("objects %v", keys)
	}
	db, _ := srv.Object("hp-backups", "hallpass/snapshots/bkp_1/db.hpbak")
	if !bytes.HasPrefix(db, []byte(backup.SealedMagic)) || bytes.Contains(db, []byte("SQLite format 3")) {
		t.Fatal("the database snapshot is not sealed")
	}
	man, _ := srv.Object("hp-backups", "hallpass/snapshots/bkp_1/manifest.hpbak")
	if !bytes.HasPrefix(man, []byte(backup.SealedMagic)) || bytes.Contains(man, []byte("schema_version")) || bytes.Contains(man, []byte(f.a.Store.Dir())) {
		t.Fatal("the manifest is not sealed")
	}

	// A second backup reuses the segment objects.
	f.finished("hostname")
	res2, err := backup.CreateRemote(ctx, f.a.Store, kek, objs, opts("bkp_2"))
	must(t, err)
	uploaded := 0
	for _, s := range res2.Segments {
		if s.Uploaded {
			uploaded++
		}
	}
	if len(res2.Segments) != 4 || uploaded != 1 {
		t.Fatalf("second backup uploaded %d of %d segments", uploaded, len(res2.Segments))
	}

	list, err := backup.ListRemote(ctx, objs, "hallpass/")
	must(t, err)
	if len(list) != 2 || list[0].ID != "bkp_2" || !list[0].Complete || !list[1].Complete {
		t.Fatalf("list %+v", list)
	}

	out := filepath.Join(t.TempDir(), "dl")
	m, err := backup.DownloadRemote(ctx, objs, kek, "hallpass/", "bkp_2", out)
	must(t, err)
	rep, err := backup.Verify(ctx, out)
	must(t, err)
	if !rep.OK || rep.Files != 5 || rep.ChainLength != 4 {
		t.Fatalf("downloaded backup verify: %+v", rep)
	}
	must(t, f.a.Close())
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := backup.Restore(ctx, out, target, backup.RestoreOptions{KEKID: m.KEKID}); err != nil {
		t.Fatal(err)
	}
	a2 := openApp(t, testConfig(target, f.cfg.KEK.File))
	defer a2.Close()
	vr, err := a2.Recording.Verify(ctx, "")
	must(t, err)
	if !vr.OK || !vr.ChainOK || len(vr.Segments) != 4 {
		t.Fatalf("restored verify: %+v", vr)
	}

	// Deleting a backup removes its own objects; shared segments stay for the sweep to decide.
	must(t, backup.DeleteRemote(ctx, objs, "hallpass/", "bkp_1"))
	list, err = backup.ListRemote(ctx, objs, "hallpass/")
	must(t, err)
	if len(list) != 1 || list[0].ID != "bkp_2" {
		t.Fatalf("after delete %+v", list)
	}
	if n := len(srv.Keys("hp-backups")); n != 6 {
		t.Fatalf("%d objects after delete, want 4 segments + 2 for bkp_2", n)
	}
}

func TestRemoteDownloadRejects(t *testing.T) {
	f := newFixture(t)
	f.finished("uptime")
	ctx := f.ctx
	srv, objs := remoteStore(t)
	kek := f.a.Keyring.Wrapper()
	res, err := backup.CreateRemote(ctx, f.a.Store, kek, objs, backup.RemoteOptions{BackupID: "bkp_1", StageDir: t.TempDir()})
	must(t, err)

	if _, err := backup.DownloadRemote(ctx, objs, backup.NewTestKEK(t), "", "bkp_1", filepath.Join(t.TempDir(), "x")); !errors.Is(err, backup.ErrKEKMismatch) {
		t.Fatalf("other KEK: %v", err)
	}
	seg := res.Segments[0].Object
	b, _ := srv.Object("hp-backups", seg)
	bad := append([]byte(nil), b...)
	bad[len(bad)-3] ^= 1
	srv.SetObject("hp-backups", seg, bad)
	if _, err := backup.DownloadRemote(ctx, objs, kek, "", "bkp_1", filepath.Join(t.TempDir(), "y")); !errors.Is(err, backup.ErrInvalid) {
		t.Fatalf("tampered segment: %v", err)
	}
	srv.SetObject("hp-backups", seg, b)
	db, _ := srv.Object("hp-backups", "snapshots/bkp_1/db.hpbak")
	srv.SetObject("hp-backups", "snapshots/bkp_1/db.hpbak", db[:len(db)-10])
	if _, err := backup.DownloadRemote(ctx, objs, kek, "", "bkp_1", filepath.Join(t.TempDir(), "z")); !errors.Is(err, backup.ErrSealed) {
		t.Fatalf("truncated snapshot: %v", err)
	}
}

// A backup whose upload fails before the manifest is listed as incomplete and never as restorable.
func TestRemoteIncomplete(t *testing.T) {
	f := newFixture(t)
	f.finished("uptime")
	srv, objs := remoteStore(t)
	srv.Fail = func(r *http.Request) int {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifest.hpbak") {
			return http.StatusServiceUnavailable
		}
		return 0
	}
	if _, err := backup.CreateRemote(f.ctx, f.a.Store, f.a.Keyring.Wrapper(), objs, backup.RemoteOptions{BackupID: "bkp_1", StageDir: t.TempDir()}); err == nil {
		t.Fatal("failed manifest upload reported success")
	}
	list, err := backup.ListRemote(f.ctx, objs, "")
	must(t, err)
	if len(list) != 1 || list[0].Complete {
		t.Fatalf("list %+v", list)
	}
}

func TestValidatePrefix(t *testing.T) {
	for _, ok := range []string{"", "hallpass/", "prod/hp-1/"} {
		if err := backup.ValidatePrefix(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"hallpass", "/hallpass/", "a//b/", "a/../", "a b/", "a?/", "./"} {
		if err := backup.ValidatePrefix(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
