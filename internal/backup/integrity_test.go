package backup

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
)

// finishedClosed records and finalizes one channel and closes the channel.
func (f *fixture) finishedClosed(cmd string) {
	f.t.Helper()
	reg, err := f.a.Access.RegisterChannel(f.ctx, access.RegisterInput{ConnectionID: f.conn, AgentID: f.agent, KeyID: f.keyID, GrantID: f.grant, Kind: access.KindExec})
	must(f.t, err)
	rec, err := f.a.Recording.Open(f.ctx, reg, access.KindExec, false)
	must(f.t, err)
	must(f.t, rec.ExecRequested(cmd))
	must(f.t, rec.Output(sshproxy.StreamStdout, []byte("output of "+cmd+"\n")))
	must(f.t, rec.Finalize("exit_status"))
	must(f.t, f.a.Access.CloseChannel(f.ctx, reg, access.CloseInfo{Reason: "exit_status"}))
}

// expire closes the fixture's session and runs retention with a negative retention, so every recording of the
// session is deleted now through the real retention path.
func (f *fixture) expire() {
	f.t.Helper()
	_, err := f.a.Access.RevokeGrant(f.ctx, f.adminOp, f.grant, "done")
	must(f.t, err)
	must(f.t, f.a.Access.CloseConnection(f.ctx, f.conn, "client_closed"))
	_, err = f.a.Access.CloseFinishedSessions(f.ctx)
	must(f.t, err)
	n, err := f.a.Recording.ApplyRetention(f.ctx, func(string) time.Duration { return -time.Hour })
	must(f.t, err)
	if n == 0 {
		f.t.Fatal("retention deleted nothing")
	}
}

// SR-17: anchors verify accepts a deleted segment only when retention left its tombstone; a row merely relabeled
// "deleted" is reported.
func TestAnchorsDeletedNeedsTombstone(t *testing.T) {
	f := newFixture(t)
	for _, c := range []string{"a", "b"} {
		f.finishedClosed(c)
	}
	anchors, _ := exportAll(t, f, 0)
	exec(t, f, "UPDATE recording_segments SET state = 'deleted' WHERE id = (SELECT segment_id FROM integrity_chain WHERE seq = 1)")
	if rep := verifyAnchors(t, f, anchors); rep.OK || !hasProblem(rep, "tombstone") {
		t.Fatalf("relabeled deletion accepted: %+v", rep)
	}
	exec(t, f, "UPDATE recording_segments SET state = 'finalized' WHERE id = (SELECT segment_id FROM integrity_chain WHERE seq = 1)")
	f.expire()
	if rep := verifyAnchors(t, f, anchors); !rep.OK {
		t.Fatalf("real retention rejected: %+v", rep)
	}
}

// openWritable opens a database copy inside a backup for an attacker-style edit.
func openWritable(t *testing.T, p string) *sql.DB {
	t.Helper()
	q := url.Values{}
	q.Add("_pragma", "journal_mode(DELETE)")
	d, err := sql.Open("sqlite", "file:"+p+"?"+q.Encode())
	must(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// SR-16 (HP-OPS-004): a backup whose database points a segment row outside recordings/ is refused by verify and
// restore, even when the manifest was recomputed to match.
func TestVerifyRefusesForeignSegmentPaths(t *testing.T) {
	base, _ := backupOf(t, 1)
	for name, path := range map[string]string{
		"outside the data dir": "/etc/hallpass/kek",
		"traversal":            "RECDIR/../../kek",
	} {
		t.Run(name, func(t *testing.T) {
			dir := copyTree(t, base)
			m := readManifestT(t, dir)
			if path == "RECDIR/../../kek" {
				path = filepath.Join(m.SourceDataDir, "recordings") + "/../../kek"
			}
			d := openWritable(t, filepath.Join(dir, DBFile))
			if _, err := d.Exec("UPDATE recording_segments SET path = ?", path); err != nil {
				t.Fatal(err)
			}
			must(t, d.Close())
			rehash(t, dir, DBFile)
			expectProblem(t, dir, "path")
			_, err := Restore(context.Background(), dir, filepath.Join(t.TempDir(), "r"), RestoreOptions{})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("restore with a foreign segment path: %v", err)
			}
		})
	}
}

// SR-18 (HP-OPS-003, HP-CRY-002): after a purpose-key rotation, retirement of the old version and a KEK rotation,
// backups still work and record the new KEK.
func TestBackupAfterKEKRotationWithRetiredKey(t *testing.T) {
	f := newFixture(t)
	f.finished("a")
	ctx := f.ctx
	if _, err := f.a.Keyring.Rotate(ctx, f.a.Store, keyring.PurposeToken); err != nil {
		t.Fatal(err)
	}
	must(t, f.a.Keyring.Retire(ctx, f.a.Store, keyring.PurposeToken, 1))
	oldW, err := keyring.LoadKEK(keyring.Source{Kind: "file", File: f.cfg.KEK.File})
	must(t, err)
	newFile := writeKEK(t)
	newW, err := keyring.LoadKEK(keyring.Source{Kind: "file", File: newFile})
	must(t, err)
	if _, err := keyring.RotateKEK(ctx, f.a.Store, oldW, newW); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "b")
	res, err := Create(ctx, f.a.Store, out, Options{})
	if err != nil {
		t.Fatalf("backup after KEK rotation: %v", err)
	}
	if res.Manifest.KEKID != newW.ID() {
		t.Fatalf("manifest kek_id %s, want %s", res.Manifest.KEKID, newW.ID())
	}
	if rep, err := Verify(ctx, out); err != nil || !rep.OK {
		t.Fatalf("verify: %v %+v", err, rep)
	}
	_ = os.Remove(newFile)
}
