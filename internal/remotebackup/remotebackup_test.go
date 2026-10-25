package remotebackup_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/backup"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/policy"
	"github.com/aurimasniekis/go-hallpass/internal/remotebackup"
	"github.com/aurimasniekis/go-hallpass/internal/s3client"
	"github.com/aurimasniekis/go-hallpass/internal/s3client/s3test"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/testutil/sshkeys"
)

var admin = audit.Actor{Type: audit.ActorOperator, ID: "opr_admin"}

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// fx is a running App with a grant and an open connection, so finished channels leave recording segments.
type fx struct {
	t                       *testing.T
	ctx                     context.Context
	a                       *app.App
	agent, key, grant, conn string
	srv                     *s3test.Server
}

func insertOperator(t *testing.T, s *store.Store, role string) string {
	t.Helper()
	id := ids.New(ids.Operator)
	must(t, s.W().Tx(context.Background(), func(tx *store.Tx) error {
		if _, err := tx.SQL.ExecContext(context.Background(), `INSERT INTO operators (id, email, display_name, enabled, provisioned_via,
			created_at, created_by, updated_at) VALUES (?, ?, 'op', 1, 'admin', ?, 'test', ?)`, id, id+"@example.com", tx.NowMicros(), tx.NowMicros()); err != nil {
			return err
		}
		_, err := tx.SQL.ExecContext(context.Background(), `INSERT INTO operator_roles (operator_id, role, source) VALUES (?, ?, 'manual')`, id, role)
		return err
	}))
	return id
}

func newFx(t *testing.T) *fx {
	t.Helper()
	k, err := keyring.GenerateKEK()
	must(t, err)
	kekFile := filepath.Join(t.TempDir(), "kek")
	must(t, keyring.WriteKEKFile(kekFile, k))
	cfg := config.Default()
	cfg.Mode, cfg.DataDir, cfg.KEK.File = "development", filepath.Join(t.TempDir(), "data"), kekFile
	cfg.Egress.AllowCIDRs = []string{"10.0.0.0/8"}
	a, err := app.New(context.Background(), cfg, slog.New(slog.DiscardHandler))
	must(t, err)
	t.Cleanup(func() { _ = a.Close() })
	f := &fx{t: t, ctx: context.Background(), a: a, srv: s3test.New(t, "AKIDTEST")}
	ctx := f.ctx
	ag, err := a.Agents.Create(ctx, admin, agents.CreateInput{Name: "sre-bot", Groups: []string{"sre"}, PublicKeys: []string{sshkeys.Ed25519(t).AuthorizedLine("")}})
	must(t, err)
	keys, err := a.Agents.Keys(ctx, ag.ID)
	must(t, err)
	f.agent, f.key = ag.ID, keys[0].ID
	srv, err := a.Inventory.CreateServer(ctx, admin, inventory.ServerInput{Alias: ptr("web1"), Address: ptr("10.0.0.1")})
	must(t, err)
	role, err := a.Inventory.CreateRole(ctx, admin, srv.ID, inventory.RoleInput{Alias: ptr("inspect"), RemoteUser: ptr("ro"), MaxConcurrent: ptr(50), MaxConcurrentPerAgent: ptr(50)})
	must(t, err)
	_, err = a.Policy.CreateRule(ctx, admin, policy.Rule{Name: "sre", Effect: policy.EffectAllow, Level: policy.LevelRequestable, Enabled: true,
		Subjects: policy.SubjectSelector{AgentGroups: []string{"sre"}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	op := insertOperator(t, a.Store, "approver")
	_, err = a.Policy.CreateApproverRule(ctx, admin, policy.ApproverRule{Name: "oncall", Enabled: true,
		Operators: policy.OperatorSelector{Operators: []string{op}}, Targets: policy.TargetSelector{All: true}, Roles: policy.RoleSelector{All: true}})
	must(t, err)
	req, err := a.Access.CreateRequest(ctx, access.CreateRequestInput{AgentID: ag.ID, KeyID: f.key, ServerID: srv.ID, RoleID: role.ID, Reason: "debug", Duration: time.Hour})
	must(t, err)
	dec, err := a.Access.Decide(ctx, access.DecideInput{RequestID: req.Request.ID, Approve: true,
		Operator: policy.OperatorInfo{ID: op, Roles: []string{"approver"}, Enabled: true}, Channel: access.ChannelWeb})
	must(t, err)
	f.grant = dec.Grant.ID
	f.conn, err = a.Access.OpenConnection(ctx, access.ConnectionInfo{AgentID: ag.ID, KeyID: f.key, ClientUser: "x", ClientVersion: "SSH-2.0-test", SourceIP: "10.9.9.9"})
	must(t, err)
	a.RemoteBackup.Start(ctx)
	return f
}

// finished records and finalizes one channel and returns its segment ID.
func (f *fx) finished(cmd string) string {
	f.t.Helper()
	reg, err := f.a.Access.RegisterChannel(f.ctx, access.RegisterInput{ConnectionID: f.conn, AgentID: f.agent, KeyID: f.key, GrantID: f.grant, Kind: access.KindExec})
	must(f.t, err)
	rec, err := f.a.Recording.Open(f.ctx, reg, access.KindExec, false)
	must(f.t, err)
	must(f.t, rec.ExecRequested(cmd))
	must(f.t, rec.Output(sshproxy.StreamStdout, []byte("output of "+cmd+"\n")))
	status := 0
	must(f.t, rec.Exit(&status, ""))
	must(f.t, rec.Finalize("exit_status"))
	return rec.SegmentID()
}

func (f *fx) target(mod func(*remotebackup.TargetInput)) *remotebackup.Target {
	f.t.Helper()
	in := remotebackup.TargetInput{Endpoint: ptr(f.srv.URL), Bucket: ptr("hp-backups"), Prefix: ptr("hallpass/"), PathStyle: ptr(true),
		AccessKeyID: ptr("AKIDTEST"), SecretAccessKey: ptr("s3cret-value"), CABundlePEM: ptr(f.srv.CAPEM()), AllowPrivateNetwork: ptr(true)}
	if mod != nil {
		mod(&in)
	}
	tg, err := f.a.RemoteBackup.PutTarget(f.ctx, admin, in)
	must(f.t, err)
	return tg
}

// run starts a manual backup and waits for it.
func (f *fx) run() *remotebackup.Run {
	f.t.Helper()
	r, err := f.a.RemoteBackup.RunNow(f.ctx, admin)
	must(f.t, err)
	f.a.RemoteBackup.Wait()
	r, err = f.a.RemoteBackup.GetRun(f.ctx, r.ID)
	must(f.t, err)
	return r
}

func (f *fx) objects() []string { return f.srv.Keys("hp-backups") }

func hasPrefix(keys []string, p string) int {
	n := 0
	for _, k := range keys {
		if strings.HasPrefix(k, p) {
			n++
		}
	}
	return n
}

func TestTargetValidationAndSecret(t *testing.T) {
	f := newFx(t)
	svc := f.a.RemoteBackup
	if _, err := svc.GetTarget(f.ctx); apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("no target yet: %v", err)
	}
	for name, mod := range map[string]func(*remotebackup.TargetInput){
		"no secret":      func(in *remotebackup.TargetInput) { in.SecretAccessKey = nil },
		"short interval": func(in *remotebackup.TargetInput) { in.Interval = ptr("5m") },
		"bad prefix":     func(in *remotebackup.TargetInput) { in.Prefix = ptr("/abs") },
		"bad bucket":     func(in *remotebackup.TargetInput) { in.Bucket = ptr("UPPER") },
		"bad endpoint":   func(in *remotebackup.TargetInput) { in.Endpoint = ptr("ftp://x") },
		"keep last 0":    func(in *remotebackup.TargetInput) { in.KeepLast = ptr(int64(0)) },
		"bad region":     func(in *remotebackup.TargetInput) { in.Region = ptr("EU West") },
	} {
		in := remotebackup.TargetInput{Endpoint: ptr(f.srv.URL), Bucket: ptr("hp-backups"), AccessKeyID: ptr("AKIDTEST"), SecretAccessKey: ptr("x")}
		mod(&in)
		if _, err := svc.PutTarget(f.ctx, admin, in); !errors.Is(err, apperr.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	tg := f.target(nil)
	if tg.Interval != "1h0m0s" || tg.KeepLast != 48 || tg.KeepDailyDays != 30 || !tg.Enabled || tg.Version != 1 {
		t.Fatalf("defaults %+v", tg)
	}
	b, _ := json.Marshal(tg)
	if strings.Contains(string(b), "s3cret-value") || strings.Contains(string(b), "secret") {
		t.Fatalf("secret in the target JSON: %s", b)
	}
	var stored []byte
	must(t, f.a.Store.ReadDB().QueryRowContext(f.ctx, "SELECT secret_enc FROM backup_target").Scan(&stored))
	if strings.Contains(string(stored), "s3cret-value") {
		t.Fatal("secret stored in plaintext")
	}
	// Updates need the version; the secret is kept when omitted.
	if _, err := svc.PutTarget(f.ctx, admin, remotebackup.TargetInput{Interval: ptr("2h")}); apperr.CodeOf(err) != apperr.CodeConflict {
		t.Fatalf("update without version: %v", err)
	}
	tg, err := svc.PutTarget(f.ctx, admin, remotebackup.TargetInput{Interval: ptr("2h"), Version: tg.Version})
	must(t, err)
	if tg.Interval != "2h0m0s" || tg.Version != 2 {
		t.Fatalf("updated %+v", tg)
	}
	if res, err := svc.TestTarget(f.ctx); err != nil || !res.OK {
		t.Fatalf("test: %+v %v", res, err)
	}
	if n := len(f.objects()); n != 0 {
		t.Fatalf("connection test left %d objects", n)
	}
	must(t, svc.DeleteTarget(f.ctx, admin))
	if _, err := svc.GetTarget(f.ctx); apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("after delete: %v", err)
	}
}

// Retention keeps the newest backups and deletes a recording object once no kept backup was taken while it existed.
func TestRunsRetentionAndSweep(t *testing.T) {
	f := newFx(t)
	segA := f.finished("uptime")
	f.target(func(in *remotebackup.TargetInput) { in.KeepLast, in.KeepDailyDays = ptr(int64(2)), ptr(int64(0)) })

	r1 := f.run()
	if r1.State != "succeeded" || *r1.Segments != 1 || *r1.SegmentsUploaded != 1 || !r1.Stored {
		t.Fatalf("run 1 %+v", r1)
	}
	objs := f.objects()
	if hasPrefix(objs, "hallpass/snapshots/"+r1.ID+"/") != 2 || hasPrefix(objs, "hallpass/recordings/") != 1 {
		t.Fatalf("after run 1: %v", objs)
	}

	// Recording retention deletes segment A locally; segment B is recorded.
	must(t, f.a.Store.W().Tx(f.ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(f.ctx, "UPDATE recording_segments SET state = 'deleted' WHERE id = ?", segA)
		return err
	}))
	f.finished("df -h")

	r2 := f.run()
	var err error
	if r2.State != "succeeded" || *r2.Segments != 1 || *r2.SegmentsUploaded != 1 {
		t.Fatalf("run 2 %+v", r2)
	}
	if n := hasPrefix(f.objects(), "hallpass/recordings/"); n != 2 {
		t.Fatalf("segment A must stay while backup 1 is kept: %d recording objects", n)
	}

	r3 := f.run()
	if *r3.SegmentsUploaded != 0 {
		t.Fatalf("run 3 re-uploaded %d segments", *r3.SegmentsUploaded)
	}
	objs = f.objects()
	if hasPrefix(objs, "hallpass/snapshots/"+r1.ID+"/") != 0 || hasPrefix(objs, "hallpass/snapshots/"+r2.ID+"/") != 2 ||
		hasPrefix(objs, "hallpass/snapshots/"+r3.ID+"/") != 2 {
		t.Fatalf("retention kept the wrong backups: %v", objs)
	}
	if n := hasPrefix(objs, "hallpass/recordings/"); n != 1 {
		t.Fatalf("segment A not swept after backup 1 was deleted: %v", objs)
	}
	r1, err = f.a.RemoteBackup.GetRun(f.ctx, r1.ID)
	must(t, err)
	if r1.Stored {
		t.Fatal("run 1 still marked stored")
	}

	// The newest kept backup restores.
	c, err := s3client.New(s3client.Config{Endpoint: f.srv.URL, Bucket: "hp-backups", PathStyle: true, AccessKeyID: "AKIDTEST", SecretAccessKey: "s3cret-value",
		CABundlePEM: f.srv.CAPEM(), AllowPrivateNetwork: true})
	must(t, err)
	out := filepath.Join(t.TempDir(), "dl")
	_, err = backup.DownloadRemote(f.ctx, c, f.a.Keyring.Wrapper(), "hallpass/", r3.ID, out)
	must(t, err)
	rep, err := backup.Verify(f.ctx, out)
	must(t, err)
	if !rep.OK {
		t.Fatalf("downloaded backup: %+v", rep)
	}
}

func TestFailedRunAndScheduling(t *testing.T) {
	f := newFx(t)
	f.finished("uptime")
	svc := f.a.RemoteBackup
	tg := f.target(func(in *remotebackup.TargetInput) { in.SecretAccessKey = ptr("wrong"); in.AccessKeyID = ptr("WRONG") })
	r := f.run()
	if r.State != "failed" || r.Error == "" || r.Stored {
		t.Fatalf("failed run %+v", r)
	}
	st, err := svc.Status(f.ctx)
	must(t, err)
	// After a failure the next attempt is due within 15 minutes, not after the full interval.
	if st.NextRunAt == nil || st.NextRunAt.Sub(r.StartedAt) != 15*time.Minute || st.LastSuccess != nil {
		t.Fatalf("status %+v", st)
	}
	// Not due yet: Tick starts nothing.
	must(t, svc.Tick(f.ctx))
	svc.Wait()
	runs, err := svc.ListRuns(f.ctx, "", 10)
	must(t, err)
	if len(runs) != 1 {
		t.Fatalf("Tick ran early: %d runs", len(runs))
	}
	// A fixed target and a stale last run: Tick starts the scheduled backup.
	_, err = svc.PutTarget(f.ctx, admin, remotebackup.TargetInput{AccessKeyID: ptr("AKIDTEST"), SecretAccessKey: ptr("s3cret-value"), Version: tg.Version})
	must(t, err)
	must(t, f.a.Store.W().Tx(f.ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(f.ctx, "UPDATE backup_runs SET started_at = started_at - ?", (time.Hour).Microseconds())
		return err
	}))
	must(t, svc.Tick(f.ctx))
	svc.Wait()
	runs, err = svc.ListRuns(f.ctx, "", 10)
	must(t, err)
	if len(runs) != 2 || runs[0].Trigger != "schedule" || runs[0].State != "succeeded" {
		t.Fatalf("scheduled run %+v", runs[0])
	}
	if _, err := svc.RunNow(f.ctx, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RunNow(f.ctx, admin); !errors.Is(err, remotebackup.ErrRunning) && err != nil {
		t.Fatalf("second concurrent run: %v", err)
	}
	svc.Wait()
}

// Moving the target to another bucket or prefix starts over: every segment is uploaded again there.
func TestLocationChangeStartsOver(t *testing.T) {
	f := newFx(t)
	f.finished("uptime")
	tg := f.target(nil)
	f.run()
	_, err := f.a.RemoteBackup.PutTarget(f.ctx, admin, remotebackup.TargetInput{Prefix: ptr("moved/"), Version: tg.Version})
	must(t, err)
	r := f.run()
	if *r.SegmentsUploaded != 1 || hasPrefix(f.objects(), "moved/recordings/") != 1 {
		t.Fatalf("after moving: %+v %v", r, f.objects())
	}
}

// A run left running by a crashed process is marked interrupted on start.
func TestInterruptedOnStart(t *testing.T) {
	f := newFx(t)
	f.target(nil)
	must(t, f.a.Store.W().Tx(f.ctx, func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(f.ctx, `INSERT INTO backup_runs (id, generation, trigger, state, started_at) VALUES ('bkp_x', 1, 'schedule', 'running', 1)`)
		return err
	}))
	_ = os.MkdirAll(filepath.Join(f.a.Store.Dir(), store.BackupsDir, "remote-staging", "junk"), 0o700)
	f.a.RemoteBackup.Start(f.ctx)
	r, err := f.a.RemoteBackup.GetRun(f.ctx, "bkp_x")
	must(t, err)
	if r.State != "interrupted" {
		t.Fatalf("state %s", r.State)
	}
	if _, err := os.Stat(filepath.Join(f.a.Store.Dir(), store.BackupsDir, "remote-staging")); !os.IsNotExist(err) {
		t.Fatalf("staging dir left: %v", err)
	}
}
