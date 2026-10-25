// Package remotebackup runs scheduled and on-demand backups to S3-compatible object storage (ADR-0054): one target
// configured in the console, the API or Terraform, its secret access key sealed at rest, a run history, and
// retention that keeps the newest backups plus one per day and deletes recording objects no kept backup references.
// The backup content and format are internal/backup's (CreateRemote); this package adds the database bookkeeping.
package remotebackup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/backup"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/s3client"
	"github.com/aurimasniekis/go-hallpass/internal/store"
	"github.com/aurimasniekis/go-hallpass/internal/store/db"
)

// Limits and defaults.
const (
	MinInterval         = 15 * time.Minute
	MaxInterval         = 7 * 24 * time.Hour
	DefaultInterval     = time.Hour
	DefaultKeepLast     = 48
	DefaultKeepDaily    = 30
	retryAfterFailure   = 15 * time.Minute
	maxErrorLen         = 1000
	bookkeepingBatch    = 500
	stagingDirName      = "remote-staging"
	defaultRegion       = "us-east-1"
	maxCABundle         = 64 << 10
	runStateRunning     = "running"
	runStateSucceeded   = "succeeded"
	runStateFailed      = "failed"
	runStateInterrupted = "interrupted"
)

// secretAAD binds the sealed secret access key to its column and row (resealed by the keyring job).
var secretAAD = keyring.FieldAAD("backup_target", "secret_enc", "default")

var reRegion = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// ErrRunning means a backup run is already in progress.
var ErrRunning = apperr.New(apperr.CodeConflict, "a backup is already running")

// Target is the configured object storage location (never the secret).
type Target struct {
	Enabled             bool      `json:"enabled"`
	Endpoint            string    `json:"endpoint"`
	Region              string    `json:"region"`
	Bucket              string    `json:"bucket"`
	Prefix              string    `json:"prefix"`
	PathStyle           bool      `json:"path_style"`
	AccessKeyID         string    `json:"access_key_id"`
	CABundlePEM         string    `json:"ca_bundle_pem,omitempty"`
	AllowPrivateNetwork bool      `json:"allow_private_network"`
	Interval            string    `json:"interval"`
	KeepLast            int64     `json:"keep_last"`
	KeepDailyDays       int64     `json:"keep_daily_days"`
	Version             int64     `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`

	generation int64
	secret     []byte
	interval   time.Duration
}

// TargetInput creates or replaces the target. Nil fields keep the current value (defaults on create).
// SecretAccessKey is required on create and write-only.
type TargetInput struct {
	Enabled             *bool   `json:"enabled"`
	Endpoint            *string `json:"endpoint"`
	Region              *string `json:"region"`
	Bucket              *string `json:"bucket"`
	Prefix              *string `json:"prefix"`
	PathStyle           *bool   `json:"path_style"`
	AccessKeyID         *string `json:"access_key_id"`
	SecretAccessKey     *string `json:"secret_access_key"`
	CABundlePEM         *string `json:"ca_bundle_pem"`
	AllowPrivateNetwork *bool   `json:"allow_private_network"`
	Interval            *string `json:"interval"`
	KeepLast            *int64  `json:"keep_last"`
	KeepDailyDays       *int64  `json:"keep_daily_days"`
	// Version is the current version for an update (If-Match); 0 creates.
	Version int64 `json:"-"`
}

// Run is one backup run.
type Run struct {
	ID               string     `json:"id"`
	Trigger          string     `json:"trigger"`
	RequestedBy      string     `json:"requested_by,omitempty"`
	State            string     `json:"state"`
	StartedAt        time.Time  `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	DBBytes          *int64     `json:"db_bytes,omitempty"`
	Segments         *int64     `json:"segments,omitempty"`
	SegmentsUploaded *int64     `json:"segments_uploaded,omitempty"`
	UploadedBytes    *int64     `json:"uploaded_bytes,omitempty"`
	Error            string     `json:"error,omitempty"`
	// Stored is false once retention deleted the backup from the bucket, or when it belongs to an earlier target.
	Stored bool `json:"stored"`

	generation int64
}

// Status summarizes remote backups for the console.
type Status struct {
	Configured  bool       `json:"configured"`
	Enabled     bool       `json:"enabled"`
	Running     bool       `json:"running"`
	LastRun     *Run       `json:"last_run,omitempty"`
	LastSuccess *Run       `json:"last_success,omitempty"`
	NextRunAt   *time.Time `json:"next_run_at,omitempty"`
}

// Deps are the collaborators.
type Deps struct {
	Store   *store.Store
	Keyring *keyring.Keyring
	Audit   *audit.Writer
	Metrics *metrics.Metrics
}

// Options configure the service.
type Options struct {
	// DataDir is the data directory to back up.
	DataDir string
	// AllowInsecureHTTP permits http endpoints (development mode only).
	AllowInsecureHTTP bool
	Clock             clock.Clock
	Logger            *slog.Logger
	// Source overrides how the database is opened for a snapshot (tests).
	Source func(ctx context.Context) (backup.Snapshotter, func(), error)
}

// Service manages the target, runs and retention.
type Service struct {
	d       Deps
	o       Options
	log     *slog.Logger
	running atomic.Bool
	wg      sync.WaitGroup
	bg      context.Context
}

// New returns a service. Call Start to schedule backups.
func New(d Deps, o Options) *Service {
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Source == nil {
		dir := o.DataDir
		o.Source = func(ctx context.Context) (backup.Snapshotter, func(), error) {
			src, err := backup.OpenReadOnly(ctx, dir)
			if err != nil {
				return nil, nil, err
			}
			return src, func() { _ = src.Close() }, nil
		}
	}
	return &Service{d: d, o: o, log: obs.Component(o.Logger, "remotebackup"), bg: context.Background()}
}

func targetFromRow(r db.BackupTarget) *Target {
	iv := time.Duration(r.IntervalSeconds) * time.Second
	return &Target{Enabled: r.Enabled == 1, Endpoint: r.Endpoint, Region: r.Region, Bucket: r.Bucket, Prefix: r.Prefix,
		PathStyle: r.PathStyle == 1, AccessKeyID: r.AccessKeyID, CABundlePEM: r.CaBundlePem, AllowPrivateNetwork: r.AllowPrivateNetwork == 1,
		Interval: iv.String(), KeepLast: r.KeepLast, KeepDailyDays: r.KeepDailyDays, Version: r.Version,
		CreatedAt: time.UnixMicro(r.CreatedAt).UTC(), UpdatedAt: time.UnixMicro(r.UpdatedAt).UTC(),
		generation: r.Generation, secret: r.SecretEnc, interval: iv}
}

func runFromRow(r db.BackupRun, generation int64) *Run {
	out := &Run{ID: r.ID, Trigger: r.Trigger, RequestedBy: r.RequestedBy.String, State: r.State, StartedAt: time.UnixMicro(r.StartedAt).UTC(),
		Error: r.Error.String, Stored: r.RemoteState == "stored" && r.Generation == generation && r.State == runStateSucceeded, generation: r.Generation}
	if r.FinishedAt.Valid {
		v := time.UnixMicro(r.FinishedAt.Int64).UTC()
		out.FinishedAt = &v
	}
	for dst, src := range map[**int64]sql.NullInt64{&out.DBBytes: r.DbBytes, &out.Segments: r.Segments, &out.SegmentsUploaded: r.SegmentsUploaded,
		&out.UploadedBytes: r.UploadedBytes} {
		if src.Valid {
			v := src.Int64
			*dst = &v
		}
	}
	return out
}

func notConfigured() error {
	return apperr.New(apperr.CodeNotFound, "no backup target is configured")
}

// GetTarget returns the target, or a not-found error.
func (svc *Service) GetTarget(ctx context.Context) (*Target, error) {
	r, err := svc.d.Store.R().GetBackupTarget(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notConfigured()
	}
	if err != nil {
		return nil, err
	}
	return targetFromRow(r), nil
}

func invalid(field, msg string) error {
	v := &apperr.Validation{}
	v.Add(field, "%s", msg)
	return v.Err()
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// PutTarget creates the target (Version 0) or updates it (Version must match).
func (svc *Service) PutTarget(ctx context.Context, actor audit.Actor, in TargetInput) (*Target, error) {
	cur, err := svc.GetTarget(ctx)
	exists := err == nil
	if err != nil && apperr.CodeOf(err) != apperr.CodeNotFound {
		return nil, err
	}
	if exists && in.Version == 0 {
		return nil, apperr.New(apperr.CodeConflict, "a backup target exists; send its version to change it")
	}
	if !exists && in.Version != 0 {
		return nil, notConfigured()
	}
	t := &Target{Enabled: true, Region: defaultRegion, Interval: DefaultInterval.String(), KeepLast: DefaultKeepLast, KeepDailyDays: DefaultKeepDaily}
	var secret string
	if exists {
		c := *cur
		t = &c
		if t.secret != nil {
			pt, err := svc.d.Keyring.Open(keyring.PurposeCredential, secretAAD, t.secret)
			if err != nil {
				return nil, fmt.Errorf("open backup secret: %w", err)
			}
			secret = string(pt)
		}
	}
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = strings.TrimSpace(*v)
		}
	}
	set(&t.Endpoint, in.Endpoint)
	set(&t.Region, in.Region)
	set(&t.Bucket, in.Bucket)
	set(&t.Prefix, in.Prefix)
	set(&t.AccessKeyID, in.AccessKeyID)
	set(&t.Interval, in.Interval)
	if in.CABundlePEM != nil {
		t.CABundlePEM = strings.TrimSpace(*in.CABundlePEM)
	}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
	}
	if in.PathStyle != nil {
		t.PathStyle = *in.PathStyle
	}
	if in.AllowPrivateNetwork != nil {
		t.AllowPrivateNetwork = *in.AllowPrivateNetwork
	}
	if in.KeepLast != nil {
		t.KeepLast = *in.KeepLast
	}
	if in.KeepDailyDays != nil {
		t.KeepDailyDays = *in.KeepDailyDays
	}
	secretChanged := false
	if in.SecretAccessKey != nil && *in.SecretAccessKey != "" {
		secret, secretChanged = *in.SecretAccessKey, true
	}
	if t.Region == "" {
		t.Region = defaultRegion
	}
	iv, err := time.ParseDuration(t.Interval)
	switch {
	case err != nil || iv < MinInterval || iv > MaxInterval:
		return nil, invalid("interval", "must be a duration from 15m to 168h")
	case !reRegion.MatchString(t.Region):
		return nil, invalid("region", "must be like eu-central-1 or auto")
	case t.KeepLast < 1 || t.KeepLast > 1000:
		return nil, invalid("keep_last", "must be 1-1000")
	case t.KeepDailyDays < 0 || t.KeepDailyDays > 3650:
		return nil, invalid("keep_daily_days", "must be 0-3650")
	case t.AccessKeyID == "" || len(t.AccessKeyID) > 128:
		return nil, invalid("access_key_id", "is required (at most 128 characters)")
	case secret == "" || len(secret) > 256 || !utf8.ValidString(secret):
		return nil, invalid("secret_access_key", "is required (at most 256 characters)")
	case len(t.CABundlePEM) > maxCABundle:
		return nil, invalid("ca_bundle_pem", "is too large")
	}
	if err := backup.ValidatePrefix(t.Prefix); err != nil {
		return nil, invalid("prefix", err.Error())
	}
	t.interval = iv
	t.Interval = iv.String()
	if _, err := svc.client(t, secret); err != nil {
		return nil, invalid("endpoint", err.Error())
	}
	enc, err := svc.d.Keyring.Seal(keyring.PurposeCredential, secretAAD, []byte(secret))
	if err != nil {
		return nil, err
	}
	gen := int64(1)
	moved := false
	if exists {
		gen = cur.generation
		if cur.Endpoint != t.Endpoint || cur.Bucket != t.Bucket || cur.Prefix != t.Prefix || cur.PathStyle != t.PathStyle {
			gen++
			moved = true
		}
	}
	details := map[string]any{"enabled": t.Enabled, "endpoint": t.Endpoint, "bucket": t.Bucket, "prefix": t.Prefix, "interval": t.Interval,
		"keep_last": t.KeepLast, "keep_daily_days": t.KeepDailyDays, "secret_changed": secretChanged || !exists, "location_changed": moved}
	err = svc.d.Store.W().TxNamed(ctx, "remotebackup.put_target", func(tx *store.Tx) error {
		action := "backup.target_created"
		if exists {
			action = "backup.target_updated"
			n, err := tx.Q.UpdateBackupTarget(ctx, db.UpdateBackupTargetParams{Enabled: b2i(t.Enabled), Endpoint: t.Endpoint, Region: t.Region,
				Bucket: t.Bucket, Prefix: t.Prefix, PathStyle: b2i(t.PathStyle), AccessKeyID: t.AccessKeyID, SecretEnc: enc, CaBundlePem: t.CABundlePEM,
				AllowPrivateNetwork: b2i(t.AllowPrivateNetwork), IntervalSeconds: int64(iv / time.Second), KeepLast: t.KeepLast,
				KeepDailyDays: t.KeepDailyDays, Generation: gen, UpdatedAt: tx.NowMicros(), Version: in.Version})
			if err != nil {
				return err
			}
			if n == 0 {
				return apperr.New(apperr.CodeConflict, "the backup target was modified concurrently; reload and retry")
			}
			if moved {
				if err := tx.Q.DeleteRemoteSegmentsOtherGenerations(ctx, gen); err != nil {
					return err
				}
			}
		} else if err := tx.Q.InsertBackupTarget(ctx, db.InsertBackupTargetParams{Enabled: b2i(t.Enabled), Endpoint: t.Endpoint, Region: t.Region,
			Bucket: t.Bucket, Prefix: t.Prefix, PathStyle: b2i(t.PathStyle), AccessKeyID: t.AccessKeyID, SecretEnc: enc, CaBundlePem: t.CABundlePEM,
			AllowPrivateNetwork: b2i(t.AllowPrivateNetwork), IntervalSeconds: int64(iv / time.Second), KeepLast: t.KeepLast,
			KeepDailyDays: t.KeepDailyDays, Generation: gen, CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := svc.d.Audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, Target: audit.Target{Type: "backup_target", ID: "default"},
			Details: details})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.GetTarget(ctx)
}

// DeleteTarget removes the target. Objects already in the bucket are left there.
func (svc *Service) DeleteTarget(ctx context.Context, actor audit.Actor) error {
	return svc.d.Store.W().TxNamed(ctx, "remotebackup.delete_target", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteBackupTarget(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return notConfigured()
		}
		if err := tx.Q.DeleteRemoteSegmentsOtherGenerations(ctx, -1); err != nil {
			return err
		}
		_, err = svc.d.Audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "backup.target_deleted", Target: audit.Target{Type: "backup_target", ID: "default"}})
		return err
	})
}

func (svc *Service) client(t *Target, secret string) (*s3client.Client, error) {
	return s3client.New(s3client.Config{Endpoint: t.Endpoint, Region: t.Region, Bucket: t.Bucket, PathStyle: t.PathStyle,
		AccessKeyID: t.AccessKeyID, SecretAccessKey: secret, CABundlePEM: t.CABundlePEM, AllowPrivateNetwork: t.AllowPrivateNetwork,
		AllowInsecureHTTP: svc.o.AllowInsecureHTTP, Now: svc.o.Clock.Now})
}

func (svc *Service) openClient(t *Target) (*s3client.Client, error) {
	pt, err := svc.d.Keyring.Open(keyring.PurposeCredential, secretAAD, t.secret)
	if err != nil {
		return nil, fmt.Errorf("open backup secret: %w", err)
	}
	return svc.client(t, string(pt))
}

// TestResult reports a connection test.
type TestResult struct {
	OK      bool   `json:"ok"`
	Backups int    `json:"backups"`
	Error   string `json:"error,omitempty"`
}

// TestTarget lists the bucket and writes and deletes a probe object below the prefix.
func (svc *Service) TestTarget(ctx context.Context) (*TestResult, error) {
	t, err := svc.GetTarget(ctx)
	if err != nil {
		return nil, err
	}
	c, err := svc.openClient(t)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list, err := backup.ListRemote(ctx, c, t.Prefix)
	if err != nil {
		return &TestResult{Error: "list: " + err.Error()}, nil
	}
	probe := t.Prefix + ".hallpass-probe-" + ids.New(ids.Backup)
	if err := c.Put(ctx, probe, strings.NewReader(""), 0, s3client.EmptySHA256); err != nil {
		return &TestResult{Error: "write: " + err.Error()}, nil
	}
	if err := c.Delete(ctx, probe); err != nil {
		return &TestResult{Error: "delete: " + err.Error()}, nil
	}
	return &TestResult{OK: true, Backups: len(list)}, nil
}

// ListRuns returns runs newest first.
func (svc *Service) ListRuns(ctx context.Context, before string, limit int64) ([]*Run, error) {
	gen := svc.generation(ctx)
	rows, err := svc.d.Store.R().ListBackupRuns(ctx, db.ListBackupRunsParams{Before: before, Lim: limit})
	if err != nil {
		return nil, err
	}
	out := make([]*Run, len(rows))
	for i, r := range rows {
		out[i] = runFromRow(r, gen)
	}
	return out, nil
}

// GetRun returns one run.
func (svc *Service) GetRun(ctx context.Context, id string) (*Run, error) {
	r, err := svc.d.Store.R().GetBackupRun(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apperr.New(apperr.CodeNotFound, "backup run not found")
	}
	if err != nil {
		return nil, err
	}
	return runFromRow(r, svc.generation(ctx)), nil
}

func (svc *Service) generation(ctx context.Context) int64 {
	if t, err := svc.GetTarget(ctx); err == nil {
		return t.generation
	}
	return -1
}

// Status reports the target state, the last runs and when the next scheduled run is due.
func (svc *Service) Status(ctx context.Context) (*Status, error) {
	st := &Status{Running: svc.running.Load()}
	t, err := svc.GetTarget(ctx)
	if err != nil && apperr.CodeOf(err) != apperr.CodeNotFound {
		return nil, err
	}
	gen := int64(-1)
	if t != nil {
		st.Configured, st.Enabled, gen = true, t.Enabled, t.generation
	}
	if r, err := svc.d.Store.R().LatestBackupRun(ctx); err == nil {
		st.LastRun = runFromRow(r, gen)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if r, err := svc.d.Store.R().LatestSucceededBackupRun(ctx); err == nil {
		st.LastSuccess = runFromRow(r, gen)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if t != nil && t.Enabled && !st.Running {
		next := svc.nextRun(t, st.LastRun)
		st.NextRunAt = &next
	}
	return st, nil
}

func (svc *Service) nextRun(t *Target, last *Run) time.Time {
	if last == nil || last.generation != t.generation {
		return svc.o.Clock.Now().UTC()
	}
	d := t.interval
	if last.State != runStateSucceeded {
		d = min(d, retryAfterFailure)
	}
	return last.StartedAt.Add(d)
}

// Start marks runs left over from a previous process as interrupted and removes stale staging files. Runs started
// later use ctx; Wait blocks until they have finished. The app calls Tick every minute to start scheduled backups.
func (svc *Service) Start(ctx context.Context) {
	svc.bg = ctx
	if err := svc.d.Store.W().TxNamed(ctx, "remotebackup.interrupt_stale", func(tx *store.Tx) error {
		_, err := tx.Q.InterruptRunningBackups(ctx, sql.NullInt64{Int64: tx.NowMicros(), Valid: true})
		return err
	}); err != nil {
		svc.log.Error("marking interrupted backup runs failed", obs.Err(err))
	}
	_ = os.RemoveAll(svc.stagingDir())
	if r, err := svc.d.Store.R().LatestSucceededBackupRun(ctx); err == nil {
		svc.d.Metrics.SetBackupLastSuccess(time.UnixMicro(r.StartedAt))
	}
}

// Wait blocks until running backups have stopped.
func (svc *Service) Wait() { svc.wg.Wait() }

// Tick starts a scheduled backup when the target is enabled and one is due.
func (svc *Service) Tick(ctx context.Context) error {
	t, err := svc.GetTarget(ctx)
	if err != nil || !t.Enabled || svc.running.Load() {
		return nil //nolint:nilerr // no target configured: nothing to do
	}
	var last *Run
	if r, err := svc.d.Store.R().LatestBackupRun(ctx); err == nil {
		last = runFromRow(r, t.generation)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if svc.o.Clock.Now().Before(svc.nextRun(t, last)) {
		return nil
	}
	if _, err := svc.start(ctx, "schedule", nil); err != nil && !errors.Is(err, ErrRunning) {
		return err
	}
	return nil
}

// RunNow starts a backup in the background and returns its run.
func (svc *Service) RunNow(ctx context.Context, actor audit.Actor) (*Run, error) {
	return svc.start(ctx, "manual", &actor)
}

func (svc *Service) stagingDir() string {
	return filepath.Join(svc.o.DataDir, store.BackupsDir, stagingDirName)
}

// start records the run and runs it in the background. The run row is committed before anything is uploaded.
func (svc *Service) start(ctx context.Context, trigger string, actor *audit.Actor) (*Run, error) {
	t, err := svc.GetTarget(ctx)
	if err != nil {
		return nil, err
	}
	if !svc.running.CompareAndSwap(false, true) {
		return nil, ErrRunning
	}
	id := ids.New(ids.Backup)
	requestedBy := sql.NullString{}
	if actor != nil {
		requestedBy = sql.NullString{String: actor.ID, Valid: true}
	}
	err = svc.d.Store.W().TxNamed(ctx, "remotebackup.start_run", func(tx *store.Tx) error {
		if err := tx.Q.InsertBackupRun(ctx, db.InsertBackupRunParams{ID: id, Generation: t.generation, Trigger: trigger, RequestedBy: requestedBy,
			StartedAt: tx.NowMicros()}); err != nil {
			return err
		}
		if actor == nil {
			return nil
		}
		_, err := svc.d.Audit.Append(ctx, tx, audit.Event{Actor: *actor, Action: "backup.run_requested", Target: audit.Target{Type: "backup_run", ID: id}})
		return err
	})
	if err != nil {
		svc.running.Store(false)
		return nil, err
	}
	run, err := svc.GetRun(ctx, id)
	if err != nil {
		svc.running.Store(false)
		return nil, err
	}
	svc.wg.Add(1)
	go func() {
		defer svc.wg.Done()
		defer svc.running.Store(false)
		svc.execute(svc.bg, t, run)
	}()
	return run, nil
}

func (svc *Service) execute(ctx context.Context, t *Target, run *Run) {
	log := svc.log.With(slog.String("backup_id", run.ID))
	began := svc.o.Clock.Now()
	res, err := svc.upload(ctx, t, run)
	state, msg := runStateSucceeded, ""
	if err != nil {
		state, msg = runStateFailed, err.Error()
	} else if len(res.Problems) > 0 {
		msg = fmt.Sprintf("%d segment file(s) did not match the database: %s", len(res.Problems), strings.Join(res.Problems, "; "))
	}
	if len(msg) > maxErrorLen {
		msg = msg[:maxErrorLen]
	}
	fin := db.FinishBackupRunParams{ID: run.ID, State: state, Error: sql.NullString{String: msg, Valid: msg != ""}}
	if res != nil {
		uploaded := int64(0)
		for _, s := range res.Segments {
			if s.Uploaded {
				uploaded++
			}
		}
		fin.DbBytes = sql.NullInt64{Int64: res.DBBytes, Valid: true}
		fin.Segments = sql.NullInt64{Int64: int64(len(res.Segments)), Valid: true}
		fin.SegmentsUploaded = sql.NullInt64{Int64: uploaded, Valid: true}
		fin.UploadedBytes = sql.NullInt64{Int64: res.UploadedBytes, Valid: true}
	}
	ctx = context.WithoutCancel(ctx)
	if err := svc.d.Store.W().TxNamed(ctx, "remotebackup.finish_run", func(tx *store.Tx) error {
		fin.FinishedAt = sql.NullInt64{Int64: tx.NowMicros(), Valid: true}
		if err := tx.Q.FinishBackupRun(ctx, fin); err != nil {
			return err
		}
		if state == runStateSucceeded {
			return nil
		}
		_, err := svc.d.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorSystem, ID: "remotebackup"}, Action: "backup.run_failed",
			Target: audit.Target{Type: "backup_run", ID: run.ID}, Details: map[string]any{"error": msg}})
		return err
	}); err != nil {
		log.Error("recording the backup result failed", obs.Err(err))
	}
	svc.d.Metrics.BackupRun(state, svc.o.Clock.Now().Sub(began))
	if state != runStateSucceeded {
		log.Error("remote backup failed", slog.String("error", msg))
		return
	}
	svc.d.Metrics.SetBackupLastSuccess(run.StartedAt)
	log.Info("remote backup finished", slog.Int64("uploaded_bytes", res.UploadedBytes), slog.Int("segments", len(res.Segments)))
	if err := svc.retain(ctx, t, run); err != nil {
		log.Error("backup retention failed", obs.Err(err))
	}
}

// upload runs CreateRemote and records which segment versions the bucket now holds.
func (svc *Service) upload(ctx context.Context, t *Target, run *Run) (*backup.RemoteResult, error) {
	c, err := svc.openClient(t)
	if err != nil {
		return nil, err
	}
	src, closeSrc, err := svc.o.Source(ctx)
	if err != nil {
		return nil, err
	}
	defer closeSrc()
	rows, err := svc.d.Store.R().ListRemoteSegments(ctx, t.generation)
	if err != nil {
		return nil, err
	}
	stored := make(map[string]string, len(rows))
	for _, r := range rows {
		stored[r.SegmentID] = r.KeyID
	}
	stage := svc.stagingDir()
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return nil, err
	}
	res, err := backup.CreateRemote(ctx, src, svc.d.Keyring.Wrapper(), c, backup.RemoteOptions{Prefix: t.Prefix, BackupID: run.ID, StageDir: stage,
		Clock: svc.o.Clock, Stored: func(seg, key string) bool { k, ok := stored[seg]; return ok && k == key }})
	if err != nil {
		return res, err
	}
	seen := make(map[string]bool, len(res.Segments))
	seenAt := run.StartedAt.UnixMicro()
	for i := 0; i < len(res.Segments); i += bookkeepingBatch {
		batch := res.Segments[i:min(i+bookkeepingBatch, len(res.Segments))]
		if err := svc.d.Store.W().TxNamed(ctx, "remotebackup.record_segments", func(tx *store.Tx) error {
			for _, s := range batch {
				if err := tx.Q.UpsertRemoteSegment(ctx, db.UpsertRemoteSegmentParams{SegmentID: s.SegmentID, Generation: t.generation, Object: s.Object,
					KeyID: s.KeyID, Size: s.Size, SeenAt: seenAt}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return res, err
		}
		for _, s := range batch {
			seen[s.SegmentID] = true
		}
	}
	var gone []string
	for _, r := range rows {
		if !seen[r.SegmentID] && !r.GoneAt.Valid {
			gone = append(gone, r.SegmentID)
		}
	}
	for i := 0; i < len(gone); i += bookkeepingBatch {
		batch := gone[i:min(i+bookkeepingBatch, len(gone))]
		if err := svc.d.Store.W().TxNamed(ctx, "remotebackup.mark_gone", func(tx *store.Tx) error {
			for _, id := range batch {
				if err := tx.Q.MarkRemoteSegmentGone(ctx, db.MarkRemoteSegmentGoneParams{GoneAt: sql.NullInt64{Int64: seenAt, Valid: true}, SegmentID: id}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return res, err
		}
	}
	return res, nil
}

// retain keeps the newest KeepLast successful backups and the newest one of each of the last KeepDailyDays days,
// deletes every other backup of the current target (and leftovers of failed runs), then deletes segment objects
// that no kept backup references. A segment is referenced by a backup taken while it was present: between the first
// backup that included it and the first that no longer did.
func (svc *Service) retain(ctx context.Context, t *Target, latest *Run) error {
	c, err := svc.openClient(t)
	if err != nil {
		return err
	}
	rows, err := svc.d.Store.R().StoredBackupRuns(ctx, t.generation)
	if err != nil {
		return err
	}
	keep := map[string]bool{latest.ID: true}
	cutoff := svc.o.Clock.Now().UTC().AddDate(0, 0, -int(t.KeepDailyDays))
	days := map[string]bool{}
	n := int64(0)
	for _, r := range rows {
		if r.State != runStateSucceeded {
			continue
		}
		started := time.UnixMicro(r.StartedAt).UTC()
		if n < t.KeepLast {
			keep[r.ID] = true
		}
		n++
		if day := started.Format(time.DateOnly); t.KeepDailyDays > 0 && !started.Before(cutoff) && !days[day] {
			days[day] = true
			keep[r.ID] = true
		}
	}
	var kept []int64
	for _, r := range rows {
		if keep[r.ID] {
			kept = append(kept, r.StartedAt)
			continue
		}
		if err := backup.DeleteRemote(ctx, c, t.Prefix, r.ID); err != nil {
			return fmt.Errorf("delete backup %s: %w", r.ID, err)
		}
		if err := svc.d.Store.W().TxNamed(ctx, "remotebackup.mark_deleted", func(tx *store.Tx) error {
			return tx.Q.MarkBackupRunDeleted(ctx, r.ID)
		}); err != nil {
			return err
		}
	}
	segs, err := svc.d.Store.R().ListRemoteSegments(ctx, t.generation)
	if err != nil {
		return err
	}
	for _, s := range segs {
		if !s.GoneAt.Valid {
			continue
		}
		referenced := false
		for _, at := range kept {
			if at >= s.FirstSeenAt && at < s.GoneAt.Int64 {
				referenced = true
				break
			}
		}
		if referenced {
			continue
		}
		if err := c.Delete(ctx, t.Prefix+s.Object); err != nil {
			return fmt.Errorf("delete segment object %s: %w", s.Object, err)
		}
		if err := svc.d.Store.W().TxNamed(ctx, "remotebackup.forget_segment", func(tx *store.Tx) error {
			return tx.Q.DeleteRemoteSegment(ctx, s.SegmentID)
		}); err != nil {
			return err
		}
	}
	return nil
}
