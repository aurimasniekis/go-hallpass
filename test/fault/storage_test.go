//go:build fault

package fault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/agents"
	"github.com/aurimasniekis/go-hallpass/internal/app"
	"github.com/aurimasniekis/go-hallpass/internal/clock"
	"github.com/aurimasniekis/go-hallpass/internal/config"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/obs/health"
	"github.com/aurimasniekis/go-hallpass/internal/store"
)

// FI-06: SQLITE_FULL (the database cannot grow; injected with PRAGMA max_page_count on the writer connection). New
// requests and channels are refused, readiness degrades, an established channel keeps working, and the gateway
// recovers once space is available (HP-DB-009).
func TestFI06SQLiteFull(t *testing.T) {
	w := newWorld(t)
	g := w.start(t, withRoles(1))
	ctx := context.Background()
	w.dest.Exec = func(_ string, stdin io.Reader, stdout, _ io.Writer) uint32 {
		_, _ = io.Copy(stdout, stdin) // echo
		return 0
	}
	le := startExec(t, g.addr, w, "exec web1 --role inspect -- cat")
	_, _ = le.stdin.Write([]byte("before\n"))
	if !eventually(5*time.Second, func() bool { return strings.Contains(le.stdout.String(), "before") }) {
		t.Fatal("echo session not working")
	}

	pages := queryInt(t, g.a.Store.ReadDB(), `PRAGMA page_count`)
	must(t, g.a.Store.W().Exec(ctx, fmt.Sprintf("PRAGMA max_page_count = %d", pages)))
	t.Cleanup(func() { _ = g.a.Store.W().Exec(ctx, "PRAGMA max_page_count = 1073741823") })
	full := false
	for i := range 20000 {
		_, err := g.a.Agents.Create(ctx, admin, agents.CreateInput{Name: fmt.Sprintf("filler-%05d", i), Description: strings.Repeat("x", 400)})
		if errors.Is(err, store.ErrFull) {
			full = true
			t.Logf("database full after %d inserts", i)
			break
		}
		must(t, err)
	}
	if !full {
		t.Fatal("could not fill the database")
	}
	if st := g.a.Store.Health().Status(); st.State != store.HealthDegraded {
		t.Fatalf("store health %+v, want degraded", st)
	}
	logins := len(w.dest.Logins())
	refused := func(stage string) {
		t.Helper()
		if _, _, code := g.run("exec web1 --role inspect -- id"); code == 0 {
			t.Errorf("%s: new channel opened while the database is full", stage)
		}
		if _, _, code := g.run("request web1 --role role0 --reason 'disk full' --no-wait --json"); code == 0 {
			t.Errorf("%s: new request accepted while the database is full", stage)
		}
		if len(w.dest.Logins()) != logins {
			t.Errorf("%s: destination dialed while the database is full", stage)
		}
	}
	refused("immediately")
	rep := g.a.Health.Refresh(ctx)
	st := g.a.Store.Health().Status()
	t.Logf("readiness %s; store health after the readiness probe: %+v", rep.Status, st)
	if rep.Status == health.StatusReady || st.State == store.HealthOK {
		t.Errorf("FINDING: the database is still full but the readiness probe's no-op write transaction succeeded and reset "+
			"storage health to %q (readiness %s); any small successful write clears the disk-full state (HP-DB-009)", st.State, rep.Status)
	}
	refused("after the readiness probe")
	_, _ = le.stdin.Write([]byte("during\n"))
	if !eventually(5*time.Second, func() bool { return strings.Contains(le.stdout.String(), "during") }) {
		t.Error("established channel stopped working while the database is full")
	}

	must(t, g.a.Store.W().Exec(ctx, "PRAGMA max_page_count = 1073741823"))
	if _, _, code := g.run("exec web1 --role inspect -- id"); code != 0 {
		t.Fatalf("no recovery after space returned: exit %d", code)
	}
	if st := g.a.Store.Health().Status(); st.State != store.HealthOK {
		t.Fatalf("store health %+v after recovery", st)
	}
}

// FI-09: writer contention. Another connection holds the write lock: transactions fail with storage_busy after
// bounded retries, readiness degrades only after BusyDegradeAfter of continuous contention, and everything
// recovers when the lock is released. A long reader does not block writes (WAL) and only delays the checkpoint.
func TestFI09WriterContention(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Now())
	s, err := store.Open(ctx, store.Options{DataDir: filepath.Join(t.TempDir(), "data"), BusyTimeout: 100 * time.Millisecond, Clock: clk})
	must(t, err)
	t.Cleanup(func() { _ = s.Close() })
	put := func(k string) error {
		return s.W().Tx(ctx, func(tx *store.Tx) error {
			_, err := tx.SQL.ExecContext(ctx, `INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, 'v', ?)`, k, tx.NowMicros())
			return err
		})
	}
	must(t, put("warmup"))

	release := holdWriteLock(t, s.Path(store.DBFile))
	start := time.Now()
	err = put("contended")
	elapsed := time.Since(start)
	t.Logf("busy transaction gave up after %s: %v", elapsed.Round(time.Millisecond), err)
	if !errors.Is(err, store.ErrBusy) {
		t.Fatalf("got %v, want storage busy", err)
	}
	// 5 attempts × 100 ms busy timeout plus jittered backoff (≤ 10+20+40+80 ms).
	if elapsed < 400*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("retry budget not bounded as specified: %s", elapsed)
	}
	if st := s.Health().Status(); st.State != store.HealthOK {
		t.Fatalf("health degraded before %s of contention: %+v", store.BusyDegradeAfter, st)
	}
	clk.Advance(store.BusyDegradeAfter + time.Second)
	_ = put("still contended")
	if s.Health().AcceptsWrites() {
		t.Fatalf("health still accepts writes after sustained contention: %+v", s.Health().Status())
	}
	release()
	must(t, put("released"))
	if !s.Health().AcceptsWrites() {
		t.Fatalf("no recovery after contention ended: %+v", s.Health().Status())
	}

	// Long reader: an open read transaction pins the WAL; writes continue and the checkpoint cannot truncate.
	rtx, err := s.ReadDB().BeginTx(ctx, nil)
	must(t, err)
	var n int
	must(t, rtx.QueryRowContext(ctx, `SELECT count(*) FROM settings`).Scan(&n))
	for i := range 200 {
		must(t, put(fmt.Sprintf("k%d", i)))
	}
	ckStart := time.Now()
	ckErr := s.Checkpoint(ctx, "TRUNCATE")
	_, walPinned := s.Sizes()
	t.Logf("checkpoint with a pinned reader: %s, err=%v, wal=%d B", time.Since(ckStart).Round(time.Millisecond), ckErr, walPinned)
	if time.Since(ckStart) > 2*time.Second {
		t.Fatal("checkpoint blocked unboundedly behind a reader")
	}
	must(t, rtx.Rollback())
	must(t, s.Checkpoint(ctx, "TRUNCATE"))
	if _, wal := s.Sizes(); wal != 0 || walPinned == 0 {
		t.Fatalf("WAL %d B after the reader ended (pinned %d B)", wal, walPinned)
	}
}

// FI-09 at the gateway: a short external write lock (under the busy timeout) is absorbed; the exec succeeds.
func TestFI09GatewayAbsorbsShortContention(t *testing.T) {
	w := newWorld(t)
	g := w.start(t)
	release := holdWriteLock(t, g.a.Store.Path(store.DBFile))
	go func() {
		time.Sleep(1500 * time.Millisecond)
		release()
	}()
	start := time.Now()
	if _, errOut, code := g.run("exec web1 -- id"); code != 0 {
		t.Fatalf("exit %d (%q) under a 1.5 s write lock", code, errOut)
	}
	t.Logf("exec completed %s after the lock was taken", time.Since(start).Round(time.Millisecond))
}

// FI-10: a corrupted database makes startup refuse with the corruption class and restore guidance (HP-DB-008):
// structural damage found when the database is opened, and damage only PRAGMA quick_check finds.
func TestFI10CorruptDatabaseRefusesStart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pages func(n int64) []int64
	}{
		{"every_other_page", func(n int64) []int64 {
			var out []int64
			for p := int64(1); p < n; p += 2 { // leave page 1 (header and schema root) intact
				out = append(out, p)
			}
			return out
		}},
		{"last_pages", func(n int64) []int64 { return []int64{n - 1, n - 2, n - 3} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.setup(t, 0)
			path := filepath.Join(w.dir, store.DBFile)
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			must(t, err)
			fi, err := f.Stat()
			must(t, err)
			const page = 4096
			for _, p := range tc.pages(fi.Size() / page) {
				_, err := f.WriteAt([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, p*page)
				must(t, err)
			}
			must(t, f.Close())
			_, err = app.New(context.Background(), baseConfig(w.dir), logger())
			if err == nil {
				t.Fatal("gateway started on a corrupted database")
			}
			t.Logf("startup refused: %v", err)
			if !errors.Is(err, store.ErrCorrupt) {
				t.Fatalf("refusal without the corruption class: %v", err)
			}
			if !strings.Contains(err.Error(), "restore") {
				t.Errorf("FINDING: corruption refusal carries no restore guidance (HP-DB-008): %v", err)
			}
		})
	}
}

// FI-14: a missing KEK stops a production start; a wrong KEK is detected (keyring canary) before anything is served.
func TestFI14KEKMissingOrWrong(t *testing.T) {
	ctx := context.Background()
	keys := t.TempDir()
	writeKEK := func(name string) string {
		k, err := keyring.GenerateKEK()
		must(t, err)
		p := filepath.Join(keys, name)
		must(t, keyring.WriteKEKFile(p, k))
		return p
	}
	prod := func(dir, kek string) *config.Config {
		cfg := baseConfig(dir)
		cfg.Mode, cfg.KEK.File = config.ModeProduction, kek
		return cfg
	}
	for name, kek := range map[string]string{"unset": "", "absent": filepath.Join(keys, "nope")} {
		if _, err := app.New(ctx, prod(filepath.Join(t.TempDir(), "data"), kek), logger()); !errors.Is(err, keyring.ErrNoKEK) {
			t.Errorf("production start with %s KEK: %v, want ErrNoKEK", name, err)
		}
	}
	dir := filepath.Join(t.TempDir(), "data")
	a, err := app.New(ctx, prod(dir, writeKEK("a")), logger())
	must(t, err)
	must(t, a.Close())
	if _, err := app.New(ctx, prod(dir, writeKEK("b")), logger()); !errors.Is(err, keyring.ErrWrongKEK) {
		t.Errorf("start with the wrong KEK: %v, want ErrWrongKEK", err)
	}
	loose := filepath.Join(keys, "loose")
	k, err := keyring.GenerateKEK()
	must(t, err)
	must(t, os.WriteFile(loose, keyring.EncodeKEK(k), 0o600))
	must(t, os.Chmod(loose, 0o644)) // explicit: app.New sets a 077 umask
	if _, err := app.New(ctx, prod(dir, loose), logger()); !errors.Is(err, keyring.ErrBadKEKFile) {
		t.Errorf("start with a group/world-readable KEK file: %v, want ErrBadKEKFile", err)
	}
	// The development KEK lives inside the data directory; production configuration rejects that location.
	cfg := prod("/var/lib/hallpass", "/var/lib/hallpass/"+keyring.DevKEKFile)
	cfg.PublicURL, cfg.HTTP.Listen = "https://hallpass.example", ":8080"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "kek.file") {
		t.Errorf("production config with the KEK inside data_dir validated: %v", err)
	}
}

// FI-22: a second gateway on the same data directory fails fast on the lock, in-process and from another process,
// and the first gateway keeps serving (HP-DB-006).
func TestFI22SecondProcessSameDataDir(t *testing.T) {
	w := newWorld(t)
	g := w.start(t)
	start := time.Now()
	if _, err := app.New(context.Background(), baseConfig(w.dir), logger()); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("second in-process gateway: %v, want ErrLocked", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("lock refusal took %s", d)
	}
	if _, _, code := g.run("exec web1 -- id"); code != 0 {
		t.Fatalf("first gateway affected: exit %d", code)
	}
	g.stop()

	c := w.spawn(t, "")
	if _, err := app.New(context.Background(), baseConfig(w.dir), logger()); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("gateway while another process owns the directory: %v, want ErrLocked", err)
	}
	if _, _, code := run(t, c.addr, w, "exec web1 -- id"); code != 0 {
		t.Fatalf("owning process affected: exit %d", code)
	}
}
