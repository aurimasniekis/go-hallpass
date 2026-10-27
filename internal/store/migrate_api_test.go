package store

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// embeddedUpTo returns the embedded migrations with versions up to and including last.
func embeddedUpTo(t *testing.T, last string) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	err := fs.WalkDir(EmbeddedMigrations(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p[:4] > last {
			return err
		}
		b, err := fs.ReadFile(EmbeddedMigrations(), p)
		out[p] = &fstest.MapFile{Data: b}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Migration 0032 rebuilds servers to allow kind 'api': rows and every reference to them survive, and foreign keys
// are on again afterwards.
func TestMigrationAPITargetsKeepsServers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	ctx := context.Background()
	s, err := Open(ctx, Options{DataDir: dir, migrations: embeddedUpTo(t, "0031")})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO servers (id, alias, display_name, address, port, enabled, created_at, created_by, updated_at, updated_by, kind)
		 VALUES ('srv_1', 'web1', 'Web 1', '10.0.0.1', 22, 1, 1, 'x', 1, 'x', 'git')`,
		`INSERT INTO groups (id, kind, name, created_at, updated_at) VALUES ('grp_1', 'server', 'prod', 1, 1)`,
		`INSERT INTO server_groups (server_id, group_id) VALUES ('srv_1', 'grp_1')`,
	} {
		if _, err := s.wdb.ExecContext(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	_ = s.Close()

	s = openTest(t, Options{DataDir: dir})
	var kind string
	var groups, fkErrors, fkOn int
	if err := s.rdb.QueryRowContext(ctx, "SELECT kind FROM servers WHERE id = 'srv_1'").Scan(&kind); err != nil || kind != "git" {
		t.Fatalf("server row: %q %v", kind, err)
	}
	if err := s.rdb.QueryRowContext(ctx, "SELECT count(*) FROM server_groups WHERE server_id = 'srv_1'").Scan(&groups); err != nil || groups != 1 {
		t.Fatalf("server_groups: %d %v", groups, err)
	}
	if err := s.wdb.QueryRowContext(ctx, "SELECT count(*) FROM pragma_foreign_key_check").Scan(&fkErrors); err != nil || fkErrors != 0 {
		t.Fatalf("foreign key check: %d %v", fkErrors, err)
	}
	if err := s.wdb.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fkOn); err != nil || fkOn != 1 {
		t.Fatalf("foreign_keys after migration: %d %v", fkOn, err)
	}
	if _, err := s.wdb.ExecContext(ctx, `INSERT INTO servers (id, alias, display_name, address, port, enabled, created_at,
		created_by, updated_at, updated_by, kind) VALUES ('srv_2', 'gh', 'GitHub', 'api.github.com', 443, 1, 1, 'x', 1, 'x', 'api')`); err != nil {
		t.Fatalf("kind api refused: %v", err)
	}
	if _, err := s.wdb.ExecContext(ctx, "INSERT INTO server_groups (server_id, group_id) VALUES ('srv_missing', 'grp_1')"); err == nil {
		t.Fatal("a reference to a missing server was stored: foreign keys are not enforced")
	}
}
