package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/remotebackup"
	"github.com/aurimasniekis/go-hallpass/internal/s3client/s3test"
)

// ADR-0054: a backup the server stored in object storage is listed and downloaded on another host with only the
// bucket details, the access key from the environment and the KEK, then verifies and restores like a local backup.
func TestRemoteBackupCommands(t *testing.T) {
	e := newOpsEnv(t)
	e.seed()
	srv := s3test.New(t, "AKIDTEST")
	ca := filepath.Join(e.dir, "ca.pem")
	if err := os.WriteFile(ca, []byte(srv.CAPEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := openApp(context.Background(), e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ptr := func(s string) *string { return &s }
	yes := true
	actor := audit.Actor{Type: audit.ActorOperator, ID: "opr_test"}
	if _, err := a.RemoteBackup.PutTarget(context.Background(), actor, remotebackup.TargetInput{Endpoint: ptr(srv.URL), Bucket: ptr("hp-backups"),
		Prefix: ptr("hp/"), PathStyle: &yes, AccessKeyID: ptr("AKIDTEST"), SecretAccessKey: ptr("secret"), CABundlePEM: ptr(srv.CAPEM()),
		AllowPrivateNetwork: &yes}); err != nil {
		t.Fatal(err)
	}
	run, err := a.RemoteBackup.RunNow(context.Background(), actor)
	if err != nil {
		t.Fatal(err)
	}
	a.RemoteBackup.Wait()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	flags := []string{"--s3-endpoint", srv.URL, "--s3-bucket", "hp-backups", "--s3-prefix", "hp/", "--s3-path-style", "--s3-ca-file", ca,
		"--s3-allow-private-network"}
	if _, _, code, err := call(t, runBackupRemoteList, flags...); code != 1 || !strings.Contains(err.Error(), "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("list without credentials: %d %v", code, err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	stdout, _, code, err := call(t, runBackupRemoteList, flags...)
	if code != 0 || !strings.Contains(stdout, run.ID) || !strings.Contains(stdout, "complete") {
		t.Fatalf("list: %d %v %q", code, err, stdout)
	}
	out := filepath.Join(e.dir, "dl")
	stdout, _, code, err = call(t, runBackupRemoteDownload, append([]string{"--config", e.cfgPath, "--out", out}, flags...)...)
	if code != 0 || !strings.Contains(stdout, "downloaded backup "+run.ID) {
		t.Fatalf("download: %d %v %q", code, err, stdout)
	}
	if stdout, _, code, _ := call(t, runBackupVerify, out); code != 0 || !strings.Contains(stdout, "backup: ok") {
		t.Fatalf("verify: %d %q", code, stdout)
	}
	target := filepath.Join(e.dir, "restored")
	if stdout, _, code, err := call(t, runRestore, "--config", e.cfgPath, "--data", target, out); code != 0 || !strings.Contains(stdout, "unlocks the keyring") {
		t.Fatalf("restore: %d %v %q", code, err, stdout)
	}
}
