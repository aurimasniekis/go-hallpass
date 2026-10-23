package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
)

const input = `Oct 23 12:00:00 web1 sshd[2001]: Accepted publickey for ro from 203.0.113.10 port 51234 ssh2: ED25519-CERT SHA256:eph ID hallpass:rol_1:grt_2:con_3 (serial 991) CA ED25519 SHA256:ca
type=LOGIN msg=audit(1792756800.100:500): pid=2001 uid=0 auid=1001 ses=7 res=1
type=SYSCALL msg=audit(1792756801.200:510): syscall=59 success=yes ppid=2005 pid=2010 auid=1001 uid=1001 ses=7 exe="/usr/bin/cat"
type=EXECVE msg=audit(1792756801.200:510): argc=2 a0="cat" a1="/etc/hostname"
type=EOE msg=audit(1792756801.200:510):`

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestDryRunFromStdinAndFiles(t *testing.T) {
	code, out, stderr := runCLI(t, input, "run", "-dry-run")
	if code != 0 {
		t.Fatalf("%d %s", code, stderr)
	}
	var r wire.Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &r); err != nil {
		t.Fatalf("%v: %q", err, out)
	}
	if r.Login.CertKeyID != "hallpass:rol_1:grt_2:con_3" || r.Argv[1] != "/etc/hostname" || !strings.Contains(stderr, "shipped=1") {
		t.Fatalf("%+v %s", r, stderr)
	}
	// Split across two files (auth log, then audit log).
	dir := t.TempDir()
	lines := strings.Split(input, "\n")
	auth, audit := filepath.Join(dir, "auth.log"), filepath.Join(dir, "audit.log")
	must(t, os.WriteFile(auth, []byte(lines[0]), 0o600))
	must(t, os.WriteFile(audit, []byte(strings.Join(lines[1:], "\n")), 0o600))
	code, out, stderr = runCLI(t, "", "run", "-dry-run", auth, audit)
	if code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("%d %q %s", code, out, stderr)
	}
	if code, _, _ := runCLI(t, "", "run", "-dry-run", filepath.Join(dir, "missing")); code != 1 {
		t.Fatal("missing file accepted")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeygenPubkey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	code, out, stderr := runCLI(t, "", "keygen", "-key", p, "-comment", "c@h")
	if code != 0 || !strings.HasPrefix(out, "ssh-ed25519 ") {
		t.Fatalf("%d %q %s", code, out, stderr)
	}
	code, out2, _ := runCLI(t, "", "pubkey", "-key", p)
	if code != 0 || !strings.HasPrefix(out, strings.TrimSpace(out2)) {
		t.Fatalf("%q vs %q", out, out2)
	}
	if code, _, _ := runCLI(t, "", "keygen", "-key", p); code != 1 {
		t.Fatal("overwrote key")
	}
	if code, _, _ := runCLI(t, "", "keygen"); code != 1 {
		t.Fatal("missing -key accepted")
	}
}

func TestRunFlagValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if code, _, _ := runCLI(t, "", "keygen", "-key", p); code != 0 {
		t.Fatal("keygen")
	}
	for _, args := range [][]string{
		{"run"},
		{"run", "-url", "http://hallpass.example", "-collector-id", "dac_x", "-key", p},
		{"run", "-url", "ftp://hallpass.example", "-collector-id", "dac_x", "-key", p},
		{"run", "-url", "https://hallpass.example", "-collector-id", "../x", "-key", p},
		{"run", "-url", "https://hallpass.example", "-collector-id", "dac_x", "-key", p, "-ca-file", p + ".missing"},
	} {
		if code, _, _ := runCLI(t, "", args...); code != 1 {
			t.Errorf("%v accepted", args)
		}
	}
	if code, _, _ := runCLI(t, ""); code != 2 {
		t.Fatal("no command")
	}
	if code, _, _ := runCLI(t, "", "bogus"); code != 2 {
		t.Fatal("bogus command")
	}
	if code, out, _ := runCLI(t, "", "version"); code != 0 || !strings.HasPrefix(out, "hallpass-collector ") {
		t.Fatal("version")
	}
}

func TestIngestURL(t *testing.T) {
	u, err := ingestURL("https://hallpass.example.com/base/", "dac_abc", false)
	if err != nil || u != "https://hallpass.example.com/base/hooks/destaudit/dac_abc" {
		t.Fatalf("%q %v", u, err)
	}
	if _, err := ingestURL("http://127.0.0.1:8080", "dac_abc", true); err != nil {
		t.Fatal(err)
	}
}
