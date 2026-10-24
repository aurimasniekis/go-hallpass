//go:build openssh

package openssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/inventory"
)

// transfer runs the system scp or sftp client against the gateway with strict host-key checking.
func (g *Gateway) transfer(stdin, tool string, args ...string) (string, int) {
	g.t.Helper()
	all := []string{"-F", "/dev/null", "-i", g.keyFile, "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + g.knownHosts,
		"-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-P", fmt.Sprint(g.port)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, append(all, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok { //nolint:errorlint // exec returns *ExitError directly
		code = ee.ExitCode()
	} else if err != nil {
		g.t.Fatalf("%s %v: %v", tool, args, err)
	}
	return out.String(), code
}

// scp and sftp through the gateway against a real OpenSSH destination: the SSH user names the server (and optionally
// the role), only roles with the file-transfer capability qualify, and every file operation is recorded with its
// size and digest while the bytes themselves are not stored.
func TestOpenSSHFileTransfer(t *testing.T) {
	if _, err := exec.LookPath("scp"); err != nil {
		t.Skip("scp not available")
	}
	g := startGateway(t)
	ctx := context.Background()
	role, err := g.A.Inventory.CreateRole(ctx, admin, g.Server.ID, inventory.RoleInput{Alias: ptr("files"), RemoteUser: ptr("deploy"),
		Capabilities: ptr([]string{inventory.CapFileTransfer})})
	must(t, err)
	cred, err := g.A.Credentials.Generate(ctx, admin, role.ID)
	must(t, err)
	g.Dest.Authorize("deploy", strings.Replace(cred.AuthorizedKeysLine, `from="`, `from="*,`, 1))
	_, err = g.A.Credentials.Probe(ctx, admin, cred.ID)
	must(t, err)
	_, err = g.A.Credentials.Activate(ctx, admin, cred.ID, false)
	must(t, err)

	dir := t.TempDir()
	payload := make([]byte, 3<<20)
	_, _ = rand.Read(payload)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	src := filepath.Join(dir, "build.tar")
	must(t, os.WriteFile(src, payload, 0o600))

	// Upload with scp (SFTP protocol), the role chosen by capability.
	if out, code := g.transfer("", "scp", src, "web1@127.0.0.1:/tmp/build.tar"); code != 0 {
		t.Fatalf("scp upload: %d %s", code, out)
	}
	if got := g.Dest.Exec("sha256sum /tmp/build.tar | cut -d' ' -f1; stat -c %U /tmp/build.tar"); got != digest+"\ndeploy" {
		t.Fatalf("uploaded file: %q", got)
	}
	// Download with the role named explicitly.
	back := filepath.Join(dir, "back.tar")
	if out, code := g.transfer("", "scp", "web1+files@127.0.0.1:/tmp/build.tar", back); code != 0 {
		t.Fatalf("scp download: %d %s", code, out)
	}
	if b, err := os.ReadFile(back); err != nil || !bytes.Equal(b, payload) {
		t.Fatalf("downloaded file differs (%v)", err)
	}
	// An interactive sftp batch: directory, rename, removal and a refused operation.
	out, code := g.transfer("mkdir /tmp/drop\nrename /tmp/build.tar /tmp/drop/b.tar\nls /tmp/drop\n-rm /etc/passwd\nrm /tmp/drop/b.tar\n",
		"sftp", "-b", "-", "web1@127.0.0.1")
	if code != 0 || !strings.Contains(out, "b.tar") {
		t.Fatalf("sftp batch: %d %s", code, out)
	}

	// Refusals: a role without the capability, an unknown server, a user name that is not a server.
	for user, want := range map[string]string{
		"web1+inspect": "no role you can use on web1 allows file transfer",
		"nosuch":       "not found or not permitted",
		"agent":        "not found or not permitted",
		"web_1":        "file transfer: connect as",
	} {
		out, code := g.transfer("", "scp", src, user+"@127.0.0.1:/tmp/x")
		if code == 0 || !strings.Contains(out, want) {
			t.Errorf("scp as %q: %d %s", user, code, out)
		}
	}
	if out, code := g.transfer("", "scp", "-O", src, "web1@127.0.0.1:/tmp/x"); code == 0 || !strings.Contains(out, "legacy scp protocol") {
		t.Errorf("legacy scp: %d %s", code, out)
	}
	// The file-transfer role cannot run commands, and command roles cannot transfer files.
	if _, stderr, code := g.Run("exec web1 --role files -- id"); code == 0 {
		t.Fatalf("exec with a file-transfer role: %d %s", code, stderr)
	}

	type fileEvent struct {
		Op, Path, Target, SHA256, Error string
		Bytes                           int64
		OK                              bool
	}
	rows, err := g.A.Store.ReadDB().QueryContext(ctx, `SELECT data_json FROM timeline_events WHERE type = 'file.operation' ORDER BY at, id`)
	must(t, err)
	defer rows.Close()
	var events []fileEvent
	for rows.Next() {
		var raw string
		must(t, rows.Scan(&raw))
		var e fileEvent
		must(t, json.Unmarshal([]byte(raw), &e))
		events = append(events, e)
	}
	must(t, rows.Err())
	find := func(op, path string) *fileEvent {
		for i := range events {
			if events[i].Op == op && events[i].Path == path {
				return &events[i]
			}
		}
		t.Errorf("no %s event for %s in %+v", op, path, events)
		return &fileEvent{}
	}
	if e := find("write", "/tmp/build.tar"); !e.OK || e.Bytes != int64(len(payload)) || e.SHA256 != digest {
		t.Errorf("upload event %+v", e)
	}
	if e := find("read", "/tmp/build.tar"); !e.OK || e.Bytes != int64(len(payload)) || e.SHA256 != digest {
		t.Errorf("download event %+v", e)
	}
	if e := find("rename", "/tmp/build.tar"); !e.OK || e.Target != "/tmp/drop/b.tar" {
		t.Errorf("rename event %+v", e)
	}
	if e := find("remove", "/etc/passwd"); e.OK || e.Error == "" {
		t.Errorf("refused remove event %+v", e)
	}
	find("mkdir", "/tmp/drop")
	find("list", "/tmp/drop/")
	find("remove", "/tmp/drop/b.tar")

	var summaries, channels int
	must(t, g.A.Store.ReadDB().QueryRowContext(ctx, `SELECT count(*) FROM timeline_events WHERE type = 'file.summary'`).Scan(&summaries))
	must(t, g.A.Store.ReadDB().QueryRowContext(ctx, `SELECT count(*) FROM ssh_channels WHERE subsystem = 'sftp'`).Scan(&channels))
	if summaries != 3 || channels != 3 {
		t.Errorf("summaries = %d, sftp channels = %d, want 3 each", summaries, channels)
	}
}
