package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/s3client/s3test"
)

// Remote backup endpoints: the target never returns its secret, changes need the version, runs start in the background
// and are listed, and only system.settings may change anything.
func TestRemoteBackupAPI(t *testing.T) {
	h := newHarness(t)
	admin := h.bootstrapAdmin()
	srv := s3test.New(t, "AKIDTEST")

	var st struct {
		Configured bool `json:"configured"`
	}
	admin.ok("getBackupStatus", 200, http.MethodGet, "/api/v1/system/backups", nil).json(t, &st)
	if st.Configured {
		t.Fatal("configured before setup")
	}
	if r := admin.do(http.MethodGet, "/api/v1/system/backups/target", nil); r.status != http.StatusNotFound {
		t.Fatalf("target before setup: %d", r.status)
	}
	body := map[string]any{"endpoint": srv.URL, "bucket": "hp-backups", "prefix": "hallpass/", "path_style": true, "access_key_id": "AKIDTEST",
		"secret_access_key": "s3cret-value", "ca_bundle_pem": srv.CAPEM(), "allow_private_network": true, "keep_last": 3}
	r := admin.ok("putBackupTarget", 200, http.MethodPut, "/api/v1/system/backups/target", body)
	if strings.Contains(string(r.body), "s3cret-value") {
		t.Fatalf("secret returned: %s", r.body)
	}
	var tg struct {
		Version  int64  `json:"version"`
		Interval string `json:"interval"`
	}
	r.json(t, &tg)
	// A change without the version conflicts; with If-Match it applies and keeps the secret.
	if r := admin.do(http.MethodPut, "/api/v1/system/backups/target", map[string]any{"interval": "2h"}); r.status != http.StatusConflict {
		t.Fatalf("update without version: %d %s", r.status, r.body)
	}
	admin.ok("putBackupTarget", 200, http.MethodPut, "/api/v1/system/backups/target", map[string]any{"interval": "2h"}, "If-Match", `"1"`).json(t, &tg)
	if tg.Interval != "2h0m0s" || tg.Version != 2 {
		t.Fatalf("updated %+v", tg)
	}
	var test struct {
		OK bool `json:"ok"`
	}
	admin.ok("testBackupTarget", 200, http.MethodPost, "/api/v1/system/backups/target/test", nil).json(t, &test)
	if !test.OK {
		t.Fatal("connection test failed")
	}
	admin.ok("startBackupRun", 202, http.MethodPost, "/api/v1/system/backups/runs", nil)
	h.a.RemoteBackup.Wait()
	var runs struct {
		Items []struct {
			State  string `json:"state"`
			Stored bool   `json:"stored"`
		} `json:"items"`
	}
	admin.ok("listBackupRuns", 200, http.MethodGet, "/api/v1/system/backups/runs", nil).json(t, &runs)
	if len(runs.Items) != 1 || runs.Items[0].State != "succeeded" || !runs.Items[0].Stored {
		t.Fatalf("runs %+v", runs)
	}
	if len(srv.Keys("hp-backups")) < 2 {
		t.Fatalf("nothing uploaded: %v", srv.Keys("hp-backups"))
	}

	viewer := h.principalClient([]string{"viewer"}, "password")
	if r := viewer.do(http.MethodPut, "/api/v1/system/backups/target", map[string]any{"enabled": false}, "If-Match", `"2"`); r.status != http.StatusForbidden {
		t.Fatalf("viewer changed the target: %d", r.status)
	}
	if r := viewer.do(http.MethodPost, "/api/v1/system/backups/runs", nil); r.status != http.StatusForbidden {
		t.Fatalf("viewer started a backup: %d", r.status)
	}
	admin.ok("deleteBackupTarget", 204, http.MethodDelete, "/api/v1/system/backups/target", nil)
}
