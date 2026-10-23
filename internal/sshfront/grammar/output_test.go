package grammar

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var (
	now     = time.Date(2026, 10, 23, 14, 2, 11, 0, time.UTC)
	created = now
	expires = now.Add(30 * time.Minute)
	gid     = "grt_01jabcdefghjkmnpqrstvwxyz1"
	sid     = "ses_01jabcdefghjkmnpqrstvwxyz2"
)

func at(d time.Duration) Time { return Time(now.Add(d)) }

// fixtures returns one or more golden documents per schema, covering null and non-null variants.
func fixtures() map[string]any {
	cest := time.FixedZone("CEST", 2*3600)
	grantActive := &GrantInfo{ID: gid, State: "active", StartsAt: Time(now.Add(-5 * time.Minute).In(cest)), ExpiresAt: at(25*time.Minute + 500*time.Millisecond)}
	return map[string]any{
		"list": NewListDoc(now, []ListServer{
			{Alias: "foo-server", Description: "Primary web server", Roles: []ListRole{
				{Alias: "inspect", Description: "Read-only inspection", Level: LevelRequestable},
				{Alias: "deploy", Description: "Deploy releases", Level: LevelAuto, ActiveGrant: &ActiveGrant{GrantID: gid, ExpiresAt: at(29*time.Minute + 13*time.Second)}},
			}},
			{Alias: "db1", Description: "", Roles: []ListRole{{Alias: "readonly", Level: LevelVisible}}},
		}),
		"list-empty": NewListDoc(now, nil),
		"roles": NewRolesDoc(now, ServerRef{Alias: "foo-server", Description: "Primary web server"}, []RoleDetail{
			{
				Alias: "inspect", Description: "Read-only inspection", Level: LevelRequestable,
				Capabilities: []string{"exec", "pty", "shell"}, DefaultDuration: Duration(30 * time.Minute), MaxDuration: Duration(time.Hour),
				AllowedDurations: []Duration{Duration(15 * time.Minute), Duration(30 * time.Minute), Duration(time.Hour)},
			},
			{
				Alias: "deploy", Level: LevelAuto, Capabilities: []string{"exec", "env:DEPLOY_ENV"},
				DefaultDuration: Duration(10 * time.Minute), MaxDuration: Duration(90 * time.Minute),
				ActiveGrant: &ActiveGrant{GrantID: gid, ExpiresAt: at(-time.Minute)}, // expired by now: remaining clamps to 0s
			},
		}),
		"request": NewRequestDoc(now, RequestInfo{
			ID: rid, Server: "foo-server", Role: "inspect", State: "pending", CreatedAt: Time(created),
			ExpiresAt: Time(expires), RequestedDuration: Duration(30 * time.Minute),
		}),
		"request-approved": NewRequestDoc(now, RequestInfo{
			ID: rid, Server: "foo-server", Role: "deploy", State: "approved", Deduplicated: true, CreatedAt: Time(created),
			ExpiresAt: Time(expires), RequestedDuration: Duration(90 * time.Minute), Grant: grantActive,
		}),
		"status": NewStatusDoc(now, StatusInfo{
			ID: rid, Server: "foo-server", Role: "inspect", State: "pending", CreatedAt: Time(created),
			ExpiresAt: Time(expires), RequestedDuration: Duration(30 * time.Minute),
		}),
		"status-approved": NewStatusDoc(now, StatusInfo{
			ID: rid, Server: "foo-server", Role: "inspect", State: "approved", CreatedAt: Time(created.Add(-6 * time.Minute)),
			ExpiresAt: Time(expires), DecidedAt: TimePtr(now.Add(-5 * time.Minute)), RequestedDuration: Duration(30 * time.Minute),
			Grant: grantActive,
		}),
		"status-denied": NewStatusDoc(now, StatusInfo{
			ID: rid, Server: "foo-server", Role: "inspect", State: "denied", StateReason: "not during the freeze",
			CreatedAt: Time(created), ExpiresAt: Time(expires), DecidedAt: TimePtr(now), RequestedDuration: Duration(30 * time.Minute),
		}),
		"sessions": NewSessionsDoc(now, []SessionItem{
			{
				GrantID: gid, SessionID: NullString(sid), Server: "foo-server", Role: "deploy", State: "active",
				StartsAt: at(-5 * time.Minute), ExpiresAt: at(25 * time.Minute), ActiveConnections: 1, TotalConnections: 3,
			},
			{
				GrantID: "grt_01jabcdefghjkmnpqrstvwxyz3", Server: "db1", Role: "readonly", State: "revoked",
				StartsAt: at(-2 * time.Hour), ExpiresAt: at(-time.Hour), EndedAt: TimePtr(now.Add(-90 * time.Minute)), EndReason: "operator",
			},
		}),
		"sessions-empty": NewSessionsDoc(now, nil),
		"whoami":         NewWhoAmIDoc("agt_01jabcdefghjkmnpqrstvwxyz4", "ci-bot", "key_01jabcdefghjkmnpqrstvwxyz5", "SHA256:"+strings.Repeat("A", 43), "192.0.2.10"),
		"version":        NewVersionDoc("1.2.3", "abc1234"),
		"version-dev":    NewVersionDoc("dev", ""),
		"error":          NewErrorDoc(NotFoundOrForbidden()),
		"error-timeout":  NewErrorDoc(WaitTimedOut(rid, 2*time.Minute)),
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch\n got: %s\nwant: %s", name, got, want)
	}
}

func TestGoldenJSON(t *testing.T) {
	seen := map[string]bool{}
	for name, doc := range fixtures() {
		t.Run(name, func(t *testing.T) {
			b := mustMarshal(t, doc)
			if bytes.Count(b, []byte("\n")) != 1 {
				t.Errorf("not exactly one line")
			}
			golden(t, name+".json", b)
			if errs := validateDoc(t, b); len(errs) != 0 {
				t.Errorf("schema validation failed:\n%s", strings.Join(errs, "\n"))
			}
			// Round trip through the Go types.
			rt := reflect.New(reflect.TypeOf(doc))
			if err := json.Unmarshal(b, rt.Interface()); err != nil {
				t.Fatal(err)
			}
			b2 := mustMarshal(t, rt.Elem().Interface())
			if !bytes.Equal(b, b2) {
				t.Errorf("round trip changed output:\n%s%s", b, b2)
			}
		})
		var head struct{ Schema string }
		_ = json.Unmarshal(mustMarshal(t, doc), &head)
		seen[head.Schema] = true
	}
	for _, id := range Schemas() {
		if !seen[id] {
			t.Errorf("no golden document for %s", id)
		}
	}
}

// The PLAN §7.7 request example validates and matches the Go encoding.
func TestPlanRequestExample(t *testing.T) {
	doc := NewRequestDoc(now, RequestInfo{
		ID: rid, Server: "foo-server", Role: "inspect", State: "pending", CreatedAt: Time(now),
		ExpiresAt: Time(now.Add(30 * time.Minute)), RequestedDuration: Duration(30 * time.Minute),
	})
	want := `{"schema":"hallpass.request/v1","request":{"id":"` + rid + `","server":"foo-server","role":"inspect","state":"pending","deduplicated":false,"created_at":"2026-10-23T14:02:11Z","expires_at":"2026-10-23T14:32:11Z","requested_duration":"30m","grant":null}}` + "\n"
	if got := string(mustMarshal(t, doc)); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestBuilders(t *testing.T) {
	// Remaining is computed, truncated to whole seconds and never negative.
	l := NewListDoc(now, []ListServer{{Alias: "a", Roles: []ListRole{
		{Alias: "r", ActiveGrant: &ActiveGrant{ExpiresAt: at(90*time.Second + 900*time.Millisecond), Remaining: Duration(time.Hour)}},
		{Alias: "s", ActiveGrant: &ActiveGrant{ExpiresAt: at(-time.Second)}},
	}}})
	if got := time.Duration(l.Servers[0].Roles[0].ActiveGrant.Remaining); got != 90*time.Second {
		t.Errorf("remaining = %v", got)
	}
	if got := l.Servers[0].Roles[1].ActiveGrant.Remaining; got != 0 {
		t.Errorf("negative remaining not clamped: %v", got)
	}
	// Builders do not mutate their inputs.
	in := &ActiveGrant{ExpiresAt: at(time.Minute)}
	NewListDoc(now, []ListServer{{Roles: []ListRole{{ActiveGrant: in}}}})
	if in.Remaining != 0 {
		t.Error("builder mutated input")
	}
	g := &GrantInfo{State: "expired", ExpiresAt: at(time.Hour)}
	r := NewRequestDoc(now, RequestInfo{Grant: g})
	if r.Request.Grant.Remaining != 0 || r.Request.Grant == g {
		t.Error("inactive grant must have zero remaining and be copied")
	}
	// Empty slices encode as [] not null.
	for _, doc := range []any{NewListDoc(now, nil), NewSessionsDoc(now, nil), NewRolesDoc(now, ServerRef{}, []RoleDetail{{}})} {
		if b := mustMarshal(t, doc); bytes.Contains(b, []byte("null")) && !bytes.Contains(b, []byte(`"active_grant":null`)) {
			t.Errorf("null slice in %s", b)
		}
	}
	if _, err := Marshal(struct{}{}); err == nil {
		t.Error("Marshal accepted a non-document")
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0s", time.Second: "1s", 30 * time.Minute: "30m", time.Hour: "1h", 90 * time.Minute: "1h30m",
		time.Hour + time.Second: "1h0m1s", 2*time.Minute + 5*time.Second: "2m5s", 1500 * time.Millisecond: "1.5s",
		10 * time.Hour: "10h", 100 * time.Minute: "1h40m",
	} {
		got := FormatDuration(d)
		if got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
		if back, err := time.ParseDuration(got); err != nil || back != d {
			t.Errorf("%q does not round trip: %v %v", got, back, err)
		}
	}
}

func TestJSONTypes(t *testing.T) {
	var tm Time
	if err := json.Unmarshal([]byte(`"2026-10-23T16:02:11+02:00"`), &tm); err != nil || time.Time(tm).Location() != time.UTC || !time.Time(tm).Equal(now) {
		t.Errorf("Time unmarshal: %v %v", time.Time(tm), err)
	}
	for _, bad := range []string{`1`, `"nope"`} {
		if json.Unmarshal([]byte(bad), &tm) == nil {
			t.Errorf("Time accepted %s", bad)
		}
	}
	var d Duration
	for _, bad := range []string{`1`, `"nope"`} {
		if json.Unmarshal([]byte(bad), &d) == nil {
			t.Errorf("Duration accepted %s", bad)
		}
	}
	var ns NullString = "x"
	if err := json.Unmarshal([]byte(`null`), &ns); err != nil || ns != "" {
		t.Error("NullString null")
	}
	if json.Unmarshal([]byte(`1`), &ns) == nil {
		t.Error("NullString accepted a number")
	}
	if TimePtr(time.Time{}) != nil || TimePtr(now) == nil {
		t.Error("TimePtr")
	}
}

func TestGoldenHuman(t *testing.T) {
	f := fixtures()
	var b strings.Builder
	sections := []struct {
		name string
		text string
	}{
		{"list", RenderList(f["list"].(ListDoc))},
		{"list-empty", RenderList(f["list-empty"].(ListDoc))},
		{"roles", RenderRoles(f["roles"].(RolesDoc))},
		{"roles-empty", RenderRoles(NewRolesDoc(now, ServerRef{Alias: "x"}, nil))},
		{"request", RenderRequest(f["request"].(RequestDoc))},
		{"request-approved", RenderRequest(f["request-approved"].(RequestDoc))},
		{"status", RenderStatus(f["status"].(StatusDoc))},
		{"status-approved", RenderStatus(f["status-approved"].(StatusDoc))},
		{"status-denied", RenderStatus(f["status-denied"].(StatusDoc))},
		{"sessions", RenderSessions(f["sessions"].(SessionsDoc))},
		{"sessions-empty", RenderSessions(f["sessions-empty"].(SessionsDoc))},
		{"whoami", RenderWhoAmI(f["whoami"].(WhoAmIDoc))},
		{"version", RenderVersion(f["version"].(VersionDoc))},
		{"version-dev", RenderVersion(f["version-dev"].(VersionDoc))},
	}
	for _, s := range sections {
		for _, line := range strings.Split(strings.TrimSuffix(s.text, "\n"), "\n") {
			if strings.HasSuffix(line, " ") {
				t.Errorf("%s: trailing space in %q", s.name, line)
			}
		}
		if !strings.HasSuffix(s.text, "\n") {
			t.Errorf("%s: missing final newline", s.name)
		}
		b.WriteString("== " + s.name + "\n" + s.text)
	}
	golden(t, "human.txt", []byte(b.String()))
}
