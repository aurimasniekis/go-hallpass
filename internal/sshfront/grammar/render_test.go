package grammar

import (
	"strings"
	"testing"
)

// Operator-controlled text can never inject terminal control sequences into human output.
func TestRenderSanitizes(t *testing.T) {
	evil := "x\x1b]0;pwned\x07\u202eevil\r\nline"
	out := RenderList(NewListDoc(now, []ListServer{{Alias: "web1", Description: evil, Roles: []ListRole{{Alias: "r", Level: LevelAuto, Description: evil}}}}))
	out += RenderRoles(NewRolesDoc(now, ServerRef{Alias: "web1", Description: evil}, []RoleDetail{{Alias: "r", Description: evil, Capabilities: []string{evil}}}))
	out += RenderStatus(NewStatusDoc(now, StatusInfo{ID: rid, State: "denied", StateReason: NullString(evil)}))
	out += RenderSessions(NewSessionsDoc(now, []SessionItem{{GrantID: gid, State: "revoked", EndReason: NullString(evil)}}))
	out += RenderWhoAmI(NewWhoAmIDoc("agt", evil, "", "", "", evil))
	out += RenderVersion(NewVersionDoc(evil, evil))
	for _, r := range out {
		if r != '\n' && !printable(string(r)) {
			t.Fatalf("unprintable rune %U in output:\n%q", r, out)
		}
	}
	if strings.Contains(out, "\r") || strings.Count(out, "pwned") == 0 {
		t.Errorf("unexpected sanitization result: %q", out)
	}
}

func TestTableAlignment(t *testing.T) {
	got := table([][]string{{"A", "BB", "C"}, {"žžž", "", "x"}, {"", "y", ""}})
	want := "A    BB  C\nžžž      x\n     y\n"
	if got != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}
