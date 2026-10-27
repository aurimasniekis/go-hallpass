package grammar

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Human-format rendering: plain text, aligned columns, no color. Every operator- or agent-controlled string is
// passed through sanitizeLine so control, format and bidi characters can never reach the agent's terminal.

const dash = "-"

func itoa(i int) string { return strconv.Itoa(i) }

// sanitizeLine replaces non-printable runes (controls, format and bidi characters, invalid UTF-8) with '?'. Spaces
// are kept; other whitespace becomes a space.
func sanitizeLine(s string) string {
	ok := true
	for _, r := range s {
		if r == utf8.RuneError || (r != ' ' && !unicode.IsPrint(r)) {
			ok = false
			break
		}
	}
	if ok {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || (r != utf8.RuneError && unicode.IsPrint(r)):
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func cell(s string) string {
	if s == "" {
		return dash
	}
	return sanitizeLine(s)
}

// table aligns rows into columns separated by two spaces; trailing spaces are trimmed. Cells must be sanitized.
func table(rows [][]string) string {
	var widths []int
	for _, r := range rows {
		for i, c := range r {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], utf8.RuneCountInString(c))
		}
	}
	var b strings.Builder
	for _, r := range rows {
		var line strings.Builder
		for i, c := range r {
			line.WriteString(c)
			if i < len(r)-1 {
				line.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)+2))
			}
		}
		b.WriteString(strings.TrimRight(line.String(), " "))
		b.WriteByte('\n')
	}
	return b.String()
}

func activeCell(g *ActiveGrant) string {
	if g == nil {
		return dash
	}
	return FormatDuration(time.Duration(g.Remaining)) + " left"
}

// RenderList renders a ListDoc as a table: one row per server followed by its roles.
func RenderList(doc ListDoc) string {
	if len(doc.Servers) == 0 {
		return "No servers are visible to this agent.\n"
	}
	rows := [][]string{{"SERVER", "ROLE", "ACCESS", "ACTIVE", "DESCRIPTION"}}
	for _, s := range doc.Servers {
		name := sanitizeLine(s.Alias)
		if s.Kind == "git" || s.Kind == "api" {
			name += " (" + s.Kind + ")"
		}
		rows = append(rows, []string{name, "", "", "", sanitizeLine(s.Description)})
		for _, r := range s.Roles {
			rows = append(rows, []string{"", sanitizeLine(r.Alias), cell(r.Level), activeCell(r.ActiveGrant), sanitizeLine(r.Description)})
		}
	}
	return table(rows)
}

func durations(ds []Duration) string {
	if len(ds) == 0 {
		return dash
	}
	parts := make([]string, len(ds))
	for i, d := range ds {
		parts[i] = FormatDuration(time.Duration(d))
	}
	return strings.Join(parts, ",")
}

func list(ss []string) string {
	if len(ss) == 0 {
		return dash
	}
	return sanitizeLine(strings.Join(ss, ","))
}

// RenderRoles renders a RolesDoc.
func RenderRoles(doc RolesDoc) string {
	var b strings.Builder
	b.WriteString("Server: " + sanitizeLine(doc.Server.Alias))
	if doc.Server.Description != "" {
		b.WriteString(" (" + sanitizeLine(doc.Server.Description) + ")")
	}
	b.WriteString("\n\n")
	if len(doc.Roles) == 0 {
		b.WriteString("No roles are visible on this server.\n")
		return b.String()
	}
	rows := [][]string{{"ROLE", "ACCESS", "CAPABILITIES", "DEFAULT", "MAX", "DURATIONS", "ACTIVE", "DESCRIPTION"}}
	for _, r := range doc.Roles {
		rows = append(rows, []string{
			sanitizeLine(r.Alias), cell(r.Level), list(r.Capabilities),
			FormatDuration(time.Duration(r.DefaultDuration)), FormatDuration(time.Duration(r.MaxDuration)),
			durations(r.AllowedDurations), activeCell(r.ActiveGrant), sanitizeLine(r.Description),
		})
	}
	b.WriteString(table(rows))
	return b.String()
}

func grantRows(g *GrantInfo) [][]string {
	if g == nil {
		return [][]string{{"grant:", dash}}
	}
	rows := [][]string{
		{"grant:", sanitizeLine(g.ID) + " (" + cell(g.State) + ")"},
		{"grant starts:", FormatTime(time.Time(g.StartsAt))},
		{"grant expires:", FormatTime(time.Time(g.ExpiresAt))},
	}
	if g.State == "active" {
		rows = append(rows, []string{"remaining:", FormatDuration(time.Duration(g.Remaining))})
	}
	return rows
}

// RenderRequest renders a RequestDoc as aligned "key: value" lines.
func RenderRequest(doc RequestDoc) string {
	r := doc.Request
	state := cell(r.State)
	if r.Deduplicated {
		state += " (existing request reused)"
	}
	rows := [][]string{
		{"request:", sanitizeLine(r.ID)},
		{"server:", sanitizeLine(r.Server)},
		{"role:", sanitizeLine(r.Role)},
		{"state:", state},
		{"duration:", FormatDuration(time.Duration(r.RequestedDuration))},
		{"created:", FormatTime(time.Time(r.CreatedAt))},
		{"expires:", FormatTime(time.Time(r.ExpiresAt))},
	}
	rows = append(rows, grantRows(r.Grant)...)
	return table(rows)
}

// RenderStatus renders a StatusDoc as aligned "key: value" lines.
func RenderStatus(doc StatusDoc) string {
	s := doc.Request
	state := cell(s.State)
	if s.StateReason != "" {
		state += " (" + sanitizeLine(string(s.StateReason)) + ")"
	}
	decided := dash
	if s.DecidedAt != nil {
		decided = FormatTime(time.Time(*s.DecidedAt))
	}
	rows := [][]string{
		{"request:", sanitizeLine(s.ID)},
		{"server:", sanitizeLine(s.Server)},
		{"role:", sanitizeLine(s.Role)},
		{"state:", state},
		{"duration:", FormatDuration(time.Duration(s.RequestedDuration))},
		{"created:", FormatTime(time.Time(s.CreatedAt))},
		{"expires:", FormatTime(time.Time(s.ExpiresAt))},
		{"decided:", decided},
	}
	rows = append(rows, grantRows(s.Grant)...)
	return table(rows)
}

// RenderSessions renders a SessionsDoc as a table.
func RenderSessions(doc SessionsDoc) string {
	if len(doc.Sessions) == 0 {
		return "No sessions.\n"
	}
	rows := [][]string{{"GRANT", "SERVER", "ROLE", "STATE", "REMAINING", "EXPIRES", "CONNECTIONS"}}
	for _, s := range doc.Sessions {
		state := cell(s.State)
		if s.EndReason != "" {
			state += " (" + sanitizeLine(string(s.EndReason)) + ")"
		}
		rem := dash
		if s.State == "active" {
			rem = FormatDuration(time.Duration(s.Remaining))
		}
		rows = append(rows, []string{
			sanitizeLine(s.GrantID), sanitizeLine(s.Server), sanitizeLine(s.Role), state, rem,
			FormatTime(time.Time(s.ExpiresAt)), itoa(s.ActiveConnections) + " active / " + itoa(s.TotalConnections) + " total",
		})
	}
	return table(rows)
}

// RenderWhoAmI renders a WhoAmIDoc.
func RenderWhoAmI(doc WhoAmIDoc) string {
	return table([][]string{
		{"agent:", sanitizeLine(doc.AgentID) + " (" + cell(doc.AgentName) + ")"},
		{"key:", cell(doc.KeyID)},
		{"fingerprint:", cell(doc.KeyFingerprint)},
		{"source:", cell(doc.SourceIP)},
	})
}

// RenderVersion renders a VersionDoc.
func RenderVersion(doc VersionDoc) string {
	v := sanitizeLine(doc.Version)
	if doc.Commit != "" {
		v += " (" + sanitizeLine(string(doc.Commit)) + ")"
	}
	return table([][]string{
		{"hallpass:", v},
		{"grammar:", sanitizeLine(doc.GrammarVersion)},
		{"schemas:", list(doc.Schemas)},
	})
}
