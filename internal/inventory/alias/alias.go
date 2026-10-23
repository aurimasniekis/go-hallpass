// Package alias defines server/role alias syntax and the reserved gateway words (HP-SSH-017). It is a leaf
// package with no dependencies so the pure SSH grammar can import it.
package alias

import (
	"regexp"
	"slices"
	"strings"
)

// ReservedWords can never be server or role aliases because they are SSH gateway commands or likely to become
// commands (HP-SSH-017).
var ReservedWords = []string{
	"list", "ls", "ps", "roles", "request", "status", "cancel", "connect", "exec", "sessions", "help", "version", "whoami",
	"admin", "api", "login", "logout", "shell", "ssh", "sftp", "scp", "hallpass",
}

var aliasRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// Valid reports whether s is a usable alias: the syntax and not reserved.
func Valid(s string) bool {
	return aliasRE.MatchString(s) && !IsReserved(s) && !strings.HasSuffix(s, "-")
}

// Syntax reports whether s matches the alias syntax (ignoring reserved words).
func Syntax(s string) bool { return aliasRE.MatchString(s) && !strings.HasSuffix(s, "-") }

// IsReserved reports whether s is a reserved gateway word.
func IsReserved(s string) bool { return slices.Contains(ReservedWords, s) }

// Rule describes the alias syntax for error messages.
const Rule = "1-63 characters: lowercase letter first, then lowercase letters, digits or '-', not ending in '-', and not a reserved word"
