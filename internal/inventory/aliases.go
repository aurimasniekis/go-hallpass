package inventory

import (
	"regexp"
	"slices"
	"strings"
)

// ReservedWords can never be server or role aliases because they are SSH gateway commands (HP-SSH-017).
var ReservedWords = []string{
	"list", "ls", "roles", "request", "status", "cancel", "connect", "exec", "sessions", "help", "version", "whoami",
	"admin", "api", "login", "logout", "shell", "ssh", "sftp", "scp", "hallpass",
}

var aliasRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ValidAlias reports whether s is a usable server/role alias: the alias syntax and not reserved.
func ValidAlias(s string) bool {
	return aliasRE.MatchString(s) && !IsReserved(s) && !strings.HasSuffix(s, "-")
}

// IsReserved reports whether s is a reserved gateway word.
func IsReserved(s string) bool { return slices.Contains(ReservedWords, s) }

// AliasRule describes the alias syntax for error messages.
const AliasRule = "1-63 characters: lowercase letter first, then lowercase letters, digits or '-', not ending in '-', and not a reserved word"
