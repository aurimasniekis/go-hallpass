package inventory

import "github.com/aurimasniekis/go-hallpass/internal/inventory/alias"

// ReservedWords re-exports the reserved gateway words (HP-SSH-017).
var ReservedWords = alias.ReservedWords

// ValidAlias reports whether s is a usable server/role alias.
func ValidAlias(s string) bool { return alias.Valid(s) }

// IsReserved reports whether s is a reserved gateway word.
func IsReserved(s string) bool { return alias.IsReserved(s) }

// AliasRule describes the alias syntax for error messages.
const AliasRule = alias.Rule

// aliasRE is used for non-alias names (CA names) that share the syntax.
var aliasRE = struct{ MatchString func(string) bool }{MatchString: alias.Syntax}
