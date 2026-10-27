package inventory

import (
	"database/sql"
	"encoding/json"
	"slices"
	"strings"

	"github.com/aurimasniekis/go-hallpass/internal/apirules"
	"github.com/aurimasniekis/go-hallpass/internal/apperr"
)

// APITarget lists the HTTPS host names of an API target (a server of kind api). Agents reach them through the
// gateway's API proxy, never directly with the target's credentials.
type APITarget struct {
	Hosts []string `json:"hosts"`
}

// APIRules say which requests an access profile on an API target allows (see package apirules).
type APIRules struct {
	Rules []apirules.Rule `json:"rules"`
}

// MaxAPIHosts bounds APITarget.Hosts.
const MaxAPIHosts = 20

// APIPort is the only port API targets are reached on.
const APIPort = 443

// Compile validates the rules and returns the compiled policy.
func (a *APIRules) Compile() (*apirules.Policy, error) { return apirules.Compile(a.Rules) }

// PrimaryHost is the first host without a wildcard prefix, shown as the target's address.
func (a *APITarget) PrimaryHost() string {
	if a == nil || len(a.Hosts) == 0 {
		return ""
	}
	return strings.TrimPrefix(a.Hosts[0], "*.")
}

// Covers reports whether host (lower case) is one of the target's hosts.
func (a *APITarget) Covers(host string) bool {
	return a != nil && slices.ContainsFunc(a.Hosts, func(p string) bool { return apirules.HostMatches(p, host) })
}

func normalizeAPITarget(a *APITarget) *APITarget {
	if a == nil {
		return nil
	}
	hosts := make([]string, len(a.Hosts))
	for i, h := range a.Hosts {
		hosts[i] = strings.ToLower(strings.TrimSpace(h))
	}
	return &APITarget{Hosts: slices.Compact(hosts)}
}

func validateAPITarget(v *apperr.Validation, s *Server) {
	if s.API == nil || len(s.API.Hosts) == 0 {
		v.Add("api.hosts", "at least one host name is required, e.g. api.github.com or *.googleapis.com")
		return
	}
	if len(s.API.Hosts) > MaxAPIHosts {
		v.Add("api.hosts", "at most %d host names", MaxAPIHosts)
	}
	for _, h := range s.API.Hosts {
		if !apirules.ValidHost(h) {
			v.Add("api.hosts", "%q is not a host name or a *.domain wildcard (IP addresses are not allowed)", h)
		}
	}
}

func validateAPIRules(v *apperr.Validation, r *Role) {
	if r.API == nil {
		v.Add("api.rules", "at least one allow rule is required")
		return
	}
	p, err := r.API.Compile()
	if err != nil {
		v.Add("api.rules", "%s", err.Error())
		return
	}
	if !p.HasAllow() {
		v.Add("api.rules", "at least one allow rule is required")
	}
}

func apiJSON(a any) sql.NullString {
	switch t := a.(type) {
	case *APITarget:
		if t == nil {
			return sql.NullString{}
		}
	case *APIRules:
		if t == nil {
			return sql.NullString{}
		}
	}
	b, _ := json.Marshal(a)
	return sql.NullString{String: string(b), Valid: true}
}
