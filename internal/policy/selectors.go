// Package policy evaluates default-deny visibility, request and approval policy (HP-POL-*, PLAN §9, ADR-0008).
package policy

import (
	"fmt"
	"slices"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
	"github.com/aurimasniekis/go-hallpass/internal/groups"
	"github.com/aurimasniekis/go-hallpass/internal/ids"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
)

// Label selector operators (Kubernetes semantics).
const (
	OpIn           = "In"
	OpNotIn        = "NotIn"
	OpExists       = "Exists"
	OpDoesNotExist = "DoesNotExist"
)

// Requirement is one label expression.
type Requirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// LabelSelector matches labels: every matchLabels pair AND every expression must hold. Unlike Kubernetes, an empty
// label selector matches nothing (HP-POL-003).
type LabelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels,omitempty"`
	MatchExpressions []Requirement     `json:"matchExpressions,omitempty"`
}

func (ls *LabelSelector) empty() bool {
	return ls == nil || (len(ls.MatchLabels) == 0 && len(ls.MatchExpressions) == 0)
}

// Matches reports whether labels satisfy the selector. An empty selector matches nothing.
func (ls *LabelSelector) Matches(labels map[string]string) bool {
	if ls.empty() {
		return false
	}
	for k, v := range ls.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	for _, r := range ls.MatchExpressions {
		v, ok := labels[r.Key]
		switch r.Operator {
		case OpIn:
			if !ok || !slices.Contains(r.Values, v) {
				return false
			}
		case OpNotIn:
			if ok && slices.Contains(r.Values, v) {
				return false
			}
		case OpExists:
			if !ok {
				return false
			}
		case OpDoesNotExist:
			if ok {
				return false
			}
		default:
			return false // unknown operators never match (validated on write)
		}
	}
	return true
}

func (ls *LabelSelector) validate(v *apperr.Validation, field string) {
	if ls == nil {
		return
	}
	groups.ValidateLabels(v, field+".matchLabels", ls.MatchLabels)
	for i, r := range ls.MatchExpressions {
		f := fmt.Sprintf("%s.matchExpressions[%d]", field, i)
		groups.ValidateLabels(v, f, map[string]string{r.Key: ""})
		switch r.Operator {
		case OpIn, OpNotIn:
			if len(r.Values) == 0 {
				v.Add(f, "operator %s requires values", r.Operator)
			}
			for _, val := range r.Values {
				groups.ValidateLabels(v, f, map[string]string{"k": val})
			}
		case OpExists, OpDoesNotExist:
			if len(r.Values) != 0 {
				v.Add(f, "operator %s takes no values", r.Operator)
			}
		default:
			v.Add(f, "unknown operator %q (In, NotIn, Exists, DoesNotExist)", r.Operator)
		}
	}
}

// Object is the policy view of an agent, server or role.
type Object struct {
	ID     string
	Name   string // role alias for roles
	Groups []string
	Labels map[string]string
}

// SubjectSelector selects agents.
type SubjectSelector struct {
	All         bool           `json:"all,omitempty"`
	Agents      []string       `json:"agents,omitempty"`
	AgentGroups []string       `json:"agent_groups,omitempty"`
	AgentLabels *LabelSelector `json:"agent_labels,omitempty"`
}

// Matches applies union semantics across clauses; an empty selector matches nothing.
func (s SubjectSelector) Matches(o Object) bool {
	return s.All || slices.Contains(s.Agents, o.ID) || intersects(s.AgentGroups, o.Groups) || s.AgentLabels.Matches(o.Labels)
}

// Empty reports whether no clause is set.
func (s SubjectSelector) Empty() bool {
	return !s.All && len(s.Agents) == 0 && len(s.AgentGroups) == 0 && s.AgentLabels.empty()
}

func (s SubjectSelector) validate(v *apperr.Validation, field string) {
	if s.Empty() {
		v.Add(field, "selector is empty and would match nothing; use all: true explicitly to match every agent")
	}
	for _, id := range s.Agents {
		if !ids.Valid(ids.Agent, id) {
			v.Add(field+".agents", "invalid agent id %q", id)
		}
	}
	groups.ValidateGroupNames(v, field+".agent_groups", s.AgentGroups)
	s.AgentLabels.validate(v, field+".agent_labels")
}

// TargetSelector selects servers.
type TargetSelector struct {
	All          bool           `json:"all,omitempty"`
	Servers      []string       `json:"servers,omitempty"`
	ServerGroups []string       `json:"server_groups,omitempty"`
	ServerLabels *LabelSelector `json:"server_labels,omitempty"`
}

// Matches applies union semantics; all: true includes servers created later.
func (s TargetSelector) Matches(o Object) bool {
	return s.All || slices.Contains(s.Servers, o.ID) || intersects(s.ServerGroups, o.Groups) || s.ServerLabels.Matches(o.Labels)
}

// Empty reports whether no clause is set.
func (s TargetSelector) Empty() bool {
	return !s.All && len(s.Servers) == 0 && len(s.ServerGroups) == 0 && s.ServerLabels.empty()
}

func (s TargetSelector) validate(v *apperr.Validation, field string) {
	if s.Empty() {
		v.Add(field, "selector is empty and would match nothing; use all: true explicitly to match every server (including future ones)")
	}
	for _, id := range s.Servers {
		if !ids.Valid(ids.Server, id) {
			v.Add(field+".servers", "invalid server id %q", id)
		}
	}
	groups.ValidateGroupNames(v, field+".server_groups", s.ServerGroups)
	s.ServerLabels.validate(v, field+".server_labels")
}

// RoleSelector selects roles by alias, ID or role labels (role classes).
type RoleSelector struct {
	All        bool           `json:"all,omitempty"`
	Names      []string       `json:"names,omitempty"`
	IDs        []string       `json:"ids,omitempty"`
	RoleLabels *LabelSelector `json:"role_labels,omitempty"`
}

// Matches applies union semantics.
func (s RoleSelector) Matches(o Object) bool {
	return s.All || slices.Contains(s.Names, o.Name) || slices.Contains(s.IDs, o.ID) || s.RoleLabels.Matches(o.Labels)
}

// Empty reports whether no clause is set.
func (s RoleSelector) Empty() bool {
	return !s.All && len(s.Names) == 0 && len(s.IDs) == 0 && s.RoleLabels.empty()
}

func (s RoleSelector) validate(v *apperr.Validation, field string) {
	if s.Empty() {
		v.Add(field, "selector is empty and would match nothing; use all: true explicitly to match every role")
	}
	for _, n := range s.Names {
		if !inventory.ValidAlias(n) {
			v.Add(field+".names", "invalid role alias %q", n)
		}
	}
	for _, id := range s.IDs {
		if !ids.Valid(ids.Role, id) {
			v.Add(field+".ids", "invalid role id %q", id)
		}
	}
	s.RoleLabels.validate(v, field+".role_labels")
}

// OperatorSelector selects operators for approver rules.
type OperatorSelector struct {
	All            bool     `json:"all,omitempty"`
	Operators      []string `json:"operators,omitempty"`
	OperatorGroups []string `json:"operator_groups,omitempty"`
}

// Matches applies union semantics.
func (s OperatorSelector) Matches(o Object) bool {
	return s.All || slices.Contains(s.Operators, o.ID) || intersects(s.OperatorGroups, o.Groups)
}

// Empty reports whether no clause is set.
func (s OperatorSelector) Empty() bool {
	return !s.All && len(s.Operators) == 0 && len(s.OperatorGroups) == 0
}

func (s OperatorSelector) validate(v *apperr.Validation, field string) {
	if s.Empty() {
		v.Add(field, "selector is empty and would match nothing")
	}
	for _, id := range s.Operators {
		if !ids.Valid(ids.Operator, id) {
			v.Add(field+".operators", "invalid operator id %q", id)
		}
	}
	groups.ValidateGroupNames(v, field+".operator_groups", s.OperatorGroups)
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}
