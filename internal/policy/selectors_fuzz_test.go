package policy

import (
	"encoding/json"
	"slices"
	"testing"
)

// refMatches is an independent reading of the documented label-selector semantics (HP-POL-003): every matchLabels
// pair and every expression must hold; an empty selector and unknown operators match nothing.
func refMatches(ls *LabelSelector, labels map[string]string) bool {
	if ls == nil || len(ls.MatchLabels)+len(ls.MatchExpressions) == 0 {
		return false
	}
	ok := true
	for k, v := range ls.MatchLabels {
		got, has := labels[k]
		ok = ok && has && got == v
	}
	for _, r := range ls.MatchExpressions {
		v, has := labels[r.Key]
		switch r.Operator {
		case OpIn:
			ok = ok && has && slices.Contains(r.Values, v)
		case OpNotIn:
			ok = ok && (!has || !slices.Contains(r.Values, v))
		case OpExists:
			ok = ok && has
		case OpDoesNotExist:
			ok = ok && !has
		default:
			ok = false
		}
	}
	return ok
}

// HP-TST-002, HP-POL-003/004: label selectors decoded from untrusted JSON match exactly per the documented semantics;
// selectors on every clause of a rule are union-of-clauses and an all-empty selector never matches.
func FuzzLabelSelector(f *testing.F) {
	f.Add([]byte(`{"matchLabels":{"env":"prod"}}`), []byte(`{"env":"prod","team":"sre"}`))
	f.Add([]byte(`{"matchExpressions":[{"key":"env","operator":"NotIn","values":["prod"]}]}`), []byte(`{}`))
	f.Add([]byte(`{"matchExpressions":[{"key":"env","operator":"DoesNotExist"}]}`), []byte(`{"env":""}`))
	f.Add([]byte(`{"matchExpressions":[{"key":"env","operator":"in","values":["prod"]}]}`), []byte(`{"env":"prod"}`))
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte(`null`), []byte(`{"a":"b"}`))
	f.Fuzz(func(t *testing.T, sel, lbl []byte) {
		var ls *LabelSelector
		var labels map[string]string
		if json.Unmarshal(sel, &ls) != nil || json.Unmarshal(lbl, &labels) != nil {
			return
		}
		got, want := ls.Matches(labels), refMatches(ls, labels)
		if got != want {
			t.Fatalf("selector %s on %v: got %v, want %v", sel, labels, got, want)
		}
		obj := Object{ID: "x", Labels: labels}
		subj := SubjectSelector{AgentLabels: ls}
		if subj.Matches(obj) != want {
			t.Fatal("subject selector disagrees with its only clause")
		}
		if (SubjectSelector{}).Matches(obj) || (TargetSelector{}).Matches(obj) || (RoleSelector{}).Matches(obj) || (OperatorSelector{}).Matches(obj) {
			t.Fatal("empty selector matched")
		}
	})
}
