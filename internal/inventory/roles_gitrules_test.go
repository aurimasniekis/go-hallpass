package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGitRulesThinPushBasesJSON(t *testing.T) {
	// A row stored before the field existed reads as false.
	var legacy GitRules
	if err := json.Unmarshal([]byte(`{"repos":["acme/api"],"push":{"branches":["agent/**"]}}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ThinPushBases {
		t.Fatal("legacy row must read thin_push_bases as false")
	}
	// Round trip with the field set.
	b, err := json.Marshal(&GitRules{Repos: []string{"acme/api"}, ThinPushBases: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"thin_push_bases":true`) {
		t.Fatalf("not serialized: %s", b)
	}
	var back GitRules
	if err := json.Unmarshal(b, &back); err != nil || !back.ThinPushBases {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	// False is omitted, so unchanged profiles keep their stored JSON.
	if b, _ := json.Marshal(&GitRules{Repos: []string{"x/y"}}); strings.Contains(string(b), "thin_push_bases") {
		t.Fatalf("false must be omitted: %s", b)
	}
}
