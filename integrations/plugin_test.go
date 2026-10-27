// Package integrations holds the agent skill and the Claude Code plugin; this test keeps the plugin's version in step
// with HallPass releases, because Claude Code only updates an installed plugin when its version changes.
package integrations

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

func TestPluginVersionFollowsRelease(t *testing.T) {
	raw, err := os.ReadFile(".claude-plugin/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	var plugin struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &plugin); err != nil {
		t.Fatal(err)
	}
	changelog, err := os.ReadFile("../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(changelog)
	if m == nil {
		t.Fatal("no released version in CHANGELOG.md")
	}
	if plugin.Version != string(m[1]) {
		t.Fatalf("integrations/.claude-plugin/plugin.json version is %s, the latest release in CHANGELOG.md is %s: bump the plugin "+
			"version with every release so installed plugins pick up skill changes", plugin.Version, m[1])
	}
}
