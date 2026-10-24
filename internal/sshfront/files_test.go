package sshfront

import "testing"

func TestLegacySCP(t *testing.T) {
	for cmd, want := range map[string]bool{
		"scp -t /tmp/":          true,
		"scp -f /etc/app.conf":  true,
		"scp -r -t /tmp/dir":    true,
		"scp -pt /tmp":          true,
		"scp":                   false,
		"scp status":            false,
		"exec web1 -- scp -t x": false,
		"list":                  false,
	} {
		if got := legacySCP(cmd); got != want {
			t.Errorf("legacySCP(%q) = %v, want %v", cmd, got, want)
		}
	}
}
