package config

import (
	"strings"
	"testing"
	"time"
)

// HP-REC-013: per-class retention overrides with validation.
func TestRetentionClasses(t *testing.T) {
	c := Default()
	c.Recording.RetentionClasses = []string{"sensitive=8760h", " short = 168h "}
	if got := c.Recording.RetentionFor("sensitive"); got != 8760*time.Hour {
		t.Fatalf("sensitive %v", got)
	}
	if got := c.Recording.RetentionFor("short"); got != 168*time.Hour {
		t.Fatalf("short %v", got)
	}
	if got := c.Recording.RetentionFor("standard"); got != c.Recording.DefaultRetention.D() {
		t.Fatalf("default %v", got)
	}
	for _, bad := range []string{"nodelimiter", "x=1h", "=24h", "y=notaduration", "z=100000h"} {
		c.Recording.RetentionClasses = []string{bad}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "retention_classes") {
			t.Errorf("%q accepted", bad)
		}
	}
}
