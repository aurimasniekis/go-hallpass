package main

import (
	"os"
	"strings"
	"testing"
)

// TestMain removes every HALLPASS_* variable inherited from the caller so the
// tests do not depend on the environment they are run from.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "HALLPASS_") {
			_ = os.Unsetenv(k)
		}
	}
	os.Exit(m.Run())
}
