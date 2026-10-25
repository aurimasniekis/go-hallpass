package backup

import "testing"

// Internal helpers for the external backup_test package, which starts a full App (the App imports this package
// through remote backups, so tests that need it cannot live in package backup).
var (
	WriteManifestForTest = writeManifest
	HashFileForTest      = hashFile
)

// NewTestKEK returns a fresh in-memory KEK.
func NewTestKEK(t testing.TB) interface {
	ID() string
	Wrap(plaintext, aad []byte) ([]byte, error)
	Unwrap(wrapped, aad []byte) ([]byte, error)
} {
	return testKEK(t)
}
