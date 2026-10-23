// Package keyring implements Hallpass key management (PLAN §13.1–13.2, ADR-0004): a master key-encryption key (KEK)
// wraps purpose-specific data keys that seal sensitive database fields, recording DEKs and MACs.
package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// KEKSize is the master key length in bytes (AES-256).
const KEKSize = 32

// DevKEKFile is the development-mode KEK generated inside the data directory when none is configured.
const DevKEKFile = "dev-kek"

// Errors.
var (
	ErrNoKEK       = errors.New("master key (KEK) not available")
	ErrWrongKEK    = errors.New("master key (KEK) does not match this data directory")
	ErrBadKEKFile  = errors.New("invalid KEK file")
	ErrDecrypt     = errors.New("decryption failed: ciphertext or associated data was modified, or the wrong key was used")
	ErrUnknownKey  = errors.New("unknown key version")
	ErrBadSealed   = errors.New("malformed sealed value")
	ErrBadPurpose  = errors.New("unknown key purpose")
	ErrNotUnlocked = errors.New("keyring not loaded")
)

// KeyWrapper wraps and unwraps data keys under a master key. The local implementation uses a KEK held in memory;
// KMS or Vault transit implementations can satisfy the same interface (R-03).
type KeyWrapper interface {
	// ID identifies the master key (stored next to wrapped keys to detect a mismatched KEK).
	ID() string
	Wrap(plaintext, aad []byte) ([]byte, error)
	Unwrap(wrapped, aad []byte) ([]byte, error)
}

// LocalKEK is a KeyWrapper backed by a 32-byte KEK, using AES-256-GCM with random 96-bit nonces.
type LocalKEK struct {
	id   string
	aead cipher.AEAD
}

// NewLocalKEK builds a wrapper from raw key material.
func NewLocalKEK(kek []byte) (*LocalKEK, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("%w: need %d bytes, got %d", ErrBadKEKFile, KEKSize, len(kek))
	}
	if bytes.Equal(kek, make([]byte, KEKSize)) {
		return nil, fmt.Errorf("%w: all-zero key", ErrBadKEKFile)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &LocalKEK{id: KEKID(kek), aead: aead}, nil
}

// KEKID derives a non-secret identifier for a KEK.
func KEKID(kek []byte) string {
	h := sha256.Sum256(append([]byte("hallpass-kek-id"), kek...))
	return hex.EncodeToString(h[:8])
}

// ID implements KeyWrapper.
func (k *LocalKEK) ID() string { return k.id }

// Wrap implements KeyWrapper: nonce(12) || AES-256-GCM(plaintext, aad).
func (k *LocalKEK) Wrap(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize(), k.aead.NonceSize()+len(plaintext)+k.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Unwrap implements KeyWrapper.
func (k *LocalKEK) Unwrap(wrapped, aad []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(wrapped) < ns+k.aead.Overhead() {
		return nil, ErrBadSealed
	}
	pt, err := k.aead.Open(nil, wrapped[:ns], wrapped[ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// GenerateKEK returns a new random KEK.
func GenerateKEK() ([]byte, error) {
	k := make([]byte, KEKSize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// EncodeKEK renders a KEK for a key file (base64, newline-terminated).
func EncodeKEK(k []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(k) + "\n")
}

// WriteKEKFile writes a new KEK file with mode 0400. It refuses to overwrite an existing file.
func WriteKEKFile(path string, kek []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // operator-chosen path
	if err != nil {
		return fmt.Errorf("create KEK file: %w", err)
	}
	if _, err := f.Write(EncodeKEK(kek)); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ParseKEK decodes key file contents: base64 (standard or URL, padded or not) or exactly 32 raw bytes.
func ParseKEK(data []byte) ([]byte, error) {
	if len(data) == KEKSize && !isPrintable(data) {
		return append([]byte(nil), data...), nil
	}
	s := strings.TrimSpace(string(data))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == KEKSize {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: expected base64 of %d bytes", ErrBadKEKFile, KEKSize)
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// Source describes where to load the KEK from.
type Source struct {
	Kind       string // "file" or "env"
	File       string
	Production bool
	DataDir    string
	Environ    []string
}

// LoadKEK loads the KEK according to src. In production a missing KEK is fatal. In development with no file
// configured, a development KEK is generated inside the data directory.
func LoadKEK(src Source) (*LocalKEK, error) {
	switch src.Kind {
	case "env":
		for _, kv := range src.Environ {
			if v, ok := strings.CutPrefix(kv, "HALLPASS_KEK="); ok && v != "" {
				k, err := ParseKEK([]byte(v))
				if err != nil {
					return nil, fmt.Errorf("HALLPASS_KEK: %w", err)
				}
				return NewLocalKEK(k)
			}
		}
		return nil, fmt.Errorf("%w: kek.source is env but HALLPASS_KEK is not set", ErrNoKEK)
	case "file", "":
	default:
		return nil, fmt.Errorf("unknown kek source %q", src.Kind)
	}
	path := src.File
	if path == "" {
		if src.Production {
			return nil, fmt.Errorf("%w: kek.file is required in production (generate one with `hallpass keys init-kek --out FILE`)", ErrNoKEK)
		}
		return loadOrCreateDevKEK(src.DataDir)
	}
	k, err := readKEKFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist (generate one with `hallpass keys init-kek --out %s`)", ErrNoKEK, path, path)
		}
		return nil, err
	}
	return NewLocalKEK(k)
}

func readKEKFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator-configured key path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrBadKEKFile, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o; it must not be accessible by group or others (chmod 0400)", ErrBadKEKFile, path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() && st.Uid != 0 {
		return nil, fmt.Errorf("%w: %s is owned by uid %d, not the hallpass user or root", ErrBadKEKFile, path, st.Uid)
	}
	data, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, err
	}
	return ParseKEK(data)
}

func loadOrCreateDevKEK(dataDir string) (*LocalKEK, error) {
	if dataDir == "" {
		return nil, ErrNoKEK
	}
	path := filepath.Join(dataDir, DevKEKFile)
	k, err := readKEKFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if k, err = GenerateKEK(); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return nil, err
		}
		if err := WriteKEKFile(path, k); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return NewLocalKEK(k)
}
