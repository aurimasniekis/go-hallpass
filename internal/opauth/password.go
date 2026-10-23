// Package opauth implements human operator authentication: local accounts with Argon2id passwords, TOTP MFA and
// recovery codes, invitations and resets, server-side web sessions with CSRF protection, throttling, bootstrap and
// break-glass recovery (PLAN §12.2–12.3, HP-AUTH-*).
package opauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/aurimasniekis/go-hallpass/internal/apperr"
)

// MaxPasswordBytes is the upper bound after normalization; longer input is rejected, never truncated (HP-AUTH-003).
const MaxPasswordBytes = 1024

// Params are versioned Argon2id parameters (HP-AUTH-002).
type Params struct {
	Version uint32
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen int
}

// ParamSets lists every parameter version ever used; hashes record their version and are upgraded on login.
var ParamSets = map[uint32]Params{
	1: {Version: 1, Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16},
}

// CurrentParams is the version used for new hashes.
var CurrentParams = ParamSets[1]

// NormalizePassword applies NFKC and enforces length bounds.
func NormalizePassword(pw string, minBytes int) ([]byte, error) {
	if !strings.ContainsRune(pw, 0) && len(pw) > 4*MaxPasswordBytes {
		return nil, apperr.New(apperr.CodeInvalid, "password must be at most %d bytes", MaxPasswordBytes)
	}
	n := norm.NFKC.String(pw)
	switch {
	case strings.ContainsRune(n, 0):
		return nil, apperr.New(apperr.CodeInvalid, "password must not contain NUL characters")
	case len(n) > MaxPasswordBytes:
		return nil, apperr.New(apperr.CodeInvalid, "password must be at most %d bytes", MaxPasswordBytes)
	case len(n) < minBytes:
		return nil, apperr.New(apperr.CodeInvalid, "password must be at least %d bytes", minBytes)
	}
	return []byte(n), nil
}

// HashPassword returns a PHC-format Argon2id hash: $argon2id$v=19$m=…,t=…,p=…$salt$hash.
func HashPassword(pw []byte, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(pw, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// VerifyPassword checks pw against a PHC hash in constant time.
func VerifyPassword(pw []byte, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return false, errBadHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 4*1024*1024 || t > 100 {
		return false, errBadHash
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, errBadHash
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, errBadHash
	}
	got := argon2.IDKey(pw, salt, t, m, p, uint32(len(want))) //nolint:gosec // bounded above
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash returns a hash with the current parameters, verified for unknown accounts so that response time does
// not reveal whether an account exists (HP-AUTH-005). It is derived lazily per parameter version so a parameter
// change never leaves unknown-account logins measurably cheaper or more expensive than real ones.
func dummyHash() string {
	dummyMu.Lock()
	defer dummyMu.Unlock()
	if h, ok := dummyByVersion[CurrentParams.Version]; ok {
		return h
	}
	h, err := HashPassword([]byte("hallpass-dummy-password-for-timing"), CurrentParams)
	if err != nil {
		panic(err)
	}
	dummyByVersion[CurrentParams.Version] = h
	return h
}

var (
	dummyMu        sync.Mutex
	dummyByVersion = map[uint32]string{}
)

// Calibrate returns parameters whose time cost makes one hash take roughly target on this machine (bounded 1..10).
func Calibrate(target time.Duration) Params {
	p := CurrentParams
	pw := []byte("calibration-password")
	salt := make([]byte, p.SaltLen)
	for t := uint32(1); t <= 10; t++ {
		start := time.Now()
		argon2.IDKey(pw, salt, t, p.Memory, p.Threads, p.KeyLen)
		if time.Since(start) >= target {
			p.Time = t
			return p
		}
		p.Time = t
	}
	return p
}
