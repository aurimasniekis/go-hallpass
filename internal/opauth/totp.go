package opauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA-1; HMAC-SHA-1 remains secure for this purpose
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238): SHA-1, 6 digits, 30 s period, ±1 step skew (HP-AUTH-006).
const (
	totpDigits = 6
	totpPeriod = 30
	totpSkew   = 1
	totpSecret = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, totpSecret)
	_, err := rand.Read(s)
	return s, err
}

// TOTPStep returns the time step for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPCode computes the code for a step.
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // non-negative after the epoch
	h := hmac.New(sha1.New, secret)
	h.Write(msg[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1000000)
}

// VerifyTOTP returns the matched step if code is valid within the skew window and newer than lastStep (no reuse).
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	matched := int64(-1)
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := cur + d
		if hmac.Equal([]byte(TOTPCode(secret, step)), []byte(code)) && step > lastStep {
			matched = step
		}
	}
	return matched, matched >= 0
}

// TOTPURI returns the otpauth:// provisioning URI for authenticator apps.
func TOTPURI(secret []byte, issuer, account string) string {
	v := url.Values{}
	v.Set("secret", b32.EncodeToString(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

// EncodeTOTPSecret renders a secret for manual entry.
func EncodeTOTPSecret(secret []byte) string { return b32.EncodeToString(secret) }
