package s3client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)
// for the S3 service. Only the headers HallPass sends are signed: host, x-amz-content-sha256 and x-amz-date.

const (
	sigAlgorithm = "AWS4-HMAC-SHA256"
	amzDate      = "20060102T150405Z"
	scopeDate    = "20060102"
	// EmptySHA256 is the payload hash of a request without a body.
	EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// signingKey derives the SigV4 key for one day, region and service.
func signingKey(secret, day, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// uriEncode percent-encodes s as SigV4 requires: unreserved characters stay, everything else becomes %XX (uppercase).
// A slash is kept when keepSlash is set (object key paths).
func uriEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			const hexdig = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hexdig[c>>4])
			b.WriteByte(hexdig[c&15])
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

// sign adds x-amz-date, x-amz-content-sha256 and Authorization to req. rawPath is the unescaped request path; it is
// encoded once here (S3 does not double-encode).
func sign(req *http.Request, rawPath, payloadHash, accessKey, secret, region string, now time.Time) {
	now = now.UTC()
	date := now.Format(amzDate)
	day := now.Format(scopeDate)
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	host := req.URL.Host
	signed := "host;x-amz-content-sha256;x-amz-date"
	canonHeaders := "host:" + host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + date + "\n"
	canonReq := strings.Join([]string{req.Method, uriEncode(rawPath, true), canonicalQuery(req.URL.Query()), canonHeaders, signed, payloadHash}, "\n")
	sum := sha256.Sum256([]byte(canonReq))
	scope := day + "/" + region + "/s3/aws4_request"
	toSign := sigAlgorithm + "\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	sig := hex.EncodeToString(hmacSHA256(signingKey(secret, day, region, "s3"), toSign))
	req.Header.Set("Authorization", sigAlgorithm+" Credential="+accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}
