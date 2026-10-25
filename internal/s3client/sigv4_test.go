package s3client

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The signing-key derivation example from the AWS SigV4 documentation ("Derive a signing key").
func TestSigningKeyAWSExample(t *testing.T) {
	got := hex.EncodeToString(signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam"))
	if want := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"; got != want {
		t.Fatalf("signing key %s, want %s", got, want)
	}
}

// The "GET Bucket (List Objects)" example from the S3 SigV4 header-signing documentation.
func TestSignAWSListObjectsExample(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	if err != nil {
		t.Fatal(err)
	}
	sign(req, "/", EmptySHA256, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1",
		time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	auth := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
	if auth != want {
		t.Fatalf("Authorization\n got %s\nwant %s", auth, want)
	}
}

func TestURIEncode(t *testing.T) {
	for in, want := range map[string]string{
		"a-b_c.d~e":       "a-b_c.d~e",
		"dir/file name":   "dir/file%20name",
		"a+b=c&d":         "a%2Bb%3Dc%26d",
		"ünï":             "%C3%BCn%C3%AF",
		"/bucket/x/y.bin": "/bucket/x/y.bin",
	} {
		if got := uriEncode(in, true); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := uriEncode("a/b", false); !strings.Contains(got, "%2F") {
		t.Errorf("slash kept in a query value: %q", got)
	}
}
