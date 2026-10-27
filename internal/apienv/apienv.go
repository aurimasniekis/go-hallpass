// Package apienv is shared by the gateway ("api env") and the hallpass-api wrapper: the environment that points
// common API tools at the API proxy, and the CONNECT headers in which the wrapper reports the command it runs.
package apienv

import (
	"cmp"
	"encoding/base64"
	"fmt"
	"unicode/utf8"
)

// CONNECT headers set by hallpass-api. Values are base64url (no padding) of UTF-8 text, so any command line fits
// in one header line. They are reported by the agent: context for approvers, never authorization.
const (
	HeaderCommand    = "Hallpass-Command"
	HeaderReason     = "Hallpass-Reason"
	HeaderInvocation = "Hallpass-Invocation"
	// HeaderRole names the only access profile the proxy may use (plain alias, not encoded). Tools configured without
	// hallpass-api give it as the proxy URL's user name instead (http://<profile>@127.0.0.1:<port>).
	HeaderRole = "Hallpass-Role"
	// HeaderSession names the agent session (conversation) the tunnel's requests and grants belong to. Tools
	// configured without hallpass-api give it as the proxy URL's password.
	HeaderSession = "Hallpass-Session"
)

// NoRole is the proxy URL user name meaning "no named access profile", used when only a session is given.
const NoRole = "_"

// MaxTextRunes bounds the reported command and reason.
const MaxTextRunes = 1000

// Placeholder is the token tools are given; the proxy replaces it with the access profile's credential.
const Placeholder = "hallpass"

// Encode encodes a header value.
func Encode(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// Decode decodes a header value; invalid or oversized values yield "".
func Decode(v string) string {
	if v == "" || len(v) > 8*MaxTextRunes {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || !utf8.Valid(b) {
		return ""
	}
	return string(b)
}

// Vars returns the environment for API tools using the proxy on 127.0.0.1:port, with caFile holding the CA bundle
// and tokenFile the placeholder token (for gcloud). A non-empty role becomes the proxy URL's user name and a session
// its password; tools send both in Proxy-Authorization on every CONNECT. Values are literal (not shell-quoted).
func Vars(port int, role, session, caFile, tokenFile string) [][2]string {
	user := ""
	switch {
	case session != "":
		user = cmp.Or(role, NoRole) + ":" + session + "@"
	case role != "":
		user = role + "@"
	}
	proxy := fmt.Sprintf("http://%s127.0.0.1:%d", user, port)
	vars := [][2]string{
		{"HTTPS_PROXY", proxy}, {"https_proxy", proxy}, {"NO_PROXY", "localhost,127.0.0.1,::1"}, {"no_proxy", "localhost,127.0.0.1,::1"},
		{"SSL_CERT_FILE", caFile}, {"NODE_EXTRA_CA_CERTS", caFile}, {"NODE_USE_ENV_PROXY", "1"}, {"REQUESTS_CA_BUNDLE", caFile},
		{"CURL_CA_BUNDLE", caFile}, {"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", caFile}, {"CLOUDSDK_PROXY_TYPE", "http"},
		{"CLOUDSDK_PROXY_ADDRESS", "127.0.0.1"}, {"CLOUDSDK_PROXY_PORT", fmt.Sprint(port)},
		{"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", tokenFile},
		{"GH_TOKEN", Placeholder}, {"CLOUDFLARE_API_TOKEN", Placeholder},
	}
	if role != "" || session != "" {
		vars = append(vars, [2]string{"CLOUDSDK_PROXY_USERNAME", cmp.Or(role, NoRole)})
	}
	if session != "" {
		vars = append(vars, [2]string{"CLOUDSDK_PROXY_PASSWORD", session})
	}
	return vars
}
