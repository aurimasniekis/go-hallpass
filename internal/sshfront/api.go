package sshfront

import (
	"context"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/go-hallpass/internal/apiproxy"
	"github.com/aurimasniekis/go-hallpass/internal/inventory"
	"github.com/aurimasniekis/go-hallpass/internal/obs"
	"github.com/aurimasniekis/go-hallpass/internal/sshfront/grammar"
)

// APIProxyEnabled implements TunnelHandler.
func (h *Handler) APIProxyEnabled() bool { return h.API != nil }

// HandleAPITunnel implements TunnelHandler: the channel carries one HTTP CONNECT tunnel to the API proxy. The agent
// is the connection's authenticated identity; refusals outside a session are audited through Deny.
func (h *Handler) HandleAPITunnel(ctx context.Context, c *Conn, ch ssh.Channel) {
	h.API.Serve(ctx, apiproxy.Client{ConnectionID: c.ID, AgentID: c.AgentID, KeyID: c.KeyID, SourceIP: c.SourceIP.String(),
		Deny: func(action string, details map[string]any) {
			if h.Deny != nil {
				h.Deny(ctx, c, action, details)
			}
		}}, ch)
}

// apiTargets returns the IDs of the API targets visible to the agent.
func (s *session) apiTargets(ctx context.Context) []string {
	var out []string
	for _, vs := range s.snap.Visible(s.c.AgentID) {
		if s.serverKind(ctx, vs.Server.ID) == inventory.KindAPI {
			out = append(out, vs.Server.ID)
		}
	}
	return out
}

// api serves "api ca" and "api env".
func (s *session) api(ctx context.Context, c grammar.API) int {
	if s.h.API == nil || s.h.APIService == nil {
		return s.fail(grammar.Usage("the API proxy is not enabled on this gateway"))
	}
	targets := s.apiTargets(ctx)
	if len(targets) == 0 {
		return s.fail(grammar.NewError(grammar.ExitNotFoundOrForbidden, "no API targets are visible to you"))
	}
	bundle, err := s.h.APIService.CABundle(ctx, targets)
	if err != nil {
		s.h.Log.Error("API CA bundle unavailable", obs.Err(err))
		return s.fail(grammar.Internal())
	}
	if c.Sub == grammar.APICA {
		_, _ = io.WriteString(s.out, bundle)
		return 0
	}
	_, _ = io.WriteString(s.out, apiEnv(bundle, c.Port))
	return 0
}

// apiEnv renders shell lines (for eval) that install the CA bundle and point common API tools at the proxy tunnel.
func apiEnv(bundle string, port int) string {
	proxy := fmt.Sprintf("http://127.0.0.1:%d", port)
	var b strings.Builder
	fmt.Fprintf(&b, `# HallPass API proxy settings. The tunnel must be open first:
#   ssh -fN -L 127.0.0.1:%d:%s:443 <gateway>
(umask 077 && mkdir -p "$HOME/.hallpass" && cat > "$HOME/.hallpass/api-ca.pem" <<'HALLPASS_API_CA'
%sHALLPASS_API_CA
printf 'hallpass\n' > "$HOME/.hallpass/placeholder-token")
`, port, apiproxy.Host, bundle)
	ca := `"$HOME/.hallpass/api-ca.pem"`
	for _, kv := range [][2]string{
		{"HTTPS_PROXY", proxy}, {"https_proxy", proxy}, {"NO_PROXY", "localhost,127.0.0.1,::1"}, {"no_proxy", "localhost,127.0.0.1,::1"},
		{"SSL_CERT_FILE", ca}, {"NODE_EXTRA_CA_CERTS", ca}, {"NODE_USE_ENV_PROXY", "1"}, {"REQUESTS_CA_BUNDLE", ca},
		{"CURL_CA_BUNDLE", ca}, {"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", ca}, {"CLOUDSDK_PROXY_TYPE", "http"},
		{"CLOUDSDK_PROXY_ADDRESS", "127.0.0.1"}, {"CLOUDSDK_PROXY_PORT", fmt.Sprint(port)},
		{"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", `"$HOME/.hallpass/placeholder-token"`},
		{"GH_TOKEN", "hallpass"}, {"CLOUDFLARE_API_TOKEN", "hallpass"},
	} {
		fmt.Fprintf(&b, "export %s=%s\n", kv[0], kv[1])
	}
	b.WriteString("# Tokens above are placeholders: HallPass replaces them with each access profile's credential.\n")
	return b.String()
}
