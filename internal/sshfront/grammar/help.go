package grammar

import (
	"sort"
	"strings"
)

var helpTopics = map[string]string{
	"": `HallPass gateway commands (ssh <gateway> <command> …):

  list [--json] [--server <server>]     visible servers and roles (default with no command)
  roles <server> [--json]               roles of one server
  request <server> [options]            request access without connecting (--wait to wait)
  status <req_id> [--json] [--wait[=bool]] [--wait-timeout <d>]
  cancel <req_id> [--json]              cancel your pending request
  connect <server> [options]            reuse a grant or request access, wait, then open a shell
  <server> [options]                    same as connect
  exec <server> [options] -- <command>  as connect, but run <command> on the server
  sessions [--json] [--all]             your active (and with --all, recent) grants
  whoami [--json]                       your agent identity and key
  api ca | env | requests                set up HTTPS API access through the API proxy (see help api)
  version [--json]                      gateway, grammar and schema versions
  help [topic]                          topics: ` + "%TOPICS%" + `

Options for request, connect and exec:
  --role <role>               role to use (required when the server has several)
  --reason <text>             why you need access (1-1000 characters)
  --duration <d>              requested duration, e.g. 30m (policy limits apply)
  --wait[=true|false]         wait for a decision (request: false, connect/exec: true)
  --no-wait                   same as --wait=false
  --wait-timeout <d>          how long to wait, 0s to 15m (default 2m)
  --idempotency-key <key>     8-128 characters from A-Z a-z 0-9 . _ -
  --json                      machine-readable output (one JSON document)

Options take "--opt value" or "--opt=value", in any order, each at most once.

Git and file transfers use the standard tools, waiting for approval like connect:
  git clone <gateway>:<remote>/<owner>/<repo>.git    git remotes, marked (git) in list
  git clone <remote>+<profile>@<gateway>:<path>      "+<profile>" picks the access profile
  scp <file> <server>@<gateway>:<path>              roles with the file-transfer capability
  sftp <server>+<role>@<gateway>                    "+<role>" picks the role

APIs (marked (api) in list) are called with their usual tools through the API proxy; see help api.
`,
	"api": `api ca
api env [--port <port>] [--role <profile>]

API targets (marked (api) in list) are HTTPS APIs such as GitHub, Cloudflare or Google Cloud. You call them with
their usual tools (gh, wrangler, gcloud, curl) through the gateway's API proxy, which adds the credential: you never
hold the real token, and every call is checked against your access profile's rules and recorded.

1. Open the proxy tunnel (keep it running):
     ssh -fN -o ClearAllForwardings=no -L 127.0.0.1:18080:hallpass:443 <gateway>
2. Load the proxy settings (writes the CA bundle to ~/.hallpass/api-ca.pem and exports HTTPS_PROXY, CA file
   variables and placeholder tokens for gh and wrangler):
     eval "$(ssh <gateway> api env)"
3. Get access like any other target, or rely on auto-approval:
     ssh <gateway> request <api> --role <role> --reason '<why>' --wait
4. Use the tool as usual, e.g. gh pr list.

Simpler: run each command through hallpass-api (shipped with HallPass), which opens the tunnel, sets the variables
for that command only, reports the command so approvers see it, waits for approval and runs it again:
     hallpass-api --gateway <gateway> --reason '<why>' -- gh issue comment 42 --body 'Fixed in #43'

By default the proxy picks the access profile for each call: one you hold access to, then an auto-approved one, then
a requestable one. To use one profile only (no fallback), pass --role <profile> to hallpass-api, or to api env, which
puts it in the proxy URL (http://<profile>@127.0.0.1:18080).

Public hosts that are not API targets and need no credentials (gh attestation verify fetches from
tuf-repo-cdn.sigstore.dev and tmaproduction.blob.core.windows.net) are refused by the proxy. Bypass it for them
with NO_PROXY, which hallpass-api adds to its own entries:
     NO_PROXY=<host>,<host> hallpass-api --gateway <gateway> -- gh attestation verify …

api requests <invocation> lists the requests the proxy filed during a hallpass-api run (used by hallpass-api).
api ca prints only the CA bundle (PEM). Its CAs can sign certificates for the API host names only. A refused call
returns HTTP 403 with a "hallpass:" message that says why and what to request.
`,
	"list": `list [--json] [--server <server>]   (alias: ls; also the default with no command)

Shows the servers and roles visible to you, each role's access level (visible, requestable or auto) and the
remaining time of any active grant. --json emits hallpass.list/v1.
`,
	"roles": `roles <server> [--json]

Shows one server's roles with capabilities, default and maximum durations and allowed durations. Unknown and
hidden servers give the same "not found or not permitted" error (exit 82). --json emits hallpass.roles/v1.
`,
	"request": `request <server> [--role r] [--reason text] [--duration d] [--wait[=bool]|--no-wait]
        [--wait-timeout d] [--idempotency-key k] [--json]

Creates a pending request, or reuses an identical pending one. It does not connect. By default it returns at once;
with --wait it waits for a decision. --json emits hallpass.request/v1.
`,
	"status": `status <req_id> [--json] [--wait[=bool]] [--wait-timeout d]

Shows the state of one of your requests and its grant when approved. --wait waits until the request is decided,
expires or is canceled. --json emits hallpass.status/v1.
`,
	"cancel": `cancel <req_id> [--json]

Cancels one of your pending requests. --json emits hallpass.status/v1.
`,
	"connect": `connect <server> [options]   (shorthand: <server> [options])

Uses an active grant, or creates (or reuses) a request, waits for approval (default up to 2m) and opens a shell.
Without a PTY a missing --reason exits 90 instead of prompting. If the wait times out the request stays pending
(exit 86); resume with "status <req_id> --wait".
`,
	"exec": `exec <server> [options] -- <command>

As connect, but runs <command> on the server; stdout and stderr stay separate and the remote exit status is
returned. Everything after the first unquoted "--" (and the spaces after it) is sent unchanged to the server, where
the remote user's login shell interprets it: "--" does not stop remote shell expansion. Quote for the remote shell,
for example:  ssh <gateway> "exec web1 -- 'ls -l /var/log | head'"
`,
	"sessions": `sessions [--json] [--all]

Shows your active grants with remaining time and connection counts; --all adds recent ended ones.
--json emits hallpass.sessions/v1.
`,
	"whoami": `whoami [--json]

Shows your agent ID and name, the key you authenticated with and your source address. --json emits
hallpass.whoami/v1.
`,
	"version": `version [--json]

Shows the gateway version, the grammar version and the JSON schema identifiers. --json emits hallpass.version/v1.
`,
	"exit-codes": "", // generated
	"json": `With --json, success output is one JSON document on stdout carrying a "schema" field (hallpass.<name>/v1).
Errors are one line on stderr: {"schema":"hallpass.error/v1","source":"gateway","code":…,"exit_code":…,
"message":…,"request_id":…}. The line is also written when stderr is not a terminal. Timestamps are RFC 3339 UTC;
durations are Go duration strings. Fields may be added within /v1, never removed or renamed.
`,
	"quoting": `The gateway part of a command is split on spaces and tabs. '…' is literal; "…" is literal except \" and \\;
outside quotes \x means x. There is no $, glob, ~, brace or command substitution. Control characters other than
TAB are rejected. The first unquoted standalone "--" ends gateway parsing (see: help exec).
`,
}

// HelpTopics returns the help topics in order (the empty overview topic excluded).
func HelpTopics() []string {
	out := make([]string, 0, len(helpTopics))
	for k := range helpTopics {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func isHelpTopic(t string) bool {
	if t == "ls" {
		return true
	}
	_, ok := helpTopics[t]
	return ok && t != ""
}

// HelpText returns the help text for topic ("" for the overview; "ls" is accepted for "list").
func HelpText(topic string) (string, error) {
	if topic == "ls" {
		topic = "list"
	}
	if topic != "" && !isHelpTopic(topic) {
		return "", usage("unknown help topic; topics: " + strings.Join(HelpTopics(), ", "))
	}
	switch topic {
	case "":
		return strings.Replace(helpTopics[""], "%TOPICS%", strings.Join(HelpTopics(), ", "), 1), nil
	case "exit-codes":
		rows := [][]string{{"CODE", "NAME", "MEANING"}}
		for _, e := range exitCodes {
			rows = append(rows, []string{itoa(int(e.code)), e.name, e.desc})
		}
		return "Gateway exit codes (a destination exit status passes through unchanged):\n\n" + table(rows) +
			"\nWithout a hallpass.error/v1 line on stderr, an exit code in 80-90 came from the destination command.\n", nil
	}
	return helpTopics[topic], nil
}
