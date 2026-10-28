#!/usr/bin/env bash
# Browser end-to-end run: build the UI and an embedui binary, start a fresh development
# instance on loopback ports with throwaway data, bootstrap it, and run the Playwright suite against it, including the
# agent-side SSH request. Every run starts from an empty database, so specs can assert exact effective-access changes.
#
# Usage: scripts/e2e.sh [playwright args...]
#   HTTP_PORT / SSH_PORT  loopback ports (default 28080 / 22222; must be free)
#   SKIP_BUILD=1          reuse web/dist and the binary from a previous run in $WORK
#   E2E_EXTRA_CONFIG      YAML appended to the generated configuration (top-level keys not already present)
#   E2E_SOURCE_ADDRESS    egress.source_addresses entry (the from= address in suggested authorized_keys lines)
#   E2E_DEST=1            also start a throwaway OpenSSH destination container (test/openssh image) for the session
#                         and replay specs; they read HP_E2E_DEST (host:port) and HP_E2E_DEST_CONTAINER
#   E2E_DEX=1             also start a throwaway Dex identity provider on DEX_PORT (default 25556) for the SSO spec,
#                         with one user whose password is generated per run (HP_E2E_DEX_* variables)
#   E2E_ADD_HOSTS         "name:ip ..." entries: the server then runs in a container (host network) whose /etc/hosts
#                         has them, so fake upstreams can answer for real host names without touching this machine
#   E2E_CA_FILE           with E2E_ADD_HOSTS: PEM bundle the containerized server trusts instead of the system roots
#
# Needs Go, pnpm, ssh-keygen and ssh, and Chromium for Playwright (`pnpm exec playwright install chromium`); Docker for
# E2E_DEST=1, E2E_DEX=1 and E2E_ADD_HOSTS.
# The server log is kept on failure. Nothing is pushed.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
http_port=${HTTP_PORT:-28080}
ssh_port=${SSH_PORT:-22222}
work=${WORK:-$(mktemp -d)}
url="http://127.0.0.1:$http_port"
pid=""
dest=""
dex=""
server=""

cleanup() {
  local rc=$?
  if [[ -n $pid ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if [[ -n $dest ]]; then docker rm -f "$dest" >/dev/null 2>&1 || true; fi
  if [[ -n $dex ]]; then docker rm -f "$dex" >/dev/null 2>&1 || true; fi
  if [[ -n $server ]]; then docker rm -f "$server" >/dev/null 2>&1 || true; fi
  if [[ $rc -ne 0 ]]; then
    echo "e2e: FAIL (server log: $work/server.log)" >&2
    tail -n 40 "$work/server.log" >&2 2>/dev/null || true
  else
    rm -rf "$work/data"
    echo "e2e: PASS"
  fi
}
trap cleanup EXIT

if [[ ${SKIP_BUILD:-} != 1 ]]; then
  (cd "$root/web" && pnpm build)
  (cd "$root" && CGO_ENABLED=0 go build -tags embedui -o "$work/hallpass" ./cmd/hallpass)
fi

for port in "$http_port" "$ssh_port"; do
  # A readiness probe answered by some other server would run the suite against the wrong instance.
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "e2e: 127.0.0.1:$port is already in use; set HTTP_PORT/SSH_PORT" >&2
    exit 1
  fi
done

if [[ ${E2E_DEST:-} == 1 ]]; then
  # Own build context: the repository's .dockerignore excludes test/. Host keys are generated at container start.
  ctx=$(mktemp -d)
  cp "$root/test/openssh/Dockerfile.sshd" "$root/test/openssh/sshd_config" "$root/test/openssh/entrypoint.sh" "$ctx/"
  docker build -q -t hallpass-e2e-dest:local -f "$ctx/Dockerfile.sshd" "$ctx" >/dev/null
  rm -rf "$ctx"
  dest=hallpass-e2e-dest-$$
  docker run -d --name "$dest" -p 127.0.0.1::22 hallpass-e2e-dest:local >/dev/null
  for _ in $(seq 1 50); do
    docker exec "$dest" sh -c 'test -s /etc/ssh/ssh_host_ed25519_key.pub && pgrep sshd' >/dev/null 2>&1 && break
    sleep 0.2
  done
  export HP_E2E_DEST="127.0.0.1:$(docker port "$dest" 22/tcp | head -n 1 | sed 's/.*://')" HP_E2E_DEST_CONTAINER=$dest
fi

if [[ ${E2E_DEX:-} == 1 ]]; then
  dex_port=${DEX_PORT:-25556}
  if (exec 3<>"/dev/tcp/127.0.0.1/$dex_port") 2>/dev/null; then
    echo "e2e: 127.0.0.1:$dex_port is already in use; set DEX_PORT" >&2
    exit 1
  fi
  dex_issuer="http://127.0.0.1:$dex_port/dex"
  dex_secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  dex_password=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
  dex_hash=$(printf '%s\n' "$dex_password" | (cd "$root" && go run ./scripts/e2e/bcrypt))
  cat >"$work/dex.yaml" <<DEX
issuer: $dex_issuer
storage: {type: memory}
web: {http: 0.0.0.0:5556}
oauth2: {responseTypes: [code], skipApprovalScreen: true}
enablePasswordDB: true
staticClients:
  - id: hallpass-e2e
    name: HallPass
    secret: "$dex_secret"
    redirectURIs: ["$url/auth/oidc/callback"]
staticPasswords:
  - email: "sso-approver@example.test"
    username: sso-approver
    name: SSO Approver
    emailVerified: true
    userID: "e2e-sso-approver"
    hash: "$dex_hash"
    groups: ["hallpass-approvers"]
DEX
  dex=hallpass-e2e-dex-$$
  # Pinned like the OIDC interoperability tests (test/oidcinterop/docker_test.go).
  docker create --name "$dex" -p "127.0.0.1:$dex_port:5556" \
    ghcr.io/dexidp/dex:v2.46.0@sha256:933fcd3f523338c847b88ef84a7145fb2fcb7b9917f08418612afeaaa2001777 \
    dex serve /etc/dex/hallpass.yaml >/dev/null
  docker cp "$work/dex.yaml" "$dex:/etc/dex/hallpass.yaml" >/dev/null
  rm -f "$work/dex.yaml"
  docker start "$dex" >/dev/null
  for _ in $(seq 1 100); do
    curl -fsS "$dex_issuer/.well-known/openid-configuration" >/dev/null 2>&1 && break
    sleep 0.2
  done
  curl -fsS "$dex_issuer/.well-known/openid-configuration" >/dev/null
  export HP_E2E_DEX_ISSUER=$dex_issuer HP_E2E_DEX_CLIENT_ID=hallpass-e2e HP_E2E_DEX_CLIENT_SECRET=$dex_secret \
    HP_E2E_DEX_EMAIL=sso-approver@example.test HP_E2E_DEX_PASSWORD=$dex_password
fi

rm -rf "$work/data" "$root/web/.e2e-state"
cat >"$work/hallpass.yaml" <<EOF
mode: development
data_dir: $work/data
public_url: $url
kek:
  file: ""
ssh:
  listen: 127.0.0.1:$ssh_port
http:
  listen: 127.0.0.1:$http_port
egress:
  allow_cidrs: [127.0.0.0/8]
  allow_special_cidrs: [127.0.0.0/8]
${E2E_SOURCE_ADDRESS:+  source_addresses: [$E2E_SOURCE_ADDRESS]}
EOF
if [[ -n ${E2E_EXTRA_CONFIG:-} ]]; then printf '%s\n' "$E2E_EXTRA_CONFIG" >>"$work/hallpass.yaml"; fi

# The binary refuses unknown HALLPASS_* variables, so harness settings use other prefixes (HP_*).
if ! boot=$("$work/hallpass" admin bootstrap -config "$work/hallpass.yaml" 2>&1); then
  printf '%s\n' "$boot" | tail -n 5 >&2
  echo "e2e: bootstrap failed" >&2
  exit 1
fi
token=$(printf '%s\n' "$boot" | awk '/^  token: /{print $2}')
[[ -n $token ]] || { echo "e2e: bootstrap printed no setup token" >&2; exit 1; }

if [[ -n ${E2E_ADD_HOSTS:-} ]]; then
  # The static binary in a minimal container sharing the host network: same loopback ports, its own /etc/hosts.
  server=hallpass-e2e-server-$$
  run=(--rm --name "$server" --network host -u "$(id -u):$(id -g)" -v "$work:$work")
  for h in $E2E_ADD_HOSTS; do run+=(--add-host "$h"); done
  if [[ -n ${E2E_CA_FILE:-} ]]; then run+=(-v "$E2E_CA_FILE:/etc/hallpass-e2e/ca.pem:ro" -e SSL_CERT_FILE=/etc/hallpass-e2e/ca.pem); fi
  docker run "${run[@]}" alpine:3.22 "$work/hallpass" serve -config "$work/hallpass.yaml" >"$work/server.log" 2>&1 &
else
  "$work/hallpass" serve -config "$work/hallpass.yaml" >"$work/server.log" 2>&1 &
fi
pid=$!
for _ in $(seq 1 100); do
  curl -fsS "$url/readyz" >/dev/null 2>&1 && break
  kill -0 "$pid" 2>/dev/null || { echo "e2e: server exited during startup" >&2; exit 1; }
  sleep 0.2
done
curl -fsS "$url/readyz" >/dev/null

cd "$root/web"
HALLPASS_E2E_URL=$url HALLPASS_E2E_SETUP_TOKEN=$token HALLPASS_E2E_SSH=127.0.0.1:$ssh_port pnpm exec playwright test "$@"
