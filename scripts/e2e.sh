#!/usr/bin/env bash
# Browser end-to-end run (HP-TST-005, PLAN §18.3): build the UI and an embedui binary, start a fresh development
# instance on loopback ports with throwaway data, bootstrap it, and run the Playwright suite against it, including the
# agent-side SSH request. Every run starts from an empty database, so specs can assert exact effective-access changes.
#
# Usage: scripts/e2e.sh [playwright args...]
#   HTTP_PORT / SSH_PORT  loopback ports (default 28080 / 22222; must be free)
#   SKIP_BUILD=1          reuse web/dist and the binary from a previous run in $WORK
#   E2E_EXTRA_CONFIG      YAML appended to the generated configuration (top-level keys not already present)
#   E2E_SOURCE_ADDRESS    egress.source_addresses entry (the from= address in suggested authorized_keys lines)
#
# Needs Go, pnpm, ssh-keygen and ssh, and Chromium for Playwright (`pnpm exec playwright install chromium`).
# The server log is kept on failure. Nothing is pushed.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
http_port=${HTTP_PORT:-28080}
ssh_port=${SSH_PORT:-22222}
work=${WORK:-$(mktemp -d)}
url="http://127.0.0.1:$http_port"
pid=""

cleanup() {
  local rc=$?
  if [[ -n $pid ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
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

"$work/hallpass" serve -config "$work/hallpass.yaml" >"$work/server.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do
  curl -fsS "$url/readyz" >/dev/null 2>&1 && break
  kill -0 "$pid" 2>/dev/null || { echo "e2e: server exited during startup" >&2; exit 1; }
  sleep 0.2
done
curl -fsS "$url/readyz" >/dev/null

cd "$root/web"
HALLPASS_E2E_URL=$url HALLPASS_E2E_SETUP_TOKEN=$token HALLPASS_E2E_SSH=127.0.0.1:$ssh_port pnpm exec playwright test "$@"
