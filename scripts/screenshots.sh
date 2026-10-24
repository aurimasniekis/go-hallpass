#!/usr/bin/env bash
# Regenerates the documentation screenshots in site/public/screenshots (README and website). Everything shown is
# fictional: a fresh development instance (scripts/e2e.sh), four throwaway sshd containers named web1, db1, ci-runner
# and forge (a git server) on loopback ports 2431-2434, agents with keys generated at run time, and invented requests and sessions.
# Never point this at a real instance.
#
# Usage: scripts/screenshots.sh [OUT_DIR]   (default site/public/screenshots)
#   SKIP_BUILD=1  reuse the binary and web/dist from a previous run in $WORK (see scripts/e2e.sh)
#
# Needs Docker, Go, pnpm, git, ssh and ssh-keygen. Review every image before committing it.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=$(cd "${1:-$root/site/public/screenshots}" && pwd)
image=hallpass-docs-dest:local
containers=()
ctx=$(mktemp -d)

cleanup() {
  for c in ${containers[@]+"${containers[@]}"}; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$ctx"
}
trap cleanup EXIT

# Own build context: the repository's .dockerignore excludes test/ and scripts/.
cp "$root/test/openssh/sshd_config" "$root/scripts/screenshots/dest-entrypoint.sh" "$ctx/"
docker build -q -t "$image" -f "$root/scripts/screenshots/Dockerfile.dest" "$ctx" >/dev/null
port=2431
for host in web1 db1 ci-runner forge; do
  name="hallpass-docs-$host"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --hostname "$host" -p "127.0.0.1:$port:22" "$image" >/dev/null
  containers+=("$name")
  port=$((port + 1))
done

# Long reauthentication window: the spec seeds everything through the API right after signing in.
HP_SCREENSHOTS_OUT=$out E2E_SOURCE_ADDRESS=192.0.2.10 E2E_EXTRA_CONFIG=$'auth:\n  reauth_window: 1h' \
  "$root/scripts/e2e.sh" --project=screenshots
echo "screenshots written to $out"
