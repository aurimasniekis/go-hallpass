#!/usr/bin/env bash
# Container smoke test for the HallPass image (PLAN WP24 "container smoke test", HP-OPS-007).
#
# Usage: scripts/container-smoke.sh IMAGE
#
# Checks, without pushing anything:
#   1. image metadata: non-root numeric user, exposed ports, data volume, no shell in the image
#   2. `hallpass version --json` runs
#   3. KEK provisioning with `hallpass keys init-kek` into a separate volume (0400, UID 65532)
#   4. `hallpass config check` and `hallpass migrate` with a production config and a read-only root filesystem
#   5. a KEK with group/other permissions is refused
#   6. `hallpass serve` starts, accepts an SSH connection (server banner), and exits 0 on SIGTERM
#
# Not covered yet: /readyz (WP22) and `ssh center list` against a fixture agent (needs agent bootstrap, WP20).
set -euo pipefail

image=${1:?usage: $0 IMAGE}
helper=${HELPER_IMAGE:-docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5}
id="hallpass-smoke-$$"
data_vol="$id-data"
kek_vol="$id-kek"
cfg_dir=$(mktemp -d)
container=""

cleanup() {
  local rc=$?
  if [[ -n $container ]]; then
    if [[ $rc -ne 0 ]]; then docker logs "$container" 2>&1 | tail -n 50 >&2 || true; fi
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  docker volume rm -f "$data_vol" "$kek_vol" >/dev/null 2>&1 || true
  rm -rf "$cfg_dir"
  if [[ $rc -eq 0 ]]; then echo "container smoke: PASS"; else echo "container smoke: FAIL" >&2; fi
}
trap cleanup EXIT

step() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Hardened run options shared by every invocation (mirrors deploy/compose.yaml).
run_opts=(--rm --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532)

step "image metadata"
user=$(docker image inspect -f '{{.Config.User}}' "$image")
[[ $user == "65532:65532" ]] || fail "image user is '$user', want 65532:65532"
ports=$(docker image inspect -f '{{json .Config.ExposedPorts}}' "$image")
[[ $ports == *'"2222/tcp"'* && $ports == *'"8080/tcp"'* ]] || fail "exposed ports $ports"
vols=$(docker image inspect -f '{{json .Config.Volumes}}' "$image")
[[ $vols == *'"/var/lib/hallpass"'* ]] || fail "volumes $vols"
for sh in /bin/sh /bin/bash /busybox/sh; do
  if docker run --rm --entrypoint "$sh" "$image" -c true >/dev/null 2>&1; then fail "image contains a shell at $sh"; fi
done
echo "user=$user ports=$ports volumes=$vols, no shell"

step "version"
docker run "${run_opts[@]}" "$image" version --json | tee "$cfg_dir/version.json"
grep -q '"version"' "$cfg_dir/version.json" || fail "version output"

step "provision KEK in a separate volume"
docker volume create "$kek_vol" >/dev/null
docker volume create "$data_vol" >/dev/null
# The KEK volume starts root-owned; hand it to the service UID (the distroless image has no shell to do this).
docker run --rm -v "$kek_vol:/kek" "$helper" install -d -m 0700 -o 65532 -g 65532 /kek/hallpass
docker run "${run_opts[@]}" -v "$kek_vol:/kek" "$image" keys init-kek --out /kek/hallpass/kek
mode=$(docker run --rm -v "$kek_vol:/kek:ro" "$helper" stat -c '%a %u:%g' /kek/hallpass/kek)
[[ $mode == "400 65532:65532" ]] || fail "KEK mode/owner is '$mode', want '400 65532:65532'"
echo "KEK mode/owner: $mode"

cat >"$cfg_dir/hallpass.yaml" <<'EOF'
mode: production
data_dir: /var/lib/hallpass
public_url: https://hallpass.example.test
kek:
  source: file
  file: /run/secrets/hallpass/kek
ssh:
  listen: ":2222"
http:
  listen: ":8080"
log:
  level: info
  format: json
egress:
  allow_cidrs: [192.0.2.0/24]
shutdown:
  drain_timeout: 5s
EOF
chmod 0644 "$cfg_dir/hallpass.yaml"
mounts=(-v "$data_vol:/var/lib/hallpass" -v "$kek_vol:/run/secrets:ro"
  -v "$cfg_dir/hallpass.yaml:/etc/hallpass/hallpass.yaml:ro" --tmpfs "/tmp:size=16m,mode=1777")

step "config check"
docker run "${run_opts[@]}" "${mounts[@]}" "$image" config check

step "KEK inside the data volume is refused"
if out=$(docker run "${run_opts[@]}" "${mounts[@]}" -e HALLPASS_KEK_FILE=/var/lib/hallpass/kek "$image" config check 2>&1); then
  fail "config check accepted kek.file inside data_dir: $out"
fi
[[ $out == *"kek.file must be stored outside data_dir"* ]] || fail "unexpected refusal message: $out"
echo "refused: kek.file must be stored outside data_dir"

step "migrate"
docker run "${run_opts[@]}" "${mounts[@]}" "$image" migrate
perm=$(docker run --rm -v "$data_vol:/data:ro" "$helper" stat -c '%a %u:%g' /data)
[[ $perm == "700 65532:65532" ]] || fail "data volume is '$perm', want '700 65532:65532'"
echo "data volume mode/owner: $perm"

step "KEK with group/other permissions is refused"
docker run --rm -v "$kek_vol:/kek" "$helper" bash -c 'cp -p /kek/hallpass/kek /kek/hallpass/kek-loose && chmod 0440 /kek/hallpass/kek-loose'
# `keys status` loads the KEK (migrate does not).
if out=$(docker run "${run_opts[@]}" "${mounts[@]}" -e HALLPASS_KEK_FILE=/run/secrets/hallpass/kek-loose "$image" keys status 2>&1); then
  fail "keys status accepted a 0440 KEK: $out"
fi
[[ $out == *"must not be accessible by group or others"* ]] || fail "unexpected refusal message: $out"
echo "refused: ${out##*hallpass: }"

step "serve: SSH banner and graceful SIGTERM"
container=$(docker run -d --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 \
  "${mounts[@]}" -p 127.0.0.1::2222 "$image" serve)
port=""
for _ in $(seq 1 60); do
  port=$(docker port "$container" 2222/tcp 2>/dev/null | head -n1 | sed 's/.*://') || true
  banner=""
  if [[ -n $port ]] && exec 3<>"/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
    IFS= read -r -t 3 banner <&3 || true
    exec 3<&- 3>&-
    [[ $banner == SSH-2.0-* ]] && break
  fi
  [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || fail "serve exited early"
  sleep 0.5
done
[[ ${banner:-} == SSH-2.0-* ]] || fail "no SSH banner on port ${port:-?}"
echo "banner: ${banner%$'\r'}"
docker stop -t 30 "$container" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$container")
[[ $code == 0 ]] || fail "serve exited $code after SIGTERM"
echo "serve exited 0 after SIGTERM"
