#!/usr/bin/env bash
# Recovery drill: back up a populated instance, restore it onto a clean machine (a fresh
# container from the release image, no prior state, no network), verify every recording and the integrity chain,
# start it, and measure the recovery time objective (RTO) from "restore starts" to "/readyz ready".
#
# Usage: scripts/recovery-drill.sh [IMAGE] [SOAK_DURATION]
#   IMAGE          release image to restore with (default hallpass:local; built with `make image` if missing)
#   SOAK_DURATION  how long the soak harness runs to create the source data set (default 2m)
#
# Writes a report to $OUT (default ./recovery-drill-report.txt). Needs Docker and Go. Nothing is pushed.
set -euo pipefail

image=${1:-hallpass:local}
soak=${2:-2m}
out=${OUT:-$PWD/recovery-drill-report.txt}
helper=${HELPER_IMAGE:-docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5}
work=$(mktemp -d)
id="hallpass-drill-$$"
data_vol="$id-data" kek_vol="$id-kek" bak_vol="$id-backup"
container=""

cleanup() {
  local rc=$?
  if [[ -n $container ]]; then
    [[ $rc -ne 0 ]] && docker logs "$container" 2>&1 | tail -n 40 >&2
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  docker volume rm -f "$data_vol" "$kek_vol" "$bak_vol" >/dev/null 2>&1 || true
  rm -rf "$work"
  if [[ $rc -eq 0 ]]; then echo "recovery drill: PASS (report: $out)"; else echo "recovery drill: FAIL" >&2; fi
}
trap cleanup EXIT
step() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

if ! docker image inspect "$image" >/dev/null 2>&1; then
  step "building $image"
  make image IMAGE="$image"
fi

step "source data set: soak harness for $soak"
src="$work/src"
go run ./test/soak -duration "$soak" -warmup 5s -data "$src" -out "$work/soak.json" >/dev/null
go build -o "$work/hallpass" ./cmd/hallpass
cat >"$work/src.yaml" <<EOF
mode: development
data_dir: $src
public_url: http://127.0.0.1:1
kek:
  file: ""
http:
  listen: "127.0.0.1:1"
EOF
src_bytes=$(du -sk "$src" | awk '{print $1*1024}')
segments=$(find "$src/recordings" -type f | wc -l | tr -d ' ')
echo "source: $((src_bytes / 1048576)) MiB, $segments segment files"

"$work/hallpass" verify --config "$work/src.yaml" --json >"$work/src-verify.json"
src_head=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["chain_head_seq"], r["chain_head_hash"])' "$work/src-verify.json")

step "backup (online primitive, VACUUM INTO + segments + manifest)"
t0=$(now_ms)
"$work/hallpass" backup create --config "$work/src.yaml" --out "$work/backup" >/dev/null
backup_ms=$(( $(now_ms) - t0 ))
"$work/hallpass" backup verify "$work/backup" >/dev/null
[[ ! -e "$work/backup/dev-kek" ]] || fail "backup contains the KEK"
bak_bytes=$(du -sk "$work/backup" | awk '{print $1*1024}')

step "clean machine: fresh volumes, KEK delivered separately (0400, service UID)"
docker volume create "$data_vol" >/dev/null
docker volume create "$kek_vol" >/dev/null
docker volume create "$bak_vol" >/dev/null
tar -C "$work" -cf - backup | docker run --rm -i -v "$bak_vol:/b" "$helper" bash -c 'tar -C /b -xf - && chown -R 65532:65532 /b'
docker run --rm -i -v "$kek_vol:/k" "$helper" bash -c 'install -d -m 0700 -o 65532 -g 65532 /k/hallpass && cat > /k/hallpass/kek && chown 65532:65532 /k/hallpass/kek && chmod 0400 /k/hallpass/kek' <"$src/dev-kek"
cat >"$work/prod.yaml" <<'EOF'
mode: production
data_dir: /var/lib/hallpass
public_url: https://hallpass.drill.invalid
kek:
  source: file
  file: /run/secrets/hallpass/kek
ssh:
  listen: ":2222"
http:
  listen: ":8080"
egress:
  allow_cidrs: [192.0.2.0/24]
shutdown:
  drain_timeout: 5s
EOF
chmod 0644 "$work/prod.yaml"
run_opts=(--rm --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 --network none)
mounts=(-v "$data_vol:/var/lib/hallpass" -v "$kek_vol:/run/secrets:ro" -v "$bak_vol:/backup:ro"
  -v "$work/prod.yaml:/etc/hallpass/hallpass.yaml:ro" --tmpfs "/tmp:size=64m,mode=1777")

step "restore + verify + start (RTO clock running)"
t0=$(now_ms)
docker run "${run_opts[@]}" "${mounts[@]}" "$image" restore /backup/backup >"$work/restore.log" 2>&1 || { cat "$work/restore.log"; fail "restore"; }
restore_ms=$(( $(now_ms) - t0 ))
docker run "${run_opts[@]}" "${mounts[@]}" "$image" verify --json >"$work/verify.json" 2>"$work/verify.err" || { cat "$work/verify.err"; fail "verify"; }
verify_ms=$(( $(now_ms) - t0 - restore_ms ))
container=$(docker run -d --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 \
  "${mounts[@]}" -p 127.0.0.1::8080 -p 127.0.0.1::2222 "$image" serve)
ready=""
for _ in $(seq 1 240); do
  hp=$(docker port "$container" 8080/tcp 2>/dev/null | head -n1 | sed 's/.*://') || true
  if [[ -n $hp ]] && curl -fs "http://127.0.0.1:$hp/readyz" 2>/dev/null | grep -q '"ready"'; then ready=yes; break; fi
  [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || fail "serve exited"
  sleep 0.25
done
[[ -n $ready ]] || fail "restored instance never became ready"
rto_ms=$(( $(now_ms) - t0 ))
sp=$(docker port "$container" 2222/tcp | head -n1 | sed 's/.*://')
banner=$(python3 - "$sp" <<'EOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); print(s.recv(64).decode().strip()); s.close()
EOF
)
[[ $banner == SSH-2.0-Hallpass* ]] || fail "no SSH banner after restore"
docker stop -t 30 "$container" >/dev/null

# The verify report lists every segment; any non-OK segment fails the drill (open segments become "interrupted",
# which is reported, not corrupt).
verify_summary=$(python3 - "$work/verify.json" "$src_head" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
segs = r.get("segments", [])
bad = [s for s in segs if s["status"] not in ("ok", "interrupted", "skipped")]
head = f"{r['chain_head_seq']} {r['chain_head_hash']}"
print(f"{len(segs)} segments ({sum(s['status'] == 'ok' for s in segs)} ok), chain ok={r['chain_ok']} length={r['chain_length']}, "
      f"head matches source={head == sys.argv[2]}")
sys.exit(0 if r["ok"] and r["chain_ok"] and not bad and head == sys.argv[2] else 1)
PY
) || fail "verify after restore: $verify_summary"

{
  echo "HallPass recovery drill — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit:        $(git rev-parse --short HEAD)"
  echo "image:         $image ($(docker image inspect -f '{{.Id}}' "$image" | cut -c8-19))"
  echo "host:          $(uname -sm), $(sysctl -n hw.ncpu 2>/dev/null || nproc) CPUs (not the RH-1 reference hardware)"
  echo "data set:      $((src_bytes / 1048576)) MiB, $segments segment files (soak $soak)"
  echo "backup:        $((bak_bytes / 1048576)) MiB in $((backup_ms))ms; verified; KEK not included"
  echo "restore:       $((restore_ms))ms (clean volumes, no network, read-only root, non-root)"
  echo "verify:        $((verify_ms))ms: $verify_summary"
  echo "RTO:           $((rto_ms))ms from restore start to /readyz ready; SSH banner: ${banner}"
} | tee "$out"
