#!/usr/bin/env bash
# Builds Hallpass release archives and SHA256SUMS (PLAN WP24, HP-OPS-009).
#
# Usage: scripts/release-build.sh [-o OUTDIR] [PLATFORM...]
#   PLATFORM is GOOS/GOARCH; default: linux/amd64 linux/arm64 darwin/arm64.
#
# Environment (all optional; derived from git when unset):
#   VERSION            version string embedded in the binary, e.g. v1.2.3 (default: git describe, else "dev")
#   COMMIT             full commit hash (default: git rev-parse HEAD)
#   SOURCE_DATE_EPOCH  build timestamp in Unix seconds (default: commit time); also used for archive mtimes
#   BUILDVCS           true|false, passed to go build -buildvcs (default: true inside a git work tree)
#   GO                 go command (default: go)
#
# Binaries are static (CGO_ENABLED=0), built with -trimpath and an empty build ID, so equal inputs give equal bytes.
# Archives are reproducible when GNU tar is available (CI); BSD tar output is deterministic in content but not in bytes.
set -euo pipefail

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

out=dist
while getopts ":o:h" opt; do
  case $opt in
    o) out=$OPTARG ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
platforms=("$@")
if [[ ${#platforms[@]} -eq 0 ]]; then
  platforms=(linux/amd64 linux/arm64 darwin/arm64)
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

go_cmd=${GO:-go}
in_git=false
if [[ -d .git ]] && command -v git >/dev/null 2>&1; then
  in_git=true
fi

version=${VERSION:-}
if [[ -z $version ]]; then
  if $in_git; then version=$(git describe --tags --always --dirty 2>/dev/null || echo dev); else version=dev; fi
fi
if [[ ! $version =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]]; then
  echo "release-build: invalid VERSION '$version'" >&2
  exit 2
fi
commit=${COMMIT:-}
if [[ -z $commit ]] && $in_git; then commit=$(git rev-parse HEAD 2>/dev/null || true); fi
if [[ -n $commit && ! $commit =~ ^[0-9A-Za-z]+$ ]]; then
  echo "release-build: invalid COMMIT '$commit'" >&2
  exit 2
fi
epoch=${SOURCE_DATE_EPOCH:-}
if [[ -z $epoch ]] && $in_git; then epoch=$(git log -1 --format=%ct 2>/dev/null || true); fi
epoch=${epoch:-$(date +%s)}
if [[ ! $epoch =~ ^[0-9]+$ ]]; then
  echo "release-build: invalid SOURCE_DATE_EPOCH '$epoch'" >&2
  exit 2
fi
buildvcs=${BUILDVCS:-$in_git}

# RFC 3339 UTC from epoch, on GNU and BSD date.
build_date=$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ)
touch_stamp=$(date -u -d "@$epoch" +%Y%m%d%H%M.%S 2>/dev/null || date -u -r "$epoch" +%Y%m%d%H%M.%S)

pkg=github.com/aurimasniekis/go-hallpass/internal/buildinfo
ldflags="-s -w -buildid= -X $pkg.Version=$version -X $pkg.Commit=$commit -X $pkg.Date=$build_date"
file_version=${version#v}

gnu_tar=""
for t in gtar tar; do
  if command -v "$t" >/dev/null 2>&1 && "$t" --version 2>/dev/null | grep -q 'GNU tar'; then
    gnu_tar=$t
    break
  fi
done

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

archives=()
# HP-UI-016: release binaries embed the built UI (web/dist) via the embedui build tag.
tags=embedui
if [[ ! -f web/dist/index.html ]]; then
  if [[ "${ALLOW_NO_UI:-}" != "1" ]]; then
    echo "web/dist/index.html missing: run 'pnpm build' in web/ first (or ALLOW_NO_UI=1 for a UI-less build)" >&2
    exit 1
  fi
  tags=
fi

for platform in "${platforms[@]}"; do
  goos=${platform%/*}
  goarch=${platform#*/}
  name="hallpass_${file_version}_${goos}_${goarch}"
  stage="$work/$name"
  mkdir -p "$stage"
  echo "build $platform -> $name.tar.gz" >&2
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch GOFLAGS=-mod=readonly \
    "$go_cmd" build -tags "$tags" -trimpath -buildvcs="$buildvcs" -ldflags "$ldflags" -o "$stage/hallpass" ./cmd/hallpass
  cp deploy/examples/hallpass.example.yaml "$stage/"
  [[ -f deploy/systemd/hallpass.service ]] && cp deploy/systemd/hallpass.service "$stage/"
  [[ -f CHANGELOG.md ]] && cp CHANGELOG.md "$stage/"
  chmod 0755 "$stage/hallpass"
  find "$stage" -type f ! -name hallpass -exec chmod 0644 {} +
  find "$stage" -exec env TZ=UTC touch -h -t "$touch_stamp" {} +

  archive="$out/$name.tar.gz"
  if [[ -n $gnu_tar ]]; then
    (cd "$work" && "$gnu_tar" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
      --format=pax --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
      -cf - "$name") | gzip -n -9 >"$archive"
  else
    (cd "$work" && LC_ALL=C find "$name" -print | LC_ALL=C sort |
      tar --uid 0 --gid 0 --uname '' --gname '' --no-recursion -cf - -T -) | gzip -n -9 >"$archive"
  fi
  archives+=("$(basename "$archive")")
done

(cd "$out" && sha256 "${archives[@]}" >SHA256SUMS)
echo "wrote $out/SHA256SUMS" >&2
cat "$out/SHA256SUMS"
