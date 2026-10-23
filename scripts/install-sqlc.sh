#!/usr/bin/env bash
# Installs the pinned sqlc release binary into bin/ and verifies its SHA-256 (sums computed from the v1.31.1 release).
set -euo pipefail
VERSION="1.31.1"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; esac
case "${os}_${arch}" in
  darwin_amd64) sum=c5af76772e3785d21663a62697056b383f07629979b1bd25b93872e73dbd519b ;;
  darwin_arm64) sum=21602158c99eb1f2bae197a66abfb1941d1e9e50b23125bb193349c6b1acc71e ;;
  linux_amd64) sum=497ae4fcdfa64c5b0c311ffe4c2bd991e43991e82e5367792ed78bc2dca27354 ;;
  linux_arm64) sum=b7cae247740d0c51a1e657479e5b2d21e6fef428f596682a01bc55bf4ab8a23d ;;
  *) echo "unsupported platform ${os}_${arch}" >&2; exit 1 ;;
esac
mkdir -p bin
if [[ -x bin/sqlc ]] && bin/sqlc version | grep -q "v${VERSION}"; then exit 0; fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
file="sqlc_${VERSION}_${os}_${arch}.tar.gz"
curl -fsSL -o "$tmp/$file" "https://github.com/sqlc-dev/sqlc/releases/download/v${VERSION}/${file}"
echo "${sum}  $tmp/$file" | shasum -a 256 -c - >/dev/null
tar -xzf "$tmp/$file" -C "$tmp"
mv "$tmp/sqlc" bin/sqlc
