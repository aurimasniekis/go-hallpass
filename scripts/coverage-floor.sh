#!/usr/bin/env bash
# Enforce the statement-coverage floor for security-critical packages (HP-TST-009).
# Packages that do not exist yet are skipped and reported, so the floor applies as soon as a package lands.
set -euo pipefail

FLOOR="${COVERAGE_FLOOR:-80}"
MODULE="github.com/aurimasniekis/go-hallpass"
PACKAGES=(
  internal/policy
  internal/access
  internal/keyring
  internal/recording
  internal/recording/hprec
  internal/sshfront/grammar
  internal/opauth
)

fail=0
for pkg in "${PACKAGES[@]}"; do
  if [[ ! -d "$pkg" ]]; then
    echo "skip  $pkg (not present yet)"
    continue
  fi
  out=$(go test -count=1 -cover "./$pkg" 2>&1) || { echo "$out"; echo "FAIL  $pkg (tests failed)"; fail=1; continue; }
  pct=$(sed -nE 's/.*coverage: ([0-9.]+)% of statements.*/\1/p' <<<"$out" | head -1)
  if [[ -z "$pct" ]]; then
    echo "FAIL  $pkg (no coverage reported)"
    fail=1
    continue
  fi
  if awk -v p="$pct" -v f="$FLOOR" 'BEGIN { exit !(p + 0 < f + 0) }'; then
    echo "FAIL  $MODULE/$pkg ${pct}% < ${FLOOR}%"
    fail=1
  else
    echo "ok    $MODULE/$pkg ${pct}%"
  fi
done
exit "$fail"
