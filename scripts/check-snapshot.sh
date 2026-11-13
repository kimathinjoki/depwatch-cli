#!/usr/bin/env bash
# Checks a `make snapshot` build: six binaries, a checksums file that matches them, and a stamped
# version in the binary for this machine.
set -euo pipefail
cd "$(dirname "$0")/.."

bins=$(find dist -type f \( -name depwatch -o -name depwatch.exe \) | sort)
count=$(echo "$bins" | grep -c . || true)
if [ "$count" -ne 6 ]; then
  echo "want 6 binaries, found $count:"; echo "$bins"; exit 1
fi
test -f dist/checksums.txt || { echo "dist/checksums.txt is missing"; exit 1; }
(cd dist && sha256sum --check --quiet checksums.txt) || { echo "checksums do not match"; exit 1; }

os=$(go env GOOS); arch=$(go env GOARCH)
bin=$(echo "$bins" | grep "_${os}_${arch}" | head -1)
out=$("$bin" version)
case "$out" in
  *snapshot*) echo "ok: $count binaries, checksums match, $bin prints: $out" ;;
  *) echo "the version is not stamped: $out"; exit 1 ;;
esac
