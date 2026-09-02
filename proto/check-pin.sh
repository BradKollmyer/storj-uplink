#!/usr/bin/env bash
# Fail if vendored proto files differ from the SHAs in proto/README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
README="$ROOT/proto/README.md"

COMMON_SHA="$(sed -n 's/^STORJ_COMMON_SHA=//p' "$README" | head -1 | tr -d '[:space:]')"
UPLINK_SHA="$(sed -n 's/^STORJ_UPLINK_SHA=//p' "$README" | head -1 | tr -d '[:space:]')"

if [[ -z "$COMMON_SHA" || -z "$UPLINK_SHA" ]]; then
  echo "failed to parse STORJ_COMMON_SHA / STORJ_UPLINK_SHA from proto/README.md" >&2
  exit 1
fi

echo "pin storj/common=$COMMON_SHA"
echo "pin storj/uplink=$UPLINK_SHA"

FILES=(
  metainfo.proto
  piecestore2.proto
  orders.proto
  encryption.proto
  node.proto
  noise.proto
  pointerdb.proto
  gogo.proto
)

fail=0
for f in "${FILES[@]}"; do
  url="https://raw.githubusercontent.com/storj/common/${COMMON_SHA}/pb/${f}"
  tmp="$(mktemp)"
  if ! curl -fsSL "$url" -o "$tmp"; then
    echo "FETCH FAIL: $url" >&2
    rm -f "$tmp"
    fail=1
    continue
  fi
  if ! cmp -s "$tmp" "$ROOT/proto/$f"; then
    echo "DRIFT: proto/$f does not match storj/common@${COMMON_SHA} pb/$f" >&2
    fail=1
  else
    echo "ok $f"
  fi
  rm -f "$tmp"
done

gomod="$(mktemp)"
if ! curl -fsSL "https://raw.githubusercontent.com/storj/uplink/${UPLINK_SHA}/go.mod" -o "$gomod"; then
  echo "FETCH FAIL: storj/uplink@${UPLINK_SHA} go.mod" >&2
  rm -f "$gomod"
  exit 1
fi
prefix="$(printf '%s' "$COMMON_SHA" | cut -c1-12)"
if ! grep -q "storj.io/common .*${prefix}" "$gomod"; then
  echo "DRIFT: storj/uplink@${UPLINK_SHA} go.mod does not pin storj.io/common @ ${prefix}" >&2
  fail=1
else
  echo "ok uplink go.mod common pin ${prefix}"
fi
rm -f "$gomod"

exit "$fail"
