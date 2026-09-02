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

fail=0
shopt -s nullglob
for path in "$ROOT"/proto/*.proto; do
  f="$(basename "$path")"
  case "$f" in
    # Macaroon caveat types are not under pb/ upstream.
    caveat.proto) upstream="macaroon/types.proto" ;;
    *) upstream="pb/${f}" ;;
  esac
  url="https://raw.githubusercontent.com/storj/common/${COMMON_SHA}/${upstream}"
  tmp="$(mktemp)"
  if ! curl -fsSL "$url" -o "$tmp"; then
    echo "FETCH FAIL: $url" >&2
    rm -f "$tmp"
    fail=1
    continue
  fi
  if [[ "$f" == caveat.proto ]]; then
    # The vendored caveat.proto deliberately drops the pico import/annotations
    # and lists fields in picobuf *encode* order (see its header comment), so
    # compare the normalized set of field declarations instead of raw bytes.
    norm() {
      grep -E '^[[:space:]]*(repeated[[:space:]]+)?[A-Za-z_.]+[[:space:]]+[A-Za-z_]+[[:space:]]*=[[:space:]]*[0-9]+' "$1" \
        | sed -E 's/\[[^]]*\]//g; s/[[:space:]]+/ /g; s/^ //; s/ ;/;/; s/ *$//' \
        | sort
    }
    if ! cmp -s <(norm "$tmp") <(norm "$path"); then
      echo "DRIFT: proto/$f field set does not match storj/common@${COMMON_SHA} ${upstream}" >&2
      diff <(norm "$tmp") <(norm "$path") >&2 || true
      fail=1
    else
      echo "ok $f (normalized field set)"
    fi
    rm -f "$tmp"
    continue
  fi
  if ! cmp -s "$tmp" "$path"; then
    echo "DRIFT: proto/$f does not match storj/common@${COMMON_SHA} ${upstream}" >&2
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
