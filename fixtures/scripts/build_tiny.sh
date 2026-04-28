#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT_DIR/fixtures/src/tiny.c"
OUT_DIR="${FIXTURES_BUILD_DIR:-$ROOT_DIR/fixtures/build}"
BIN="$OUT_DIR/tiny"
STRIPPED="$OUT_DIR/tiny.stripped"

mkdir -p "$OUT_DIR"

CC_BIN="${CC:-cc}"
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
  echo "compiler not found: $CC_BIN" >&2
  exit 1
fi

"$CC_BIN" -O0 -g -Wall -Wextra "$SRC" -o "$BIN"
cp "$BIN" "$STRIPPED"

if command -v strip >/dev/null 2>&1; then
  strip "$STRIPPED"
else
  echo "note: 'strip' not found; '$STRIPPED' remains unstripped" >&2
fi

echo "built: $BIN"
echo "built: $STRIPPED"
