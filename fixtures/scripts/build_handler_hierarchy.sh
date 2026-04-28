#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT_DIR/fixtures/src/handler_hierarchy.cpp"
OUT_DIR="${FIXTURES_BUILD_DIR:-$ROOT_DIR/fixtures/build}"
BIN="$OUT_DIR/handler_hierarchy"
STRIPPED="$OUT_DIR/handler_hierarchy.stripped"

mkdir -p "$OUT_DIR"

CXX_BIN="${CXX:-c++}"
if ! command -v "$CXX_BIN" >/dev/null 2>&1; then
  echo "compiler not found: $CXX_BIN" >&2
  exit 1
fi

"$CXX_BIN" -std=c++17 -O0 -g -fno-inline -Wall -Wextra "$SRC" -o "$BIN"
cp "$BIN" "$STRIPPED"

if command -v strip >/dev/null 2>&1; then
  strip "$STRIPPED"
else
  echo "note: 'strip' not found; '$STRIPPED' remains unstripped" >&2
fi

echo "built: $BIN"
echo "built: $STRIPPED"
