#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${FIXTURES_BUILD_DIR:-$ROOT_DIR/fixtures/build}"
IDB_DIR="${FIXTURES_IDB_DIR:-$ROOT_DIR/fixtures/idb}"
IDA_BIN="${IDA_IDAT:-/Applications/IDA Professional 9.3.app/Contents/MacOS/idat}"

mkdir -p "$IDB_DIR"

if ! command -v "$IDA_BIN" >/dev/null 2>&1; then
  echo "idat not found: $IDA_BIN" >&2
  exit 1
fi

run_idat() {
  local input="$1"
  local output="$2"
  local log="$3"
  "$IDA_BIN" -A -c "-L$log" "-o$output" "$input"
}

run_idat "$BIN_DIR/handler_hierarchy" "$IDB_DIR/handler_hierarchy.i64" "$IDB_DIR/handler_hierarchy.log"
run_idat "$BIN_DIR/handler_hierarchy.stripped" "$IDB_DIR/handler_hierarchy_stripped.i64" "$IDB_DIR/handler_hierarchy_stripped.log"

echo "generated: $IDB_DIR/handler_hierarchy.i64"
echo "generated: $IDB_DIR/handler_hierarchy_stripped.i64"
