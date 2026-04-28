#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IDAUSR_DIR="${IDAUSR:-$HOME/.idapro}"
PLUGINS_DIR="$IDAUSR_DIR/plugins"

mkdir -p "$PLUGINS_DIR"

BOOTSTRAP_SRC="$ROOT_DIR/src/idac/ida_plugin/idac_bridge_plugin.py"
PACKAGE_SRC="$ROOT_DIR/src/idac/ida_plugin/idac_bridge"
BOOTSTRAP_DST="$PLUGINS_DIR/idac_bridge_plugin.py"
PACKAGE_DST="$PLUGINS_DIR/idac_bridge"

ln -sfn "$BOOTSTRAP_SRC" "$BOOTSTRAP_DST"
rm -rf "$PACKAGE_DST"
ln -s "$PACKAGE_SRC" "$PACKAGE_DST"

echo "installed bootstrap: $BOOTSTRAP_DST -> $BOOTSTRAP_SRC"
echo "installed package:   $PACKAGE_DST -> $PACKAGE_SRC"
echo "start IDA with this repo available at: $ROOT_DIR"
