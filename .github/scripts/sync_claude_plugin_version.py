from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} VERSION", file=sys.stderr)
        return 2

    manifest_path = Path("src/idac/skills/idac/.claude-plugin/plugin.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = sys.argv[1]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
