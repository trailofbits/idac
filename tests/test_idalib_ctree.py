from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import run_idalib, run_idalib_json


def test_idalib_ctree_dump(idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path) -> None:
    database = copy_database(tiny_database)

    result = run_idalib_json(idac_cmd, idac_env, database, "ctree", "main")

    assert isinstance(result, dict)
    assert result["level"] == "ctree"
    assert result["function"] == "main"
    assert "asg" in result["text"]
    assert isinstance(result["nodes"], list)
    assert any(item["op"] == "call" for item in result["nodes"] if isinstance(item, dict))


def test_idalib_microcode_dump(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    out_path = tmp_path / "microcode.json"
    proc = run_idalib(
        idac_cmd,
        idac_env,
        database,
        "ctree",
        "main",
        "--level",
        "micro",
        "--maturity",
        "generated",
        "--out",
        str(out_path),
        use_json=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    result = json.loads(out_path.read_text(encoding="utf-8"))

    assert isinstance(result, dict)
    assert result["level"] == "micro"
    assert result["maturity"] == "generated"
    assert isinstance(result["lines"], list)
    assert any("BLOCK" in line or "mov" in line for line in result["lines"])
