from __future__ import annotations

from pathlib import Path

from tests.helpers import preview_snapshot_cli2, run_idalib_json, run_preview_json


def test_comment_preview_does_not_persist(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    result = preview_snapshot_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["comment", "show", "main"],
        preview_args=["comment", "set", "main", "preview comment"],
    )
    before = result["before"]
    preview = result["preview"]
    after = result["after_preview"]

    assert isinstance(preview, dict)
    assert preview["before"] == before
    assert preview["after"] == {
        "address": "0x100000460",
        "scope": "line",
        "repeatable": False,
        "comment": "preview comment",
    }
    assert preview["result"]["comment"] == "preview comment"
    assert preview["undo"]["mode"] == "undo"
    assert after == before


def test_type_declare_preview_does_not_persist(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    proc, preview = run_preview_json(
        idac_cmd,
        idac_env,
        database,
        tmp_path / "type-preview.json",
        "type",
        "declare",
        "--decl",
        "typedef struct preview_record { int value; } preview_record;",
    )
    listed = run_idalib_json(idac_cmd, idac_env, database, "type", "list", "preview_record")

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert isinstance(preview, dict)
    assert "preview_record" in preview["result"]["imported_types"]
    assert preview["before"]["type_count"] <= preview["after"]["type_count"]
    assert preview["undo"]["mode"] == "undo"
    assert listed == []
