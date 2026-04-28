from __future__ import annotations

from pathlib import Path

from tests.helpers import run_idalib_json


def test_idalib_local_list(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(idac_cmd, idac_env, copy_database(tiny_database), "function", "locals", "list", "main")
    assert isinstance(payload, dict)
    assert payload["function"] == "main"
    locals_rows = payload["locals"]
    assert any(item["name"] == "argc" for item in locals_rows if isinstance(item, dict))
    assert any(item["name"] == "v4" and item["is_stack"] for item in locals_rows if isinstance(item, dict))
    assert all(item.get("local_id") for item in locals_rows if isinstance(item, dict))
    assert any("@" in item["local_id"] for item in locals_rows if isinstance(item, dict))


def test_idalib_local_rename_and_retype(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    listed = run_idalib_json(idac_cmd, idac_env, database, "function", "locals", "list", "main")
    target = next(item for item in listed["locals"] if isinstance(item, dict) and item.get("name") == "v4")

    renamed_by_index = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "rename",
        "main",
        "--index",
        str(target["index"]),
        "--new-name",
        "sum_value",
    )
    assert isinstance(renamed_by_index, dict)
    assert any(item["name"] == "sum_value" for item in renamed_by_index["locals"] if isinstance(item, dict))

    renamed = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "rename",
        "main",
        "--local-id",
        target["local_id"],
        "--new-name",
        "sum_value_2",
    )
    assert isinstance(renamed, dict)
    assert any(item["name"] == "sum_value_2" for item in renamed["locals"] if isinstance(item, dict))

    renamed = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "rename",
        "main",
        "--local-id",
        target["local_id"],
        "--new-name",
        "sum_value_3",
    )
    assert isinstance(renamed, dict)
    assert any(item["name"] == "sum_value_3" for item in renamed["locals"] if isinstance(item, dict))

    retyped = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "retype",
        "main",
        "--index",
        str(target["index"]),
        "--decl",
        "unsigned int sum_value;",
    )
    assert isinstance(retyped, dict)
    target = next(item for item in retyped["locals"] if isinstance(item, dict) and item["name"] == "sum_value_3")
    assert target["type"] == "unsigned int"


def test_idalib_local_update_accepts_stable_selectors_without_positional_selector(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    listed = run_idalib_json(idac_cmd, idac_env, database, "function", "locals", "list", "main")
    target = next(item for item in listed["locals"] if isinstance(item, dict) and item.get("name") == "v4")

    updated = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "update",
        "main",
        "--local-id",
        target["local_id"],
        "--rename",
        "sum_value",
        "--decl",
        "unsigned int sum_value;",
    )
    assert isinstance(updated, dict)
    renamed = next(item for item in updated["locals"] if isinstance(item, dict) and item["name"] == "sum_value")
    assert renamed["type"] == "unsigned int"

    updated = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "update",
        "main",
        "--index",
        str(target["index"]),
        "--rename",
        "sum_value_2",
    )
    assert isinstance(updated, dict)
    assert any(item["name"] == "sum_value_2" for item in updated["locals"] if isinstance(item, dict))


def test_idalib_local_rename_accepts_stable_selector_without_positional_selector(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    listed = run_idalib_json(idac_cmd, idac_env, database, "function", "locals", "list", "main")
    target = next(item for item in listed["locals"] if isinstance(item, dict) and item.get("name") == "v4")

    renamed = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "rename",
        "main",
        "--index",
        str(target["index"]),
        "--new-name",
        "sum_value",
    )
    assert isinstance(renamed, dict)
    assert any(item["name"] == "sum_value" for item in renamed["locals"] if isinstance(item, dict))


def test_idalib_local_retype_accepts_stable_selector_without_positional_selector(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    listed = run_idalib_json(idac_cmd, idac_env, database, "function", "locals", "list", "main")
    target = next(item for item in listed["locals"] if isinstance(item, dict) and item.get("name") == "v4")

    retyped = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "retype",
        "main",
        "--local-id",
        target["local_id"],
        "--decl",
        "unsigned int v4;",
    )
    assert isinstance(retyped, dict)
    updated = next(
        item for item in retyped["locals"] if isinstance(item, dict) and item["local_id"] == target["local_id"]
    )
    assert updated["type"] == "unsigned int"


def test_idalib_local_retype_accepts_type_shorthand(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    listed = run_idalib_json(idac_cmd, idac_env, database, "function", "locals", "list", "main")
    target = next(item for item in listed["locals"] if isinstance(item, dict) and item.get("name") == "v4")

    retyped = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "locals",
        "retype",
        "main",
        "--index",
        str(target["index"]),
        "--type",
        "unsigned int",
    )
    assert isinstance(retyped, dict)
    updated = next(
        item for item in retyped["locals"] if isinstance(item, dict) and item["local_id"] == target["local_id"]
    )
    assert updated["type"] == "unsigned int"
