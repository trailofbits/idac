from __future__ import annotations

from pathlib import Path

from tests.helpers import preview_round_trip_cli2, run_idalib, run_idalib_json, run_idalib_text


def _local_type_map(payload: object) -> dict[str, str]:
    assert isinstance(payload, dict)
    return {item["name"]: item["type"] for item in payload["locals"] if isinstance(item, dict) and item.get("name")}


def _local_names(payload: object) -> set[str]:
    assert isinstance(payload, dict)
    return {item["name"] for item in payload["locals"] if isinstance(item, dict)}


def test_name_set_persists_and_updates_function_metadata_and_decompile(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    before = run_idalib_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    persisted = run_idalib_json(idac_cmd, idac_env, database, "misc", "rename", "add", "add_numbers")
    after_persist = run_idalib_json(idac_cmd, idac_env, database, "function", "metadata", "add_numbers")
    decompiled = run_idalib_text(idac_cmd, idac_env, database, "decompile", "main")

    assert isinstance(before, dict)
    assert before["address"] == "0x1000004b0"
    assert before["name"] == "add"
    assert before["size"] == 32
    assert "add(" in before["prototype"]

    assert isinstance(persisted, dict)
    assert persisted["address"] == "0x1000004b0"
    assert persisted["changed"] is True
    assert persisted["name"] == "add_numbers"
    assert isinstance(after_persist, dict)
    assert after_persist["address"] == "0x1000004b0"
    assert after_persist["name"] == "add_numbers"
    assert after_persist["size"] == before["size"]
    assert "add_numbers(" in after_persist["prototype"]
    assert "add_numbers(2, 3);" in decompiled
    assert "v4 = add_numbers(2, 3);" in decompiled


def test_local_rename_preview_then_persist_updates_local_list_and_decompile(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["function", "locals", "list", "main"],
        preview_args=["function", "locals", "rename", "main", "v4", "--new-name", "sum_preview"],
        persist_args=["function", "locals", "rename", "main", "v4", "--new-name", "sum_value"],
    )
    before = result["before"]
    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]
    decompiled = run_idalib_text(idac_cmd, idac_env, database, "decompile", "main")

    before_names = _local_names(before)
    assert "v4" in before_names

    assert isinstance(preview, dict)
    preview_names = _local_names(preview["after"])
    assert "sum_preview" in preview_names
    assert after_preview == before

    persisted_names = _local_names(persisted)
    after_names = _local_names(after_persist)
    assert "sum_value" in persisted_names
    assert "sum_value" in after_names
    assert "v4" not in after_names
    assert "int sum_value;" in decompiled
    assert "sum_value = add(2, 3);" in decompiled


def test_local_retype_preview_then_persist_updates_local_list_and_decompile(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["function", "locals", "list", "main"],
        persist_args=[
            "function",
            "locals",
            "retype",
            "main",
            "v4",
            "--decl",
            "unsigned int v4;",
        ],
    )
    before = result["before"]
    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]
    decompiled = run_idalib_text(idac_cmd, idac_env, database, "decompile", "main")

    before_types = _local_type_map(before)
    assert before_types["v4"] == "int"

    assert isinstance(preview, dict)
    preview_types = _local_type_map(preview["after"])
    assert preview_types["v4"] == "unsigned int"
    assert after_preview == before

    persisted_types = _local_type_map(persisted)
    after_types = _local_type_map(after_persist)
    assert persisted_types["v4"] == "unsigned int"
    assert after_types["v4"] == "unsigned int"
    assert "unsigned int v4;" in decompiled


def test_local_update_preview_then_persist_updates_name_and_type_together(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["function", "locals", "list", "main"],
        persist_args=[
            "function",
            "locals",
            "update",
            "main",
            "v4",
            "--rename",
            "sum_value",
            "--decl",
            "unsigned int sum_value;",
        ],
    )
    before = result["before"]
    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]
    decompiled = run_idalib_text(idac_cmd, idac_env, database, "decompile", "main")

    before_names = _local_names(before)
    before_types = _local_type_map(before)
    assert "v4" in before_names
    assert before_types["v4"] == "int"

    assert isinstance(preview, dict)
    preview_names = _local_names(preview["after"])
    preview_types = _local_type_map(preview["after"])
    assert "sum_value" in preview_names
    assert preview_types["sum_value"] == "unsigned int"
    assert after_preview == before

    persisted_names = _local_names(persisted)
    persisted_types = _local_type_map(persisted)
    after_names = _local_names(after_persist)
    after_types = _local_type_map(after_persist)
    assert "sum_value" in persisted_names
    assert "sum_value" in after_names
    assert "v4" not in after_names
    assert persisted_types["sum_value"] == "unsigned int"
    assert after_types["sum_value"] == "unsigned int"
    assert "unsigned int sum_value;" in decompiled
    assert "sum_value = add(2, 3);" in decompiled


def test_local_update_requires_at_least_one_change(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    proc = run_idalib(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "function",
        "locals",
        "update",
        "main",
        "v4",
    )

    assert proc.returncode == 1
    assert "at least one of --rename or declaration input is required" in proc.stderr


def test_local_rename_failure_lists_available_locals(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    proc = run_idalib(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "function",
        "locals",
        "rename",
        "main",
        "missing_local",
        "--new-name",
        "sum_value",
    )

    assert proc.returncode == 1
    assert "local variable not found: missing_local" in proc.stderr
    assert "available locals:" in proc.stderr
    assert "v4 (" in proc.stderr
