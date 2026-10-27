from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import (
    normalize_pseudocode_call_arguments,
    preview_round_trip,
    run_nexus,
    run_nexus_json,
    run_nexus_text,
    run_preview_json,
    shutdown_nexus_worker_without_save,
)


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
    before = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    persisted = run_nexus_json(idac_cmd, idac_env, database, "misc", "rename", "add", "add_numbers")
    after_persist = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add_numbers")
    decompiled = normalize_pseudocode_call_arguments(run_nexus_text(idac_cmd, idac_env, database, "decompile", "main"))

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


@pytest.mark.parametrize("original_kind", ["automatic", "hidden", "dummy", "empty"])
def test_name_preview_preserves_original_name_metadata(
    original_kind: str,
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    address = "0x1000004b4" if original_kind == "empty" else "0x1000004b0"
    initial_names = {
        "automatic": "ida_name.set_name(ea, 'automatic_add', ida_name.SN_AUTO | ida_name.SN_PUBLIC | ida_name.SN_WEAK)",
        "hidden": "ida_name.set_name(ea, 'hidden_add', ida_name.SN_NON_AUTO | ida_name.SN_NOLIST)",
        "dummy": "ida_name.set_name(ea, '') and ida_name.set_dummy_name(ea, ea)",
        "empty": "ida_name.set_name(ea, '')",
    }
    metadata_code = f"""
import ida_bytes
import ida_name
ea = {address}
flags = ida_bytes.get_flags(ea)
result = {{
    'name': ida_name.get_name(ea),
    'automatic': ida_bytes.has_auto_name(flags),
    'user': ida_bytes.has_user_name(flags),
    'dummy': ida_bytes.has_dummy_name(flags),
    'public': ida_name.is_public_name(ea),
    'weak': ida_name.is_weak_name(ea),
    'listed': ida_name.is_in_nlist(ea),
}}
"""
    initial = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--code",
        f"import ida_name\nea = {address}\nassert {initial_names[original_kind]}\n" + metadata_code,
    )
    before = initial["result"]
    if original_kind == "automatic":
        assert before["automatic"] is True
        assert before["public"] is True
        assert before["weak"] is True
    elif original_kind == "hidden":
        assert before["user"] is True
        assert before["listed"] is False
    elif original_kind == "dummy":
        assert before["dummy"] is True
    else:
        assert before["name"] == ""

    proc, preview = run_preview_json(
        idac_cmd, idac_env, database, tmp_path / "name-preview.json", "misc", "rename", address, "preview_add"
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert preview["before"] == {"address": address, "name": before["name"]}
    assert preview["after"] == {"address": address, "name": "preview_add"}
    assert preview["undo"] == {"status": "ok", "mode": "rollback", "persisted": False}

    after = run_nexus_json(idac_cmd, idac_env, database, "py", "exec", "--code", metadata_code)
    assert after["result"] == before

    collision = run_nexus(idac_cmd, idac_env, database, "misc", "rename", address, "main")
    assert collision.returncode == 1
    assert "failed to set name" in collision.stderr
    after_failure = run_nexus_json(idac_cmd, idac_env, database, "py", "exec", "--code", metadata_code)
    assert after_failure["result"] == before

    # Saving a subsequent mutation must not make preview-only metadata durable.
    run_nexus_json(idac_cmd, idac_env, database, "comment", "set", address, "checkpoint name metadata")
    shutdown_nexus_worker_without_save(database, idac_env)
    reopened = run_nexus_json(idac_cmd, idac_env, database, "py", "exec", "--code", metadata_code)
    assert reopened["result"] == before


def test_local_rename_preview_then_persist_updates_local_list_and_decompile(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    result = preview_round_trip(
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
    decompiled = normalize_pseudocode_call_arguments(run_nexus_text(idac_cmd, idac_env, database, "decompile", "main"))

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
    result = preview_round_trip(
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
    decompiled = run_nexus_text(idac_cmd, idac_env, database, "decompile", "main")

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
    result = preview_round_trip(
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
    decompiled = normalize_pseudocode_call_arguments(run_nexus_text(idac_cmd, idac_env, database, "decompile", "main"))

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
    proc = run_nexus(
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
    proc = run_nexus(
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
