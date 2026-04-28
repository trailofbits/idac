from __future__ import annotations

from pathlib import Path

from tests.helpers import preview_round_trip_cli2, run_idalib, run_idalib_json

MUTABLE_STRUCT_DECL = "typedef struct test_cli_mutable {} test_cli_mutable;"
ENUM_DECL = "typedef enum test_cli_enum { CLI_ENUM_A = 0 } test_cli_enum;"


def _member_names(payload: object) -> set[str]:
    assert isinstance(payload, dict)
    return {member["name"] for member in payload.get("members", []) if isinstance(member, dict) and member.get("name")}


def _assert_preview_result(result: dict[str, object], expected_before: object) -> None:
    preview = result["preview"]
    assert isinstance(preview, dict)
    assert result["after_preview"] == expected_before


def test_struct_field_mutations_preview_then_persist_round_trip(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    declared = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "type",
        "declare",
        "--decl",
        MUTABLE_STRUCT_DECL,
    )
    before = run_idalib_json(idac_cmd, idac_env, database, "type", "struct", "show", "test_cli_mutable")

    set_result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["type", "struct", "show", "test_cli_mutable"],
        persist_args=[
            "type",
            "struct",
            "field",
            "set",
            "test_cli_mutable",
            "count",
            "--offset",
            "0",
            "--decl",
            "int count;",
        ],
    )
    rename_result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["type", "struct", "show", "test_cli_mutable"],
        persist_args=["type", "struct", "field", "rename", "test_cli_mutable", "count", "total"],
    )
    delete_result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["type", "struct", "show", "test_cli_mutable"],
        persist_args=["type", "struct", "field", "delete", "test_cli_mutable", "total"],
    )

    assert isinstance(declared, dict)
    assert declared["success"] is True
    assert isinstance(before, dict)
    assert before["name"] == "test_cli_mutable"
    assert before["kind"] == "struct"
    assert before["members"] == []
    assert "struct test_cli_mutable" in before["layout"]

    _assert_preview_result(set_result, before)
    assert set_result["preview"]["before"] == before
    assert _member_names(set_result["preview"]["after"]) == {"count"}
    assert _member_names(set_result["persisted"]) == {"count"}
    assert _member_names(set_result["after_persist"]) == {"count"}

    _assert_preview_result(rename_result, set_result["after_persist"])
    assert _member_names(rename_result["preview"]["after"]) == {"total"}
    assert _member_names(rename_result["after_preview"]) == {"count"}
    assert _member_names(rename_result["persisted"]) == {"total"}
    assert _member_names(rename_result["after_persist"]) == {"total"}

    _assert_preview_result(delete_result, rename_result["after_persist"])
    assert _member_names(delete_result["preview"]["after"]) == set()
    assert _member_names(delete_result["after_preview"]) == {"total"}
    assert _member_names(delete_result["persisted"]) == set()
    assert isinstance(delete_result["after_persist"], dict)
    assert delete_result["after_persist"]["members"] == []
    assert "struct test_cli_mutable" in delete_result["after_persist"]["layout"]


def test_enum_member_mutations_preview_then_persist_round_trip(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    declared = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "type",
        "declare",
        "--decl",
        ENUM_DECL,
    )
    before = run_idalib_json(idac_cmd, idac_env, database, "type", "enum", "show", "test_cli_enum")

    set_result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["type", "enum", "show", "test_cli_enum"],
        persist_args=[
            "type",
            "enum",
            "member",
            "set",
            "test_cli_enum",
            "CLI_ENUM_B",
            "--value",
            "1",
            "--mask",
            "0",
        ],
    )
    rename_result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["type", "enum", "show", "test_cli_enum"],
        persist_args=[
            "type",
            "enum",
            "member",
            "rename",
            "test_cli_enum",
            "CLI_ENUM_B",
            "CLI_ENUM_ALT",
        ],
    )
    delete_result = preview_round_trip_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["type", "enum", "show", "test_cli_enum"],
        persist_args=["type", "enum", "member", "delete", "test_cli_enum", "CLI_ENUM_ALT"],
    )

    assert isinstance(declared, dict)
    assert declared["success"] is True
    assert _member_names(before) == {"CLI_ENUM_A"}

    _assert_preview_result(set_result, before)
    assert _member_names(set_result["preview"]["after"]) == {"CLI_ENUM_A", "CLI_ENUM_B"}
    assert _member_names(set_result["persisted"]) == {"CLI_ENUM_A", "CLI_ENUM_B"}
    assert _member_names(set_result["after_persist"]) == {"CLI_ENUM_A", "CLI_ENUM_B"}

    _assert_preview_result(rename_result, set_result["after_persist"])
    assert _member_names(rename_result["preview"]["after"]) == {"CLI_ENUM_A", "CLI_ENUM_ALT"}
    assert _member_names(rename_result["after_preview"]) == {"CLI_ENUM_A", "CLI_ENUM_B"}
    assert _member_names(rename_result["persisted"]) == {"CLI_ENUM_A", "CLI_ENUM_ALT"}
    assert _member_names(rename_result["after_persist"]) == {"CLI_ENUM_A", "CLI_ENUM_ALT"}

    _assert_preview_result(delete_result, rename_result["after_persist"])
    assert _member_names(delete_result["preview"]["after"]) == {"CLI_ENUM_A"}
    assert _member_names(delete_result["after_preview"]) == {"CLI_ENUM_A", "CLI_ENUM_ALT"}
    assert _member_names(delete_result["persisted"]) == {"CLI_ENUM_A"}
    assert _member_names(delete_result["after_persist"]) == {"CLI_ENUM_A"}


def test_enum_member_set_uses_sdk_default_mask_when_unspecified(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    declared = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "type",
        "declare",
        "--decl",
        ENUM_DECL,
    )
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "type",
        "enum",
        "member",
        "set",
        "test_cli_enum",
        "CLI_ENUM_B",
        "--value",
        "1",
    )
    members = {member.get("name") for member in payload.get("members") or [] if isinstance(member, dict)}
    assert isinstance(declared, dict)
    assert declared["success"] is True
    assert {"CLI_ENUM_A", "CLI_ENUM_B"} <= members


def test_struct_field_delete_reports_missing_member(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(idac_cmd, idac_env, database, "type", "declare", "--decl", MUTABLE_STRUCT_DECL)

    proc = run_idalib(
        idac_cmd,
        idac_env,
        database,
        "type",
        "struct",
        "field",
        "delete",
        "test_cli_mutable",
        "missing_field",
    )

    assert proc.returncode == 1
    assert "struct field not found: test_cli_mutable.missing_field" in proc.stderr


def test_struct_field_set_reports_unknown_type(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(idac_cmd, idac_env, database, "type", "declare", "--decl", MUTABLE_STRUCT_DECL)

    proc = run_idalib(
        idac_cmd,
        idac_env,
        database,
        "type",
        "struct",
        "field",
        "set",
        "test_cli_mutable",
        "count",
        "--offset",
        "0",
        "--decl",
        "MissingType count;",
        use_json=True,
    )

    assert proc.returncode == 1
    assert "failed to parse member type: MissingType count;" in proc.stderr


def test_enum_member_delete_reports_missing_member(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(idac_cmd, idac_env, database, "type", "declare", "--decl", ENUM_DECL)

    proc = run_idalib(
        idac_cmd,
        idac_env,
        database,
        "type",
        "enum",
        "member",
        "delete",
        "test_cli_enum",
        "CLI_ENUM_MISSING",
    )

    assert proc.returncode == 1
    assert "failed to delete enum member" in proc.stderr
