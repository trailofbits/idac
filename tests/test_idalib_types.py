from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import run_idalib, run_idalib_json

SHARED_TYPE_DECL = (
    "typedef enum test_cli_mode { CLI_MODE_A = 0, CLI_MODE_B = 1 } test_cli_mode;"
    "typedef struct test_cli_record { int value; test_cli_mode mode; } test_cli_record;"
)
ENUM_DECL = "typedef enum test_cli_enum { CLI_ENUM_A = 0 } test_cli_enum;"
REPLACE_STRUCT_DECL_V1 = "typedef struct test_cli_replace { int value; } test_cli_replace;"
REPLACE_STRUCT_DECL_V2 = "typedef struct test_cli_replace { int value; int extra; } test_cli_replace;"
ALIAS_DECL = "struct ns::bad_record { int value; };"
BROKEN_DECL = "typedef struct broken_decl { int value; } broken_decl"
BISECT_DECL = (
    "typedef struct good_one { int value; } good_one;"
    "struct Missing;"
    "typedef struct wrapper_bad { struct Missing value; } wrapper_bad;"
)


def _declare_types(idac_cmd: list[str], idac_env: dict[str, str], database: Path) -> dict[str, object]:
    return run_idalib_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", SHARED_TYPE_DECL])


def _declare_enum(idac_cmd: list[str], idac_env: dict[str, str], database: Path) -> dict[str, object]:
    return run_idalib_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", ENUM_DECL])


def test_idalib_type_declare_and_list(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "list", "test_cli"])
    names = {item.get("name") for item in payload if isinstance(item, dict)}
    assert {"test_cli_mode", "test_cli_record"} <= names


def test_idalib_type_show_includes_members(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_record"])
    assert payload.get("name") == "test_cli_record"
    assert payload.get("kind") == "struct"
    assert payload.get("size_known") is True
    assert isinstance(payload.get("size"), int)
    members = payload.get("members") or []
    assert any(member.get("name") == "mode" for member in members)


def test_idalib_struct_list_and_show(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    list_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "struct", "list", "test_cli"])
    assert any(item.get("name") == "test_cli_record" for item in list_payload if isinstance(item, dict))
    show_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "struct", "show", "test_cli_record"])
    assert show_payload.get("kind") in {"struct", "union"}
    assert "members" in show_payload


def test_idalib_enum_list_and_show(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_enum(idac_cmd, idac_env, database)
    list_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "enum", "list", "test_cli"])
    assert any(item.get("name") == "test_cli_enum" for item in list_payload if isinstance(item, dict))
    show_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "enum", "show", "test_cli_enum"])
    assert show_payload.get("kind") == "enum"
    assert any(member.get("name") == "CLI_ENUM_A" for member in show_payload.get("members") or [])


def test_idalib_type_declare_replace_updates_existing_type(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    first = run_idalib_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", REPLACE_STRUCT_DECL_V1])
    assert first.get("success") is True
    second = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--replace", "--decl", REPLACE_STRUCT_DECL_V2],
    )
    assert second.get("success") is True
    assert "test_cli_replace" in set(second.get("replaced_types") or [])
    show_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_replace"])
    member_names = {member.get("name") for member in show_payload.get("members") or []}
    assert {"value", "extra"} <= member_names


def test_idalib_type_declare_supports_alias_rewrites(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--decl", ALIAS_DECL, "--alias", "ns::bad_record=ns__bad_record"],
    )
    assert payload.get("success") is True
    aliases = payload.get("aliases_applied") or []
    assert any(item.get("from") == "ns::bad_record" and item.get("to") == "ns__bad_record" for item in aliases)
    names = {
        item.get("name") for item in run_idalib_json(idac_cmd, idac_env, database, ["type", "list", "ns__bad_record"])
    }
    assert "ns__bad_record" in names


def test_idalib_type_declare_reports_diagnostics_for_broken_input(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", BROKEN_DECL])
    diagnostics = payload.get("diagnostics") or []
    assert diagnostics
    assert any(item.get("kind") == "unterminated_declaration" for item in diagnostics)


def test_idalib_type_declare_strips_preprocessor_lines_and_comments(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    decl = """
#ifndef TEST_CLI_TYPES_H
#define TEST_CLI_TYPES_H
#include <stdint.h>
// leading comment
typedef struct comment_guard_record {
  int value;
} comment_guard_record; // trailing comment
#endif
"""
    payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", decl])

    assert payload.get("success") is True
    assert payload.get("errors") == 0
    assert payload.get("diagnostics") == []
    assert "comment_guard_record" in set(payload.get("imported_types") or [])


def test_idalib_type_declare_reports_cppobj_and_forward_decl_hints(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    proc = run_idalib(
        idac_cmd,
        idac_env,
        database,
        [
            "type",
            "declare",
            "--decl",
            "struct helper; class __cppobj Broken : helper { int value; };",
        ],
        use_json=True,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    diagnostics = payload.get("diagnostics") or []
    kinds = {item.get("kind") for item in diagnostics}

    assert "cppobj_hint" in kinds
    assert "forward_declaration_hint" in kinds


def test_idalib_type_declare_bisect_reports_first_failing_declaration(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    proc = run_idalib(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--decl", BISECT_DECL, "--bisect"],
        use_json=True,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)

    assert payload.get("success") is False
    bisect = payload.get("bisect") or {}
    failing = bisect.get("failing_declaration") or {}
    diagnostics = payload.get("diagnostics") or []

    assert failing.get("index") == 3
    assert any(item.get("kind") == "bisect_culprit" for item in diagnostics)


def test_idalib_type_declare_bisect_reports_opaque_by_value_member_hint(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    proc = run_idalib(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--decl", BISECT_DECL, "--diagnose"],
        use_json=True,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)

    diagnostics = payload.get("diagnostics") or []
    blocking = (payload.get("bisect") or {}).get("blocking_members") or []

    assert {"type_name": "Missing", "member_name": "value"} in blocking
    assert any(item.get("kind") == "opaque_by_value_member_hint" for item in diagnostics)
