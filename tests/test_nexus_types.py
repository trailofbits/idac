from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers import run_nexus, run_nexus_json

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
    return run_nexus_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", SHARED_TYPE_DECL])


def _declare_enum(idac_cmd: list[str], idac_env: dict[str, str], database: Path) -> dict[str, object]:
    return run_nexus_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", ENUM_DECL])


def test_nexus_type_declare_and_list(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "test_cli"])
    names = {item.get("name") for item in payload if isinstance(item, dict)}
    assert {"test_cli_mode", "test_cli_record"} <= names


@pytest.mark.parametrize("clang", [False, True])
def test_nexus_type_check_resolves_header_dependencies_without_importing(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path, clang: bool
) -> None:
    database = copy_database(tiny_database)
    decl = (
        "enum check_mode { CHECK_A = 1, CHECK_B = 2 };"
        "struct check_record { enum check_mode mode; unsigned length; const char *data; };"
    )
    args = ["type", "check", "--decl", decl]
    if clang:
        args.append("--clang")
    checked = run_nexus_json(idac_cmd, idac_env, database, args)
    assert checked["success"] is True
    assert checked["errors"] == 0
    assert run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "check_"]) == []


@pytest.mark.parametrize("forward_decl", ["", "struct test_cli_record; "])
def test_nexus_type_check_resolves_existing_types_and_preserves_them_on_failure(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    ida_version: tuple[int, int],
    copy_database,
    tiny_database: Path,
    forward_decl: str,
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    before = run_nexus_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_record"])
    check_proc = run_nexus(
        idac_cmd,
        idac_env,
        database,
        ["type", "check", "--decl", forward_decl + "struct check_wrapper { test_cli_record record; };"],
        use_json=True,
    )
    checked = json.loads(check_proc.stdout)
    if forward_decl and ida_version >= (9, 5):
        assert check_proc.returncode == 1
        assert checked["success"] is False
        assert checked["errors"] == 1
    else:
        assert check_proc.returncode == 0, check_proc.stderr
        assert checked["success"] is True
    proc = run_nexus(
        idac_cmd,
        idac_env,
        database,
        [
            "type",
            "check",
            "--decl",
            "struct test_cli_record { long long changed; }; struct invalid { Missing value; };",
        ],
        use_json=True,
    )
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["success"] is False
    assert run_nexus_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_record"]) == before
    assert run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "check_wrapper"]) == []


@pytest.mark.parametrize("clang", [False, True])
@pytest.mark.parametrize("other_type", ["test_cli_mode", "test_cli_sibling"])
def test_nexus_type_check_deduplicates_shared_dependencies(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    clang: bool,
    other_type: str,
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    run_nexus_json(
        idac_cmd, idac_env, database, ["type", "declare", "--decl", "struct test_cli_sibling { test_cli_mode mode; };"]
    )
    before = run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "test_cli"])
    args = ["type", "check", "--decl", f"struct check_wrapper {{ test_cli_record record; {other_type} other; }};"]
    if clang:
        args.append("--clang")

    checked = run_nexus_json(idac_cmd, idac_env, database, args)

    assert checked["success"] is True
    assert checked["errors"] == 0
    assert run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "test_cli"]) == before
    assert run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "check_wrapper"]) == []


def test_nexus_type_show_includes_members(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_record"])
    assert payload.get("name") == "test_cli_record"
    assert payload.get("kind") == "struct"
    assert payload.get("size_known") is True
    assert isinstance(payload.get("size"), int)
    members = payload.get("members") or []
    assert any(member.get("name") == "mode" for member in members)


def test_nexus_struct_list_and_show(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_types(idac_cmd, idac_env, database)
    list_payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "struct", "list", "test_cli"])
    assert any(item.get("name") == "test_cli_record" for item in list_payload if isinstance(item, dict))
    show_payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "struct", "show", "test_cli_record"])
    assert show_payload.get("kind") in {"struct", "union"}
    assert "members" in show_payload


def test_nexus_enum_list_and_show(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    _declare_enum(idac_cmd, idac_env, database)
    list_payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "enum", "list", "test_cli"])
    assert any(item.get("name") == "test_cli_enum" for item in list_payload if isinstance(item, dict))
    show_payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "enum", "show", "test_cli_enum"])
    assert show_payload.get("kind") == "enum"
    assert any(member.get("name") == "CLI_ENUM_A" for member in show_payload.get("members") or [])


@pytest.mark.parametrize("clang", [False, True])
def test_nexus_type_declare_replace_updates_existing_type(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path, clang: bool
) -> None:
    database = copy_database(tiny_database)
    first = run_nexus_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", REPLACE_STRUCT_DECL_V1])
    assert first.get("success") is True
    second = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--replace", "--decl", REPLACE_STRUCT_DECL_V2, *(["--clang"] if clang else [])],
    )
    assert second.get("success") is True
    assert "test_cli_replace" in set(second.get("replaced_types") or [])
    show_payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_replace"])
    member_names = {member.get("name") for member in show_payload.get("members") or []}
    assert {"value", "extra"} <= member_names


def test_nexus_type_declare_clang_replace_preserves_dependent_types_and_prototypes(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        [
            "type",
            "declare",
            "--decl",
            "struct test_cli_replace { int value; };struct test_cli_dependent { struct test_cli_replace record; };",
        ],
    )
    run_nexus_json(idac_cmd, idac_env, database, ["function", "prototype", "show", "main"])
    run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        ["function", "prototype", "set", "main", "--decl", "int main(struct test_cli_replace *record);"],
    )
    reference_snapshot_code = """
import ida_nalt
import ida_typeinf
import idc
result = {}
for name in ("test_cli_replace", "test_cli_dependent"):
    tif = ida_typeinf.tinfo_t()
    assert tif.get_named_type(None, name)
    result[name] = {"ordinal": tif.get_ordinal(), "size": tif.get_size()}
prototype = ida_typeinf.tinfo_t()
assert ida_nalt.get_tinfo(prototype, idc.get_name_ea_simple("main"))
details = ida_typeinf.func_type_data_t()
assert prototype.get_func_details(details)
record = details[0].type.get_pointed_object()
result["prototype_record"] = {"ordinal": record.get_ordinal(), "size": record.get_size()}
"""
    before = run_nexus_json(idac_cmd, idac_env, database, ["py", "exec", "--code", reference_snapshot_code])["result"]
    replaced = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--clang", "--replace", "--decl", "struct test_cli_replace { long long value; };"],
    )
    assert replaced["success"] is True
    after = run_nexus_json(idac_cmd, idac_env, database, ["py", "exec", "--code", reference_snapshot_code])["result"]
    for name, reference in before.items():
        assert reference["ordinal"] > 0
        assert reference["size"] == 4
        assert after[name] == {"ordinal": reference["ordinal"], "size": 8}
    dependent = run_nexus_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_dependent"])
    assert dependent["size_known"] is True
    assert dependent["size"] == 8
    assert dependent["members"][0]["name"] == "record"
    assert dependent["members"][0]["size"] == 8
    assert "test_cli_replace" in dependent["members"][0]["type"]


@pytest.mark.parametrize("bisect", [False, True])
def test_nexus_type_declare_clang_replace_failure_restores_existing_and_new_types(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path, bisect: bool
) -> None:
    database = copy_database(tiny_database)
    run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        [
            "type",
            "declare",
            "--decl",
            "struct test_cli_replace { int value; };struct test_cli_dependent { struct test_cli_replace record; };",
        ],
    )
    before = run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "test_cli_"])
    dependent_before = run_nexus_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_dependent"])
    failed = run_nexus(
        idac_cmd,
        idac_env,
        database,
        [
            "type",
            "declare",
            "--clang",
            "--replace",
            "--decl",
            "struct test_cli_replace { long long value; };"
            "struct test_cli_new { int value; };"
            "struct test_cli_invalid { Missing value; };",
            *(["--bisect"] if bisect else []),
        ],
        use_json=True,
    )
    assert failed.returncode == 1
    assert json.loads(failed.stdout)["success"] is False
    assert run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "test_cli_"]) == before
    assert run_nexus_json(idac_cmd, idac_env, database, ["type", "show", "test_cli_dependent"]) == dependent_before


def test_nexus_type_declare_supports_alias_rewrites(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    payload = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--decl", ALIAS_DECL, "--alias", "ns::bad_record=ns__bad_record"],
    )
    assert payload.get("success") is True
    aliases = payload.get("aliases_applied") or []
    assert any(item.get("from") == "ns::bad_record" and item.get("to") == "ns__bad_record" for item in aliases)
    names = {
        item.get("name") for item in run_nexus_json(idac_cmd, idac_env, database, ["type", "list", "ns__bad_record"])
    }
    assert "ns__bad_record" in names


def test_nexus_type_declare_reports_diagnostics_for_broken_input(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", BROKEN_DECL])
    diagnostics = payload.get("diagnostics") or []
    assert diagnostics
    assert any(item.get("kind") == "unterminated_declaration" for item in diagnostics)


def test_nexus_type_declare_strips_preprocessor_lines_and_comments(
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
    payload = run_nexus_json(idac_cmd, idac_env, database, ["type", "declare", "--decl", decl])

    assert payload.get("success") is True
    assert payload.get("errors") == 0
    assert payload.get("diagnostics") == []
    assert "comment_guard_record" in set(payload.get("imported_types") or [])


def test_nexus_type_declare_reports_cppobj_and_forward_decl_hints(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    proc = run_nexus(
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


def test_nexus_type_declare_bisect_reports_first_failing_declaration(
    idac_cmd: list[str], idac_env: dict[str, str], copy_database, tiny_database: Path
) -> None:
    database = copy_database(tiny_database)
    proc = run_nexus(
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
    blocking = bisect.get("blocking_members") or []

    assert failing.get("index") == 3
    assert any(item.get("kind") == "bisect_culprit" for item in diagnostics)
    assert {"type_name": "Missing", "member_name": "value"} in blocking
    assert any(item.get("kind") == "opaque_by_value_member_hint" for item in diagnostics)
