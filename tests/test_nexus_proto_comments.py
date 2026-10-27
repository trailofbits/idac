from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers import (
    normalize_pseudocode_call_arguments,
    preview_round_trip,
    run_nexus,
    run_nexus_json,
    run_nexus_text,
    shutdown_nexus_worker_without_save,
)


def test_comment_delete_preview_then_persist(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    seeded = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "comment",
        "set",
        "main",
        "entry point",
    )
    result = preview_round_trip(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["comment", "show", "main"],
        persist_args=["comment", "delete", "main"],
    )
    preview = result["preview"]
    after_preview = result["after_preview"]
    deleted = result["persisted"]
    after_delete = result["after_persist"]

    assert isinstance(seeded, dict)
    assert seeded["comment"] == "entry point"

    assert isinstance(preview, dict)
    assert preview["before"]["comment"] == "entry point"
    assert preview["after"]["comment"] is None
    assert after_preview["comment"] == "entry point"

    assert isinstance(deleted, dict)
    assert deleted["address"] == "0x100000460"
    assert deleted["comment"] is None
    assert deleted["changed"] is True
    assert after_delete["address"] == "0x100000460"
    assert after_delete["comment"] is None


def test_function_comment_repeatable_round_trip(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)

    seeded = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "comment",
        "set",
        "main",
        "function banner",
        "--scope",
        "function",
        "--repeatable",
    )
    shown = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "comment",
        "show",
        "main",
        "--scope",
        "function",
        "--repeatable",
    )
    deleted = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "comment",
        "delete",
        "main",
        "--scope",
        "function",
        "--repeatable",
    )

    assert seeded["scope"] == "function"
    assert seeded["repeatable"] is True
    assert seeded["comment"] == "function banner"
    assert shown["scope"] == "function"
    assert shown["repeatable"] is True
    assert shown["comment"] == "function banner"
    assert deleted["comment"] is None


def test_anterior_comment_preview_then_persist(
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
        read_args=["comment", "show", "main", "--anterior"],
        persist_args=["comment", "set", "main", "line one\nline two", "--anterior"],
    )
    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]

    assert preview["before"]["comment"] is None
    assert preview["after"]["scope"] == "anterior"
    assert preview["after"]["repeatable"] is False
    assert preview["after"]["comment"] == "line one\nline two"
    assert after_preview["comment"] is None
    assert persisted["scope"] == "anterior"
    assert persisted["comment"] == "line one\nline two"
    assert after_persist["comment"] == "line one\nline two"


def test_proto_set_preview_then_persist_updates_proto_get(
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
        read_args=["function", "prototype", "show", "add"],
        persist_args=[
            "function",
            "prototype",
            "set",
            "add",
            "--decl",
            "long long __cdecl add(long long a, long long b)",
        ],
    )
    before = result["before"]
    preview = result["preview"]
    after_preview = result["after_preview"]
    persisted = result["persisted"]
    after_persist = result["after_persist"]

    assert isinstance(before, dict)
    assert before["address"] == "0x1000004b0"
    assert "add(" in before["prototype"]

    assert isinstance(preview, dict)
    assert preview["before"]["address"] == before["address"]
    assert preview["before"]["prototype"] == before["prototype"]
    assert preview["after"]["address"] == "0x1000004b0"
    assert "add(" in preview["after"]["prototype"]
    assert preview["after"]["prototype"] == preview["result"]["prototype"]
    assert preview["after"]["prototype"] != before["prototype"]
    assert isinstance(preview["before"]["decompile"], str)
    assert isinstance(preview["after"]["decompile"], str)
    assert preview["after"]["decompile"] != preview["before"]["decompile"]
    assert "add(" in preview["after"]["decompile"]
    assert after_preview == before

    assert isinstance(persisted, dict)
    assert persisted["address"] == "0x1000004b0"
    assert persisted["changed"] is True
    assert persisted["prototype"] == preview["result"]["prototype"]
    assert isinstance(after_persist, dict)
    assert after_persist["address"] == "0x1000004b0"
    assert after_persist["prototype"] == preview["result"]["prototype"]


def test_proto_set_preserves_calling_convention_in_preview_and_saved_type(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    result = preview_round_trip(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        tmp_path,
        read_args=["function", "prototype", "show", "add"],
        persist_args=[
            "function",
            "prototype",
            "set",
            "add",
            "--preserve-cc",
            "--decl",
            "int __cdecl add(int left, int right);",
        ],
    )
    assert "__cdecl" in result["before"]["prototype"]
    assert result["after_preview"] == result["before"]
    expected = "int __cdecl add(int left, int right)"
    assert result["preview"]["after"]["prototype"] == expected
    assert result["after_persist"]["prototype"] == expected


@pytest.mark.parametrize("convention", ["__usercall", "__userpurge"])
@pytest.mark.parametrize("return_type", ["int", "void"])
def test_proto_set_preserves_custom_locations_in_preview_and_saved_type(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
    convention: str,
    return_type: str,
) -> None:
    database = copy_database(tiny_database)
    run_nexus_json(idac_cmd, idac_env, database, "function", "prototype", "show", "add")
    return_location = "@<W3>" if return_type == "int" else ""
    original = f"{return_type} {convention} add{return_location}(int a@<W1>, int b@<W2>)"
    seeded = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "prototype",
        "set",
        "add",
        "--decl",
        original + ";",
    )
    updated_return = "unsigned int" if return_type == "int" else "void"
    result = preview_round_trip(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=["function", "prototype", "show", "add"],
        persist_args=[
            "function",
            "prototype",
            "set",
            "add",
            "--preserve-cc",
            "--decl",
            f"{updated_return} add(unsigned int left, unsigned int right);",
        ],
    )

    assert seeded["prototype"] == original
    assert result["before"]["prototype"] == original
    assert result["after_preview"] == result["before"]
    expected = f"{updated_return} {convention} add{return_location}(unsigned int left@<W1>, unsigned int right@<W2>)"
    assert result["preview"]["after"]["prototype"] == expected
    assert result["persisted"]["prototype"] == expected
    assert result["after_persist"]["prototype"] == expected

    shutdown_nexus_worker_without_save(database, idac_env)
    reopened = run_nexus_json(idac_cmd, idac_env, database, "function", "prototype", "show", "add")
    assert reopened == result["after_persist"]


@pytest.mark.parametrize(
    ("return_type", "declaration", "diagnostic"),
    [
        ("int", "int add(int left);", "same parameter count"),
        ("int", "int add(long long left, int right);", "parameter 1 requires the same type size"),
        ("int", "long long add(int left, int right);", "same return type size"),
        ("int", "void add(int left, int right);", "same return type size"),
        ("void", "int add(int left, int right);", "same return type size"),
    ],
)
def test_proto_set_rejects_incompatible_custom_locations_without_mutation(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    return_type: str,
    declaration: str,
    diagnostic: str,
) -> None:
    database = copy_database(tiny_database)
    run_nexus_json(idac_cmd, idac_env, database, "function", "prototype", "show", "add")
    return_location = "@<W3>" if return_type == "int" else ""
    run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "prototype",
        "set",
        "add",
        "--decl",
        f"{return_type} __usercall add{return_location}(int a@<W1>, int b@<W2>);",
    )
    before = run_nexus_json(idac_cmd, idac_env, database, "function", "prototype", "show", "add")
    rejected = run_nexus(
        idac_cmd,
        idac_env,
        database,
        "function",
        "prototype",
        "set",
        "add",
        "--preserve-cc",
        "--decl",
        declaration,
    )
    after = run_nexus_json(idac_cmd, idac_env, database, "function", "prototype", "show", "add")

    assert rejected.returncode == 1
    assert "cannot preserve calling convention" in rejected.stderr
    assert diagnostic in rejected.stderr
    assert "without --preserve-cc" in rejected.stderr
    assert after == before


def test_proto_check_accepts_valid_fixture_declaration(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_nexus_json(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "function",
        "prototype",
        "check",
        "add",
        "--decl",
        "long long __cdecl add(long long a, long long b)",
    )

    assert payload["address"] == "0x1000004b0"
    assert payload["success"] is True
    assert payload["parsed"] is True
    assert payload["is_function"] is True
    assert payload["diagnostics"] == []


def test_proto_check_rejects_invalid_fixture_declaration(
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
        "prototype",
        "check",
        "add",
        "--decl",
        "int __cdecl add(",
        use_json=True,
    )

    assert proc.returncode == 1
    assert "function prototype check failed:" in proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["address"] == "0x1000004b0"
    assert payload["success"] is False
    assert payload["parsed"] is False


def test_proto_set_reports_unknown_named_types(
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
        "prototype",
        "set",
        "add",
        "--decl",
        "MissingType __cdecl add(MissingType a, MissingType b)",
    )

    assert proc.returncode == 1
    assert "failed to apply prototype" in proc.stderr
    assert "unknown type(s): MissingType" in proc.stderr


def test_proto_set_reports_parser_failure_for_bad_syntax(
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
        "prototype",
        "set",
        "add",
        "--decl",
        "long long __cdecl add(long long a,)",
    )

    assert proc.returncode == 1
    assert "failed to apply prototype" in proc.stderr
    assert "parser limitations" in proc.stderr


def test_proto_set_void_usercall_return_argloc_follows_ida_parser(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    ida_version: tuple[int, int],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_nexus(
        idac_cmd,
        idac_env,
        database,
        "function",
        "prototype",
        "set",
        "add",
        "--decl",
        (
            "void __usercall add@<D0>(const void *this@<X0>, const void *tileInfo@<X1>, "
            "unsigned int xSampling@<W2>, unsigned int ySampling@<W3>, "
            "unsigned int blockWidth@<W4>, unsigned int blockHeight@<W5>, "
            "void *__return_ptr out@<X8>)"
        ),
    )

    if ida_version >= (9, 5):
        assert proc.returncode == 0, proc.stderr
        shown = run_nexus_json(idac_cmd, idac_env, database, "function", "prototype", "show", "add")
        assert isinstance(shown, dict)
        assert "void __usercall add(" in shown["prototype"]
        assert "void *__return_ptr out@<X8>" in shown["prototype"]
    else:
        assert proc.returncode == 1
        assert "failed to apply prototype" in proc.stderr
        assert "parser limitations" in proc.stderr
        assert "unknown type(s):" not in proc.stderr


def test_proto_set_can_optionally_propagate_to_callers(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)

    result = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "prototype",
        "set",
        "add",
        "--decl",
        "long long __cdecl add(long long a, long long b)",
        "--propagate-callers",
    )
    caller_text = normalize_pseudocode_call_arguments(run_nexus_text(idac_cmd, idac_env, database, "decompile", "main"))

    assert result["changed"] is True
    assert result["callers_considered"] >= 1
    assert result["callers_updated"] >= 1
    assert result["callers_failed"] == 0
    assert "add(2" in caller_text
