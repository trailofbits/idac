from __future__ import annotations

from pathlib import Path

from tests.helpers import preview_round_trip_cli2, run_idalib, run_idalib_json, run_idalib_text


def test_comment_delete_preview_then_persist(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    seeded = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "comment",
        "set",
        "main",
        "entry point",
    )
    result = preview_round_trip_cli2(
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
    assert preview["undo"]["mode"] == "undo"
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

    seeded = run_idalib_json(
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
    shown = run_idalib_json(
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
    deleted = run_idalib_json(
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
    result = preview_round_trip_cli2(
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
    result = preview_round_trip_cli2(
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
    assert after_preview == before

    assert isinstance(persisted, dict)
    assert persisted["address"] == "0x1000004b0"
    assert persisted["changed"] is True
    assert persisted["prototype"] == preview["result"]["prototype"]
    assert isinstance(after_persist, dict)
    assert after_persist["address"] == "0x1000004b0"
    assert after_persist["prototype"] == preview["result"]["prototype"]


def test_proto_set_preview_decompile_opt_in_captures_before_after_pseudocode(
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
    preview = result["preview"]

    assert isinstance(preview, dict)
    assert isinstance(preview["before"]["decompile"], str)
    assert isinstance(preview["after"]["decompile"], str)
    assert preview["after"]["decompile"] != preview["before"]["decompile"]
    assert "add(" in preview["after"]["decompile"]


def test_proto_set_reports_unknown_named_types(
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
    proc = run_idalib(
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


def test_proto_set_reports_parser_failure_for_void_usercall_return_argloc(
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

    result = run_idalib_json(
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
    caller_text = run_idalib_text(idac_cmd, idac_env, database, "decompile", "main")

    assert result["changed"] is True
    assert result["callers_considered"] >= 1
    assert result["callers_updated"] >= 1
    assert result["callers_failed"] == 0
    assert "add(2" in caller_text
