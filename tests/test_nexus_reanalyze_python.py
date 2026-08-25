from __future__ import annotations

from pathlib import Path

from tests.helpers import (
    normalize_pseudocode_call_arguments,
    run_nexus,
    run_nexus_json,
    run_nexus_text,
)


def test_reanalyze_function_mode_reports_function_bounds(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)

    result = run_nexus_json(idac_cmd, idac_env, database, "misc", "reanalyze", "main")

    assert result["mode"] == "function"
    assert result["function"] == "main"
    assert result["start"] == "0x100000460"
    assert result["end"] == "0x1000004b0"
    assert result["waited"] is True


def test_reanalyze_address_mode_reports_single_item_range(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)

    result = run_nexus_json(idac_cmd, idac_env, database, "misc", "reanalyze", "0x1000004dc")

    assert result == {
        "mode": "address",
        "start": "0x1000004dc",
        "end": "0x1000004dd",
        "waited": True,
    }


def test_reanalyze_rejects_non_increasing_range(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_nexus(
        idac_cmd,
        idac_env,
        database,
        "misc",
        "reanalyze",
        "0x100000460",
        "--end",
        "0x100000460",
    )

    assert proc.returncode == 1
    assert "reanalyze range end must be greater than the start" in proc.stderr


def test_nexus_python_exec_supports_stdin_and_script(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    script_path = tmp_path / "emit_script.py"
    script_path.write_text(
        "print('script-stdout')\nresult = {'mode': 'script', 'count': len(list(idautils.Functions()))}\n",
        encoding="utf-8",
    )

    stdin_payload = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--stdin",
        input_text="print('stdin-stdout')\nresult = {'mode': 'stdin', 'count': len(list(idautils.Functions()))}\n",
    )
    script_payload = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--script",
        str(script_path),
    )

    assert stdin_payload == {
        "stdout": "stdin-stdout\n",
        "stderr": "",
        "result": {"mode": "stdin", "count": 3},
        "result_repr": "{'mode': 'stdin', 'count': 3}",
    }
    assert script_payload == {
        "stdout": "script-stdout\n",
        "stderr": "",
        "result": {"mode": "script", "count": 3},
        "result_repr": "{'mode': 'script', 'count': 3}",
    }


def test_nexus_python_exec_changes_are_checkpointed_for_headless_database(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    payload = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--code",
        "ea = idc.get_name_ea_simple('main')\nidc.set_cmt(ea, 'session only', 0)\nresult = {'comment_ea': hex(ea)}",
    )
    persisted = run_nexus_json(idac_cmd, idac_env, database, "comment", "show", "main")

    assert payload == {
        "stdout": "",
        "stderr": "",
        "result": {"comment_ea": "0x100000460"},
        "result_repr": "{'comment_ea': '0x100000460'}",
    }
    assert persisted == {
        "address": "0x100000460",
        "scope": "line",
        "repeatable": False,
        "comment": "session only",
    }


def test_nexus_db_save_persists_python_exec_changes(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--code",
        "ea = idc.get_name_ea_simple('main')\n"
        "idc.set_cmt(ea, 'saved by database save', 0)\n"
        "result = {'comment_ea': hex(ea)}",
    )
    saved = run_nexus_json(idac_cmd, idac_env, database, "database", "save")
    persisted = run_nexus_json(idac_cmd, idac_env, database, "comment", "show", "main")

    assert saved == {
        "saved": True,
        "path": str(database.resolve(strict=False)),
    }
    assert persisted == {
        "address": "0x100000460",
        "scope": "line",
        "repeatable": False,
        "comment": "saved by database save",
    }


def test_reanalyze_range_restores_function_after_session_item_deletion(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    deleted = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--code",
        "import ida_bytes\n"
        "ea = idc.get_name_ea_simple('main')\n"
        "ida_bytes.del_items(ea, 0, 4)\n"
        "result = {'ea': hex(ea)}",
    )
    missing = run_nexus(idac_cmd, idac_env, database, "function", "metadata", "main", use_json=True)
    reanalyzed = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "misc",
        "reanalyze",
        "0x100000460",
        "--end",
        "0x100000468",
    )
    restored = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "main")
    decompiled = normalize_pseudocode_call_arguments(run_nexus_text(idac_cmd, idac_env, database, "decompile", "main"))

    assert deleted == {
        "stdout": "",
        "stderr": "",
        "result": {"ea": "0x100000460"},
        "result_repr": "{'ea': '0x100000460'}",
    }
    assert missing.returncode == 1
    assert "function not found: main" in missing.stderr

    assert reanalyzed == {
        "mode": "range",
        "start": "0x100000460",
        "end": "0x100000468",
        "waited": True,
    }
    assert restored["address"] == "0x100000460"
    assert restored["name"] == "main"
    assert restored["prototype"] == ("int __fastcall main(int argc, const char **argv, const char **envp)")
    assert restored["size"] == 80
    assert restored["flags"] in {"0x1410", "0x210"}
    assert 'printf("tiny:%d\\n", v4);' in decompiled
