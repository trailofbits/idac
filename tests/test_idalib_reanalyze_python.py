from __future__ import annotations

from pathlib import Path

from tests.helpers import run_idalib, run_idalib_json, run_idalib_text


def test_reanalyze_function_mode_reports_function_bounds(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)

    result = run_idalib_json(idac_cmd, idac_env, database, "misc", "reanalyze", "main")

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

    result = run_idalib_json(idac_cmd, idac_env, database, "misc", "reanalyze", "0x1000004dc")

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
    proc = run_idalib(
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


def test_idalib_python_exec_supports_stdin_and_script(
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

    stdin_payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--stdin",
        input_text="print('stdin-stdout')\nresult = {'mode': 'stdin', 'count': len(list(idautils.Functions()))}\n",
    )
    script_payload = run_idalib_json(
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
        "result": {"mode": "stdin", "count": 3},
        "result_repr": "{'mode': 'stdin', 'count': 3}",
    }
    assert script_payload == {
        "stdout": "script-stdout\n",
        "result": {"mode": "script", "count": 3},
        "result_repr": "{'mode': 'script', 'count': 3}",
    }


def test_idalib_python_exec_persist_reuses_scope_within_open_session(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    first = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "counter = 41\nresult = {'counter': counter}",
    )
    second = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "counter += 1\nresult = {'counter': counter}",
    )
    fresh = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--code",
        "result = {'has_counter': 'counter' in globals()}",
    )

    assert first == {
        "stdout": "",
        "result": {"counter": 41},
        "result_repr": "{'counter': 41}",
    }
    assert second == {
        "stdout": "",
        "result": {"counter": 42},
        "result_repr": "{'counter': 42}",
    }
    assert fresh == {
        "stdout": "",
        "result": {"has_counter": False},
        "result_repr": "{'has_counter': False}",
    }


def test_idalib_python_exec_persist_can_update_and_reread_session_variable(
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
        "py",
        "exec",
        "--persist",
        "--code",
        "session_counter = 7\nresult = {'seeded': session_counter}",
    )
    reread = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "result = {'session_counter': session_counter}",
    )
    updated = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "session_counter += 5\nresult = {'updated': session_counter}",
    )
    reread_updated = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "result = {'session_counter': session_counter}",
    )

    assert seeded == {
        "stdout": "",
        "result": {"seeded": 7},
        "result_repr": "{'seeded': 7}",
    }
    assert reread == {
        "stdout": "",
        "result": {"session_counter": 7},
        "result_repr": "{'session_counter': 7}",
    }
    assert updated == {
        "stdout": "",
        "result": {"updated": 12},
        "result_repr": "{'updated': 12}",
    }
    assert reread_updated == {
        "stdout": "",
        "result": {"session_counter": 12},
        "result_repr": "{'session_counter': 12}",
    }


def test_idalib_python_exec_persist_can_call_session_function_in_later_call(
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
        "py",
        "exec",
        "--persist",
        "--code",
        "session_counter = 7\n"
        "def read_session_counter():\n"
        "    return session_counter\n"
        "result = {'seeded': read_session_counter()}",
    )
    called = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "result = {'session_counter': read_session_counter()}",
    )
    updated = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "session_counter += 5\nresult = {'updated': read_session_counter()}",
    )
    called_after_update = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--persist",
        "--code",
        "result = {'session_counter': read_session_counter()}",
    )

    assert seeded == {
        "stdout": "",
        "result": {"seeded": 7},
        "result_repr": "{'seeded': 7}",
    }
    assert called == {
        "stdout": "",
        "result": {"session_counter": 7},
        "result_repr": "{'session_counter': 7}",
    }
    assert updated == {
        "stdout": "",
        "result": {"updated": 12},
        "result_repr": "{'updated': 12}",
    }
    assert called_after_update == {
        "stdout": "",
        "result": {"session_counter": 12},
        "result_repr": "{'session_counter': 12}",
    }


def test_idalib_python_exec_changes_require_explicit_db_save(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "py",
        "exec",
        "--code",
        "ea = idc.get_name_ea_simple('main')\nidc.set_cmt(ea, 'session only', 0)\nresult = {'comment_ea': hex(ea)}",
    )
    in_session = run_idalib_json(idac_cmd, idac_env, database, "comment", "show", "main")
    closed = run_idalib_json(idac_cmd, idac_env, database, "database", "close", "--discard")
    reopened = run_idalib_json(idac_cmd, idac_env, database, "comment", "show", "main")

    assert payload == {
        "stdout": "",
        "result": {"comment_ea": "0x100000460"},
        "result_repr": "{'comment_ea': '0x100000460'}",
    }
    assert in_session == {
        "address": "0x100000460",
        "scope": "line",
        "repeatable": False,
        "comment": "session only",
    }
    assert closed == {
        "closed": True,
        "database": str(database.resolve(strict=False)),
        "saved": False,
    }
    assert reopened == {
        "address": "0x100000460",
        "scope": "line",
        "repeatable": False,
        "comment": None,
    }


def test_idalib_db_save_persists_python_exec_changes(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    run_idalib_json(
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
    saved = run_idalib_json(idac_cmd, idac_env, database, "database", "save")
    closed = run_idalib_json(idac_cmd, idac_env, database, "database", "close", "--discard")
    reopened = run_idalib_json(idac_cmd, idac_env, database, "comment", "show", "main")

    assert saved == {
        "saved": True,
        "path": str(database.resolve(strict=False)),
    }
    assert closed == {
        "closed": True,
        "database": str(database.resolve(strict=False)),
        "saved": False,
    }
    assert reopened == {
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
    deleted = run_idalib_json(
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
    missing = run_idalib(idac_cmd, idac_env, database, "function", "metadata", "main", use_json=True)
    reanalyzed = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        "misc",
        "reanalyze",
        "0x100000460",
        "--end",
        "0x100000468",
    )
    restored = run_idalib_json(idac_cmd, idac_env, database, "function", "metadata", "main")
    decompiled = run_idalib_text(idac_cmd, idac_env, database, "decompile", "main")

    assert deleted == {
        "stdout": "",
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
