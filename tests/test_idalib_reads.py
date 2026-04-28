from __future__ import annotations

from pathlib import Path

from tests.helpers import run_idalib, run_idalib_json


def test_idalib_function_metadata(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "function",
        "metadata",
        "main",
    )

    assert isinstance(payload, dict)
    assert payload["name"] == "main"
    assert payload["address"] == "0x100000460"
    assert payload["size"] == 80
    assert payload["prototype"] == "int __fastcall main(int argc, const char **argv, const char **envp)"
    assert payload["flags"] == "0x1410"


def test_idalib_disasm(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(idac_cmd, idac_env, copy_database(tiny_database), "disasm", "main")

    assert isinstance(payload, dict)
    text = payload["text"]
    assert "0x100000460: SUB" in text
    assert "BL              add" in text
    assert 'ADRL            X0, aTinyD; "tiny:%d\\n"' in text
    assert "BL              _printf" in text


def test_idalib_xrefs(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(idac_cmd, idac_env, copy_database(tiny_database), "xrefs", "add")

    assert isinstance(payload, list)
    assert payload == [
        {
            "from": "0x100000478",
            "kind": "call",
            "function": "main",
            "to": "0x1000004b0",
            "type": "Code_Near_Call",
            "user": False,
        }
    ]


def test_idalib_strings_query(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "search",
        "strings",
        "tiny",
        "--segment",
        "__cstring",
        "--timeout",
        "1",
    )

    assert isinstance(payload, list)
    assert payload == [{"address": "0x1000004dc", "text": "tiny:%d\n"}]


def test_idalib_strings_scan_range_query(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "search",
        "strings",
        "--scan",
        "tiny",
        "--segment",
        "__cstring",
        "--start",
        "0x1000004d0",
        "--end",
        "0x100000500",
        "--timeout",
        "1",
    )

    assert isinstance(payload, list)
    assert payload == [{"address": "0x1000004dc", "text": "tiny:%d\n"}]


def test_idalib_imports(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(idac_cmd, idac_env, copy_database(tiny_database), "imports")

    assert isinstance(payload, list)
    assert payload == [
        {
            "module": "/usr/lib/libSystem.B.dylib",
            "entries": [
                {
                    "address": "0x100004010",
                    "name": "_printf",
                    "ordinal": 0,
                }
            ],
        }
    ]


def test_idalib_proto_show(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(idac_cmd, idac_env, copy_database(tiny_database), "function", "prototype", "show", "add")

    assert isinstance(payload, dict)
    assert payload == {
        "address": "0x1000004b0",
        "prototype": "int __cdecl add(int a, int b)",
    }


def test_idalib_function_metadata_reports_missing_symbol(
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
        "metadata",
        "missing_symbol",
    )

    assert proc.returncode == 1
    assert "symbol not found: missing_symbol" in proc.stderr


def test_idalib_disasm_reports_missing_symbol(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    proc = run_idalib(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "disasm",
        "missing_symbol",
    )

    assert proc.returncode == 1
    assert "symbol not found: missing_symbol" in proc.stderr


def test_idalib_xrefs_reports_missing_symbol(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    proc = run_idalib(
        idac_cmd,
        idac_env,
        copy_database(tiny_database),
        "xrefs",
        "missing_symbol",
    )

    assert proc.returncode == 1
    assert "symbol not found: missing_symbol" in proc.stderr
