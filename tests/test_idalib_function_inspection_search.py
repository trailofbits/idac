from __future__ import annotations

from pathlib import Path

from tests.helpers import run_idalib_json


def test_idalib_function_frame(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(idac_cmd, idac_env, copy_database(tiny_database), "function", "frame", "main")

    assert isinstance(payload, dict)
    assert payload["function"] == "main"
    assert payload["address"] == "0x100000460"
    assert payload["frame_size"] == 24
    assert payload["local_size"] == 16
    assert payload["saved_registers_size"] == 16
    assert payload["argument_size"] == 0
    members = payload["members"]
    assert [item["name"] for item in members] == ["var_10", "var_8", "var_4", "var_s0"]
    assert [item["kind"] for item in members] == ["local", "local", "local", "special"]


def test_idalib_function_stackvars(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    payload = run_idalib_json(idac_cmd, idac_env, copy_database(tiny_database), "function", "stackvars", "main")

    assert isinstance(payload, dict)
    assert payload["function"] == "main"
    stackvars = payload["stackvars"]
    assert [item["name"] for item in stackvars] == ["var_10", "var_8", "var_4"]

    target = next(item for item in stackvars if item["name"] == "var_8")
    assert target["xref_count"] == 3
    assert [item["address"] for item in target["xrefs"]] == [
        "0x10000047c",
        "0x100000480",
        "0x100000498",
    ]
    assert [item["access"] for item in target["xrefs"]] == ["write", "read", "read"]


def test_idalib_function_callees_and_xrefs(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    callees = run_idalib_json(idac_cmd, idac_env, database, "function", "callees", "main")
    assert isinstance(callees, dict)
    assert callees["function"] == "main"
    assert {(item["callee"], item["callee_address"]) for item in callees["edges"]} == {
        ("_printf", "0x1000004d0"),
        ("add", "0x1000004b0"),
    }

    callers = run_idalib_json(idac_cmd, idac_env, database, "function", "callers", "add")
    assert isinstance(callers, dict)
    assert callers["function"] == "add"
    assert callers["edges"] == [
        {
            "call_site": "0x100000478",
            "caller": "main",
            "caller_address": "0x100000460",
        }
    ]

    xrefs = run_idalib_json(idac_cmd, idac_env, database, "xrefs", "add")
    assert xrefs == [
        {
            "from": "0x100000478",
            "kind": "call",
            "function": "main",
            "to": "0x1000004b0",
            "type": "Code_Near_Call",
            "user": False,
        }
    ]


def test_idalib_search_bytes_supports_ida_hex_pattern(
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
        "bytes",
        "74 69 6e 79",
        "--segment",
        "__cstring",
        "--timeout",
        "1",
    )

    assert isinstance(payload, dict)
    assert payload["pattern"] == "74 69 6e 79"
    assert payload["truncated"] is False
    assert payload["results"] == [{"address": "0x1000004dc"}]


def test_idalib_search_bytes_supports_ida_wildcards(
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
        "bytes",
        "74 ? 6e 79",
        "--segment",
        "__cstring",
        "--timeout",
        "1",
    )

    assert isinstance(payload, dict)
    assert payload["pattern"] == "74 ? 6e 79"
    assert payload["truncated"] is False
    assert payload["results"] == [{"address": "0x1000004dc"}]


def test_idalib_search_strings_respects_segment_scope(
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

    assert payload == [{"address": "0x1000004dc", "text": "tiny:%d\n"}]
