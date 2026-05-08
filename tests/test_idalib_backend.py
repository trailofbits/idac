from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import run_cli


def test_idalib_database_show_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "database",
        "show",
        "-c",
        f"db:{database}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["module"] == "tiny"
    assert payload["bits"] == 64
    assert payload["processor"] == "ARM"


def test_idalib_segment_list_json_filters_by_regex(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "segment",
        "list",
        "__text",
        "--regex",
        "-c",
        f"db:{database}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload
    assert all("__text" in item["name"] for item in payload)
    assert {"name", "start", "end", "size"} <= set(payload[0])


def test_idalib_function_list_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "function",
        "list",
        "-c",
        f"db:{database}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    names = {item["name"] for item in payload}
    assert {"main", "add"} <= names
    assert all("display_name" in item for item in payload)
    assert all("section" in item for item in payload)
    assert {item["section"] for item in payload if item["name"] in {"main", "add"}} == {"__text"}


def test_idalib_function_list_json_accepts_query_and_limit(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "function",
        "list",
        "--query",
        "a",
        "--limit",
        "1",
        "-c",
        f"db:{database}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert len(payload) == 1
    assert "a" in payload[0]["name"]


def test_idalib_function_list_json_with_segment_scope(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "function",
        "list",
        "--segment",
        "__text",
        "-c",
        f"db:{database}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    names = {item["name"] for item in payload}
    assert {"main", "add"} <= names


def test_idalib_decompile_text(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "decompile",
        "main",
        "-c",
        f"db:{database}",
    )
    assert proc.returncode == 0, proc.stderr
    assert "printf" in proc.stdout
    assert "add(2, 3)" in proc.stdout


def test_idalib_decompile_text_with_f5(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "decompile",
        "main",
        "--f5",
        "-c",
        f"db:{database}",
    )
    assert proc.returncode == 0, proc.stderr
    assert "printf" in proc.stdout
    assert "add(2, 3)" in proc.stdout


def test_idalib_decompile_bulk_query_writes_manifest_and_artifacts(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    out_dir = tmp_path / "decompile-query"
    proc = run_cli(
        idac_cmd,
        idac_env,
        "decompilemany",
        "a",
        "--out-dir",
        str(out_dir),
        "-c",
        f"db:{database}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["functions_total"] >= 2
    assert payload["functions_failed"] == 0
    assert len(payload["functions"]) >= 2
    manifest_path = Path(payload["manifest_path"])
    assert manifest_path.name == "manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["pattern"] == "a"
    artifacts = [Path(item["artifact_path"]) for item in manifest["functions"] if item["ok"]]
    assert len(artifacts) >= 2
    assert all(path.exists() for path in artifacts)
    contents = "\n".join(path.read_text(encoding="utf-8") for path in artifacts)
    assert "printf" in contents
    assert "add(" in contents


def test_idalib_decompile_bulk_input_writes_requested_functions(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    out_dir = tmp_path / "decompile-input"
    input_path = tmp_path / "funcs.txt"
    input_path.write_text("# requested\nmain\nadd\n", encoding="utf-8")
    proc = run_cli(
        idac_cmd,
        idac_env,
        "decompilemany",
        "--file",
        str(input_path),
        "--out-dir",
        str(out_dir),
        "-c",
        f"db:{database}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["functions_total"] == 2
    assert len(payload["functions"]) == 2
    manifest = json.loads(Path(payload["manifest_path"]).read_text(encoding="utf-8"))
    names = {item["name"] for item in manifest["functions"] if item["ok"]}
    assert names == {"main", "add"}
    artifact_text = {
        item["name"]: Path(item["artifact_path"]).read_text(encoding="utf-8")
        for item in manifest["functions"]
        if item["ok"]
    }
    assert "printf" in artifact_text["main"]
    assert "return a + b;" in artifact_text["add"]


def test_idalib_python_exec_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = run_cli(
        idac_cmd,
        idac_env,
        "py",
        "exec",
        "-c",
        f"db:{database}",
        "--code",
        "result = {'count': len(list(idautils.Functions()))}",
        "--format",
        "json",
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["result"]["count"] >= 2
