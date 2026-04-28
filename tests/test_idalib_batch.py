from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import run_cli, run_idalib_json, run_idalib_text


def _local_type_map(payload: object) -> dict[str, str]:
    assert isinstance(payload, dict)
    return {item["name"]: item["type"] for item in payload["locals"] if isinstance(item, dict) and item.get("name")}


def _local_names(payload: object) -> set[str]:
    assert isinstance(payload, dict)
    return {item["name"] for item in payload["locals"] if isinstance(item, dict)}


def test_batch_reuses_batch_dir_and_updates_prototypes_and_locals(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()

    (batch_dir / "proto_decl.h").write_text(
        "long long __cdecl add(long long a, long long b)\n",
        encoding="utf-8",
    )
    (batch_dir / "local_decl.h").write_text("unsigned int sum_value;\n", encoding="utf-8")
    (batch_dir / "recovered_types.h").write_text(
        "typedef struct cli_batch_record { int value; } cli_batch_record;\n",
        encoding="utf-8",
    )
    (batch_dir / "recovery.idac").write_text(
        "\n".join(
            [
                "# batch commands omit backend/database flags",
                "type declare --decl-file recovered_types.h",
                "function prototype set add --decl-file proto_decl.h",
                "function locals rename main v4 --new-name sum_value",
                "function locals retype main sum_value --decl-file local_decl.h",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    out_path = batch_dir / "batch_apply.json"

    proc = run_cli(
        idac_cmd,
        idac_env,
        "batch",
        str(batch_dir / "recovery.idac"),
        "--out",
        str(out_path),
        "-c",
        f"db:{database}",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert proc.stdout == ""
    result = json.loads(out_path.read_text(encoding="utf-8"))
    updated_proto = run_idalib_json(idac_cmd, idac_env, database, "function", "prototype", "show", "add")
    updated_locals = run_idalib_json(idac_cmd, idac_env, database, "function", "locals", "list", "main")
    type_info = run_idalib_json(idac_cmd, idac_env, database, "type", "show", "cli_batch_record")
    decompiled = run_idalib_text(idac_cmd, idac_env, database, "decompile", "main")

    assert isinstance(result, dict)
    assert result["ok"] is True
    assert result["commands_total"] == 4
    assert result["commands_failed"] == 0
    assert all(step["status"] == "ok" for step in result["results"])

    assert isinstance(updated_proto, dict)
    assert "add(" in updated_proto["prototype"]
    assert "__int64" in updated_proto["prototype"]

    assert isinstance(updated_locals, dict)
    assert "sum_value" in _local_names(updated_locals)
    assert _local_type_map(updated_locals)["sum_value"] == "unsigned int"

    assert isinstance(type_info, dict)
    assert type_info["name"] == "cli_batch_record"

    assert "unsigned int sum_value;" in decompiled
    assert "sum_value = add(2, 3);" in decompiled


def test_batch_defaults_to_stdout_json_without_out(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    batch_path = tmp_path / "one.idac"
    batch_path.write_text("function prototype show add\n", encoding="utf-8")

    proc = run_cli(
        idac_cmd,
        idac_env,
        "batch",
        str(batch_path),
        "-c",
        f"db:{database}",
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["commands_total"] == 1
    assert payload["results"][0]["status"] == "ok"
    assert payload["results"][0]["result"]["address"] == "0x1000004b0"


def test_batch_writes_per_line_output_artifacts(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    batch_path = tmp_path / "artifact.idac"
    out_path = tmp_path / "batch.json"
    step_out = tmp_path / "step.json"
    batch_path.write_text("function prototype show add -j -ostep.json\n", encoding="utf-8")

    proc = run_cli(
        idac_cmd,
        idac_env,
        "batch",
        str(batch_path),
        "--out",
        str(out_path),
        "-c",
        f"db:{database}",
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["results"][0]["status"] == "ok"
    artifact = payload["results"][0]["artifacts"][0]
    assert artifact["artifact_path"] == str(step_out)
    assert artifact["format"] == "json"
    assert artifact["ok"] is True
    written = json.loads(step_out.read_text(encoding="utf-8"))
    assert written["address"] == "0x1000004b0"
    assert "add(" in written["prototype"]


def test_batch_allows_per_line_json_without_step_out(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    batch_path = tmp_path / "bad_format.idac"
    out_path = tmp_path / "batch.json"
    batch_path.write_text("function prototype show add -j\n", encoding="utf-8")

    proc = run_cli(
        idac_cmd,
        idac_env,
        "batch",
        str(batch_path),
        "--out",
        str(out_path),
        "-c",
        f"db:{database}",
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["results"][0]["status"] == "ok"
    assert payload["results"][0]["result"]["address"] == "0x1000004b0"


def test_batch_preflights_step_output_before_mutation(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    batch_path = tmp_path / "bad_mutation.idac"
    out_path = tmp_path / "batch.json"
    bad_out = tmp_path / "step-dir"
    bad_out.mkdir()
    batch_path.write_text("comment set main entry point -ostep-dir\n", encoding="utf-8")

    proc = run_cli(
        idac_cmd,
        idac_env,
        "batch",
        str(batch_path),
        "--out",
        str(out_path),
        "-c",
        f"db:{database}",
    )

    assert proc.returncode == 1
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert payload["results"][0]["status"] == "failed"
    comment = run_idalib_json(idac_cmd, idac_env, database, "comment", "show", "main")
    assert comment["comment"] is None


def test_batch_reports_backend_operation_failure(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    batch_path = tmp_path / "missing.idac"
    out_path = tmp_path / "missing.json"
    batch_path.write_text("function metadata missing_symbol\n", encoding="utf-8")

    proc = run_cli(
        idac_cmd,
        idac_env,
        "batch",
        str(batch_path),
        "--out",
        str(out_path),
        "-c",
        f"db:{database}",
    )

    assert proc.returncode == 1
    assert "batch line 1:" in proc.stderr
    assert "symbol not found: missing_symbol" in proc.stderr
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert payload["commands_failed"] == 1
    assert payload["results"][0]["stderr"] == "symbol not found: missing_symbol"
