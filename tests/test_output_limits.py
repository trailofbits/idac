from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

OVERSIZED_RESULT_CHARS = 1_000_000


@pytest.mark.parametrize("output_format", ["json", "jsonl"])
def test_large_json_output_requires_out_flag(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    output_format: str,
) -> None:
    database = copy_database(tiny_database)
    proc = subprocess.run(
        [
            *idac_cmd,
            "py",
            "exec",
            "--code",
            f"result = 'x' * {OVERSIZED_RESULT_CHARS}",
            "-c",
            str(database),
            "--format",
            output_format,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stderr)
    assert payload["code"] == "output_too_large"
    assert payload["rerun_with_out"] is True
    assert payload["chars"] > payload["limit"]
    if output_format == "jsonl":
        assert proc.stderr.count("\n") == 1
    else:
        assert proc.stderr.count("\n") > 1


def test_json_output_succeeds_with_out_flag(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    out_path = tmp_path / "result.json"
    proc = subprocess.run(
        [
            *idac_cmd,
            "py",
            "exec",
            "--code",
            "result = 'written'",
            "-c",
            str(database),
            "--format",
            "json",
            "--out",
            str(out_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert proc.stdout == ""
    assert out_path.exists()
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written["result"] == "written"


def test_out_json_suffix_forces_json_output(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    out_path = tmp_path / "result.json"
    proc = subprocess.run(
        [
            *idac_cmd,
            "py",
            "exec",
            "--code",
            "result = 'json by suffix'",
            "-c",
            str(database),
            "--out",
            str(out_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert proc.stdout == ""
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written["result"] == "json by suffix"


def test_type_list_requires_pattern_or_out(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    proc = subprocess.run(
        [
            *idac_cmd,
            "type",
            "list",
            "-c",
            str(database),
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
    )
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "this list can be very large; rerun with a pattern or `--out <path>`" in proc.stderr
