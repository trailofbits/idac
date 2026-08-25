from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tests.helpers import normalize_pseudocode_call_arguments, run_cli, run_cli_json


def _headless_rows_for(rows: object, binary: Path) -> list[dict[str, object]]:
    assert isinstance(rows, list)
    return [
        row
        for row in rows
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("exe_path") == str(binary)
    ]


def _build_tiny_binary(build_dir: Path) -> Path:
    env = dict(os.environ)
    env["FIXTURES_BUILD_DIR"] = str(build_dir)
    proc = subprocess.run(
        ["bash", "fixtures/scripts/build_tiny.sh"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    binary = build_dir / "tiny"
    assert binary.is_file()
    return binary


def _build_handler_hierarchy_binaries(build_dir: Path) -> tuple[Path, Path]:
    env = dict(os.environ)
    env["FIXTURES_BUILD_DIR"] = str(build_dir)
    proc = subprocess.run(
        ["bash", "fixtures/scripts/build_handler_hierarchy.sh"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    binary = build_dir / "handler_hierarchy"
    stripped = build_dir / "handler_hierarchy.stripped"
    assert binary.is_file()
    assert stripped.is_file()
    return binary, stripped


def test_binary_path_opens_headless_nexus_target_and_reads(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    tmp_path: Path,
) -> None:
    binary = _build_tiny_binary(tmp_path / "build")
    info = run_cli_json(
        idac_cmd,
        idac_env,
        "database",
        "show",
        "--timeout",
        "120",
        "-c",
        str(binary),
    )

    assert info["path"] == str(binary)
    assert info["database_path"] == f"{binary}.i64"
    assert info["start_ea"]
    assert info["entry_ea"]

    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    headless_rows = _headless_rows_for(targets, binary)
    assert len(headless_rows) == 1
    assert headless_rows[0]["state"] == "ready"
    assert headless_rows[0]["idb_path"] == f"{binary}.i64"
    assert headless_rows[0]["managed"] is True

    main_identifier = info["main_ea"]
    assert main_identifier
    decompiled = run_cli(
        idac_cmd,
        idac_env,
        "decompile",
        main_identifier,
        "--f5",
        "--timeout",
        "30",
        "-c",
        str(binary),
    )
    assert decompiled.returncode == 0, decompiled.stderr or decompiled.stdout
    pseudocode = normalize_pseudocode_call_arguments(decompiled.stdout)
    assert "printf" in pseudocode
    assert "add(2, 3" in pseudocode


def test_binary_paths_keep_distinct_headless_nexus_targets_ready(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    tmp_path: Path,
) -> None:
    binaries = _build_handler_hierarchy_binaries(tmp_path / "build")
    for binary in binaries:
        info = run_cli_json(
            idac_cmd,
            idac_env,
            "database",
            "show",
            "--timeout",
            "120",
            "-c",
            str(binary),
        )
        assert info["path"] == str(binary)
        assert info["database_path"] == f"{binary}.i64"
        assert info["start_ea"] or info["entry_ea"]

    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "20")
    rows_by_binary = {binary: _headless_rows_for(targets, binary) for binary in binaries}
    assert all(len(rows) == 1 for rows in rows_by_binary.values())
    assert len({rows[0]["record_id"] for rows in rows_by_binary.values()}) == len(binaries)
