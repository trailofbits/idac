from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tests.helpers import run_cli, run_cli_json


def _idalib_rows_for(rows: object, binary: Path) -> list[dict[str, object]]:
    assert isinstance(rows, list)
    return [
        row
        for row in rows
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("filename") == str(binary)
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
    assert stripped.stat().st_size > 10_000
    return binary, stripped


def test_binary_first_skill_workflow_lists_headless_target_and_reads(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    tmp_path: Path,
) -> None:
    binary = _build_tiny_binary(tmp_path / "build")
    opened = False
    try:
        opened_payload = run_cli_json(
            idac_cmd,
            idac_env,
            "--timeout",
            "120",
            "database",
            "open",
            str(binary),
        )
        opened = True
        assert opened_payload["opened"] is True
        assert opened_payload["database"] == str(binary)

        targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
        headless_rows = _idalib_rows_for(targets, binary)
        assert len(headless_rows) == 1
        assert headless_rows[0]["module"] == "tiny"
        assert headless_rows[0]["active"] is True

        scoped_targets = run_cli_json(
            idac_cmd,
            idac_env,
            "targets",
            "list",
            "-c",
            f"db:{binary}",
            "--timeout",
            "10",
        )
        scoped_rows = _idalib_rows_for(scoped_targets, binary)
        assert scoped_rows == headless_rows

        info = run_cli_json(
            idac_cmd,
            idac_env,
            "database",
            "show",
            "--timeout",
            "30",
            "-c",
            f"db:{binary}",
        )
        assert info["path"] == str(binary)
        assert info["module"] == "tiny"
        assert info["processor"] == "ARM"
        function_identifier = info["start_ea"] or info["entry_ea"]
        assert function_identifier

        decompiled = run_cli(
            idac_cmd,
            idac_env,
            "decompile",
            function_identifier,
            "--f5",
            "--timeout",
            "30",
            "-c",
            f"db:{binary}",
        )
        assert decompiled.returncode == 0, decompiled.stderr or decompiled.stdout
        assert "printf" in decompiled.stdout
        assert "add(2, 3" in decompiled.stdout
    finally:
        if opened:
            close = run_cli(
                idac_cmd,
                idac_env,
                "database",
                "close",
                "--discard",
                "--timeout",
                "30",
                "-c",
                f"db:{binary}",
            )
            assert close.returncode == 0, close.stderr or close.stdout
            closed_targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
            assert _idalib_rows_for(closed_targets, binary) == []


def test_binary_workflow_can_keep_multiple_larger_targets_open(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    tmp_path: Path,
) -> None:
    binaries = _build_handler_hierarchy_binaries(tmp_path / "build")
    opened: list[Path] = []
    try:
        for binary in binaries:
            opened_payload = run_cli_json(
                idac_cmd,
                idac_env,
                "--timeout",
                "60",
                "database",
                "open",
                str(binary),
                "--no-auto-analysis",
            )
            opened.append(binary)
            assert opened_payload["opened"] is True
            assert opened_payload["database"] == str(binary)

        targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "20")
        rows_by_binary = {binary: _idalib_rows_for(targets, binary) for binary in binaries}
        assert all(len(rows) == 1 for rows in rows_by_binary.values())
        assert {rows[0]["filename"] for rows in rows_by_binary.values()} == {str(binary) for binary in binaries}
        assert len({rows[0]["instance_pid"] for rows in rows_by_binary.values()}) == len(binaries)

        for binary in binaries:
            scoped_targets = run_cli_json(
                idac_cmd,
                idac_env,
                "targets",
                "list",
                "-c",
                f"db:{binary}",
                "--timeout",
                "20",
            )
            scoped_rows = _idalib_rows_for(scoped_targets, binary)
            assert scoped_rows == rows_by_binary[binary]

            info = run_cli_json(
                idac_cmd,
                idac_env,
                "database",
                "show",
                "--timeout",
                "60",
                "-c",
                f"db:{binary}",
            )
            assert info["path"] == str(binary)
            assert str(info["module"]).startswith("handler_hierarchy")
            assert info["start_ea"] or info["entry_ea"]
    finally:
        for binary in reversed(opened):
            close = run_cli(
                idac_cmd,
                idac_env,
                "database",
                "close",
                "--discard",
                "--timeout",
                "30",
                "-c",
                f"db:{binary}",
            )
            assert close.returncode == 0, close.stderr or close.stdout
