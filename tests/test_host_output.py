from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.helpers import run_cli, run_cli_json

pytestmark = [pytest.mark.requires_ida, pytest.mark.skipif(sys.platform != "linux", reason="Linux host sessions")]


@pytest.fixture
def hosted_binary(idac_cmd, idac_env, tmp_path: Path):
    build_dir = tmp_path / "build"
    build = subprocess.run(
        ["bash", "fixtures/scripts/build_tiny.sh"],
        env={**idac_env, "FIXTURES_BUILD_DIR": str(build_dir)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert build.returncode == 0, build.stderr or build.stdout
    binary = build_dir / "tiny"
    state = run_cli_json(idac_cmd, idac_env, "database", "open", binary)
    try:
        checkpoint = run_cli_json(idac_cmd, idac_env, "database", "save", "--instance", state["record_id"])
        assert checkpoint["saved"] is True
        database = Path(f"{binary}.i64")
        assert database.is_file()
        yield binary, database, state
    finally:
        stopped = run_cli_json(idac_cmd, idac_env, "database", "close", "--instance", state["record_id"], "--discard")
        assert stopped["status"] == "stopped"


def test_reopening_database_alias_preserves_original_binary(hosted_binary, idac_cmd, idac_env, tmp_path: Path) -> None:
    binary, database, state = hosted_binary
    binary_before = binary.read_bytes()
    database_before = database.read_bytes()
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(binary)
    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(binary)

    for command in (("open", database), ("close", "--instance", state["record_id"])):
        for output in (binary, symlink, hardlink):
            rejected = run_cli(idac_cmd, idac_env, "database", *command, "--out", output)
            assert rejected.returncode == 1 and "--out must not overwrite" in rejected.stderr
            assert binary.read_bytes() == binary_before
            assert database.read_bytes() == database_before

    reused = run_cli_json(idac_cmd, idac_env, "database", "open", database)
    assert reused["record_id"] == state["record_id"]
    assert reused["status"] == "ready"


def test_rejected_output_discards_new_database_host(hosted_binary, idac_cmd, idac_env) -> None:
    binary, database, state = hosted_binary
    stopped = run_cli_json(idac_cmd, idac_env, "database", "close", "--instance", state["record_id"])
    assert stopped["status"] == "stopped"
    binary_before = binary.read_bytes()
    database_before = database.read_bytes()

    rejected = run_cli(idac_cmd, idac_env, "database", "open", database, "--out", binary)
    assert rejected.returncode == 1 and "--out must not overwrite" in rejected.stderr
    assert binary.read_bytes() == binary_before
    assert database.read_bytes() == database_before

    deadline = time.monotonic() + 20
    while True:
        rows = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "1")
        workers = [row for row in rows if row.get("idb_path") == str(database)]
        if not workers:
            break
        assert time.monotonic() < deadline, workers
        time.sleep(0.05)

    reopened = run_cli_json(idac_cmd, idac_env, "database", "open", database)
    try:
        assert reopened["status"] == "ready"
        assert reopened["record_id"] != state["record_id"]
        assert binary.read_bytes() == binary_before
        assert database.read_bytes() == database_before
    finally:
        stopped = run_cli_json(
            idac_cmd, idac_env, "database", "close", "--instance", reopened["record_id"], "--discard"
        )
        assert stopped["status"] == "stopped"
