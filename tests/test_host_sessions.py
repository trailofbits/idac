from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from idac.host import HostedCommand
from tests.helpers import run_cli, run_cli_json

pytestmark = [pytest.mark.requires_ida, pytest.mark.skipif(sys.platform != "linux", reason="Linux host sessions")]


@pytest.fixture
def hosted_database(idac_cmd, idac_env, copy_database, tiny_database):
    database = copy_database(tiny_database)
    state = run_cli_json(idac_cmd, idac_env, "database", "open", database)
    assert state["status"] == "ready"
    try:
        yield database, state
    finally:
        stopped = run_cli_json(idac_cmd, idac_env, "database", "close", "--instance", state["record_id"], "--discard")
        assert stopped["status"] == "stopped"


def test_host_reuses_worker_and_serializes_whole_commands(hosted_database, idac_cmd, idac_env, tmp_path: Path) -> None:
    database, host = hosted_database
    record_id = host["record_id"]
    assert run_cli_json(idac_cmd, idac_env, "database", "open", database)["record_id"] == record_id
    initial = run_cli_json(idac_cmd, idac_env, "function", "metadata", "add", "--instance", record_id)
    marker = tmp_path / "between-requests"
    code = """
import sys, time
from pathlib import Path
from idac.nexus import NexusSession
with NexusSession(instance_id=sys.argv[1]) as session:
    session.execute_operation("name_set", {"identifier": sys.argv[2], "new_name": "host_intermediate"})
    Path(sys.argv[3]).touch()
    time.sleep(1)
    session.execute_operation("name_set", {"identifier": sys.argv[2], "new_name": "host_final"})
"""
    writer = subprocess.Popen(
        [sys.executable, "-c", code, record_id, initial["address"], str(marker)],
        env=idac_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and writer.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), writer.communicate(timeout=5)
        # This read starts between the writer's RPCs and must see the completed
        # command, including its checkpoint, rather than the intermediate name.
        readback = run_cli_json(idac_cmd, idac_env, "function", "metadata", initial["address"], "--instance", record_id)
        stdout, stderr = writer.communicate(timeout=10)
        assert writer.returncode == 0, stderr or stdout
        assert readback["name"] == "host_final"
    finally:
        if writer.poll() is None:
            writer.kill()
            writer.communicate(timeout=10)
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list")
    assert any(row["record_id"] == record_id and row["session_status"] == "ready" for row in targets)
    stopped = run_cli_json(idac_cmd, idac_env, "database", "close", "--instance", host["record_id"])
    assert stopped["status"] == "stopped" and stopped["saved"] is True
    assert not list(database.parent.glob("*.crash-*"))
    reopened = run_cli_json(idac_cmd, idac_env, "function", "metadata", "host_final", "-c", database)
    assert reopened["name"] == "host_final"


@pytest.mark.parametrize("kill_host", [False, True], ids=["live-host", "dead-host"])
def test_failed_preview_blocks_other_clients_and_discards_without_saving(
    hosted_database, idac_cmd, idac_env, tmp_path: Path, monkeypatch, kill_host: bool
) -> None:
    database, host = hosted_database
    record_id = host["record_id"]
    initial = run_cli_json(idac_cmd, idac_env, "function", "metadata", "add", "--instance", record_id)
    remote = tmp_path / "failed_preview.py"
    remote.write_text(
        """
def dispatch(db, op, params, preview):
    import ida_name
    ida_name.set_name(int(params["address"], 0), params["name"], ida_name.SN_FORCE)
    if preview:
        raise RuntimeError("failed rollback")
    return {"changed": True}
""",
        encoding="utf-8",
    )
    code = """
import sys
from idac.nexus import NexusSession, NexusSessionError
try:
    with NexusSession(instance_id=sys.argv[1], remote_module_path=sys.argv[2]) as session:
        session.execute_operation("name_set", {"address": sys.argv[3], "name": "host_saved"})
        session.execute_operation("name_set", {"address": sys.argv[3], "name": "host_unsaved"}, preview=True)
except NexusSessionError as exc:
    assert "failed rollback" in str(exc)
else:
    raise AssertionError("preview did not fail")
"""
    failed = subprocess.run(
        [sys.executable, "-c", code, record_id, str(remote), initial["address"]],
        env=idac_env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert failed.returncode == 0, failed.stderr
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list")
    assert any(row["record_id"] == record_id and row["session_status"] == "recovery_required" for row in targets)
    for selector in (("--instance", record_id), ("-c", str(database))):
        blocked = run_cli(idac_cmd, idac_env, "database", "save", *selector)
        assert blocked.returncode == 1 and "recovery_required" in blocked.stderr
    blocked_stop = run_cli(idac_cmd, idac_env, "database", "close", "--instance", host["record_id"])
    assert blocked_stop.returncode == 1 and "--discard" in blocked_stop.stderr
    if kill_host:
        monkeypatch.setenv("IDA_NEXUS_STATE_DIR", idac_env["IDA_NEXUS_STATE_DIR"])
        command = HostedCommand.for_instance(record_id)
        assert command is not None
        owner_stat = (command.directory / "owner.lock").stat()
        owner_pids = []
        for line in Path("/proc/locks").read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if len(fields) < 8 or fields[1] != "FLOCK":
                continue
            major, minor, inode = fields[5].split(":")
            if (
                int(major, 16) == os.major(owner_stat.st_dev)
                and int(minor, 16) == os.minor(owner_stat.st_dev)
                and int(inode) == owner_stat.st_ino
            ):
                owner_pids.append(int(fields[4]))
        assert len(owner_pids) == 1 and owner_pids[0] != os.getpid()
        os.kill(owner_pids[0], signal.SIGKILL)
        blocked_stop = run_cli(idac_cmd, idac_env, "database", "close", "--instance", record_id)
        assert blocked_stop.returncode == 1 and "--discard" in blocked_stop.stderr
    stopped = run_cli_json(idac_cmd, idac_env, "database", "close", "--instance", host["record_id"], "--discard")
    assert stopped["status"] == "stopped" and stopped["saved"] is False
    readback = run_cli_json(idac_cmd, idac_env, "function", "metadata", initial["address"], "-c", database)
    assert readback["name"] == "host_saved"


def test_killed_client_requires_discard_before_another_save(
    hosted_database, idac_cmd, idac_env, tmp_path: Path
) -> None:
    database, host = hosted_database
    marker = tmp_path / "client-active"
    code = """
import sys, time
from pathlib import Path
from idac.nexus import NexusSession
with NexusSession(instance_id=sys.argv[1]) as session:
    session.execute_operation("name_set", {"identifier": "add", "new_name": "killed_unsaved"})
    Path(sys.argv[2]).touch()
    time.sleep(60)
"""
    client = subprocess.Popen(
        [sys.executable, "-c", code, host["record_id"], str(marker)],
        env=idac_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and client.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), client.communicate(timeout=5)
    finally:
        if client.poll() is None:
            client.kill()
        client.communicate(timeout=10)
    blocked = run_cli(idac_cmd, idac_env, "database", "save", "--instance", host["record_id"])
    assert blocked.returncode == 1 and "recovery_required" in blocked.stderr
    stopped = run_cli_json(idac_cmd, idac_env, "database", "close", "--instance", host["record_id"], "--discard")
    assert stopped["status"] == "stopped"
    readback = run_cli_json(idac_cmd, idac_env, "function", "metadata", "add", "-c", database)
    assert readback["name"] == "add"


def test_host_refuses_to_adopt_existing_worker(idac_cmd, idac_env, copy_database, tiny_database) -> None:
    database = copy_database(tiny_database)
    run_cli_json(idac_cmd, idac_env, "database", "show", "-c", database)
    result = run_cli(idac_cmd, idac_env, "database", "open", database)
    assert result.returncode == 1 and "cannot relocate" in result.stderr


def test_host_output_cannot_replace_database(hosted_database, idac_cmd, idac_env) -> None:
    database, state = hosted_database
    before = database.read_bytes()
    for command in (("open", str(database)), ("close", "--instance", state["record_id"])):
        rejected = run_cli(idac_cmd, idac_env, "database", *command, "--out", database)
        assert rejected.returncode == 1 and "--out" in rejected.stderr
        assert database.read_bytes() == before
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list")
    assert any(row["record_id"] == state["record_id"] and row["session_status"] == "ready" for row in targets)
