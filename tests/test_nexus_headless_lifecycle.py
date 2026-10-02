from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from tests.helpers import run_cli_json, run_nexus_json, run_preview_json


def _shutdown_without_save(database: Path, env: dict[str, str]) -> dict[str, object]:
    """Release the exact managed worker without another save checkpoint."""

    code = r"""
import json
import sys

from ida_nexus import DatabaseHandle, find_database_owner, wait_database_released

database = sys.argv[1]
instance = find_database_owner(database, timeout=5.0)
if instance is None:
    raise RuntimeError(f"no Nexus worker owns {database}")

handle = DatabaseHandle.attach(instance, keepalive=0.0)
try:
    shutdown = handle.shutdown_database(save=False)
finally:
    handle.close()

if not wait_database_released(instance, timeout=30.0):
    raise TimeoutError(f"Nexus worker did not release {instance.record_id}")

print(json.dumps({
    "record_id": instance.record_id,
    "shutting_down": shutdown["shutting_down"],
    "save": shutdown["save"],
}))
"""
    proc = subprocess.run(
        [sys.executable, "-c", code, str(database)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=45,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    result = json.loads(proc.stdout)
    assert result["shutting_down"] is True
    assert result["save"] is False
    return result


def test_headless_autosave_survives_worker_shutdown_and_fresh_reopen(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    mutation = run_nexus_json(idac_cmd, idac_env, database, "misc", "rename", "add", "lifecycle_saved")

    assert mutation["changed"] is True
    retired = _shutdown_without_save(database, idac_env)

    readback = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "lifecycle_saved")
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    reopened = [
        row
        for row in targets
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
    ]

    assert readback["name"] == "lifecycle_saved"
    assert len(reopened) == 1
    assert reopened[0]["record_id"] != retired["record_id"]


def test_headless_preview_is_absent_after_worker_shutdown_and_fresh_reopen(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    proc, preview = run_preview_json(
        idac_cmd,
        idac_env,
        database,
        tmp_path / "lifecycle-preview.json",
        "misc",
        "rename",
        "add",
        "lifecycle_preview",
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert preview["after"]["name"] == "lifecycle_preview"
    assert preview["undo"] == {"status": "ok", "mode": "rollback", "persisted": False}
    live_readback = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    assert live_readback["name"] == "add"
    retired = _shutdown_without_save(database, idac_env)

    readback = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    reopened = [
        row
        for row in targets
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
    ]

    assert readback["name"] == "add"
    assert len(reopened) == 1
    assert reopened[0]["record_id"] != retired["record_id"]


def test_failed_headless_preview_discards_worker_after_checkpointing_prior_success(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    initial = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    address = initial["address"]
    remote_module = tmp_path / "failed_preview_remote.py"
    remote_module.write_text(
        """
def dispatch(db, op, params, preview):
    import ida_name

    address = int(params["address"], 0)
    if not ida_name.set_name(address, params["name"], ida_name.SN_FORCE):
        raise RuntimeError("test mutation failed")
    if preview:
        raise RuntimeError("simulated preview rollback failure")
    return {"name": params["name"]}
""".lstrip(),
        encoding="utf-8",
    )
    committed_name = "lifecycle_before_failed_preview"
    discarded_name = "lifecycle_failed_preview"
    lifecycle_code = r"""
import json
import sys

from idac.nexus import NexusSession, NexusSessionError

database, remote_module, address, committed_name, discarded_name = sys.argv[1:]
session = NexusSession(database, timeout=30.0, remote_module_path=remote_module)
session.execute_operation("name_set", {"address": address, "name": committed_name})
record_id = session.handle.instance.record_id
try:
    session.execute_operation(
        "comment_set",
        {"address": address, "name": discarded_name},
        preview=True,
    )
except NexusSessionError as exc:
    error = str(exc)
else:
    raise AssertionError("the simulated failed preview unexpectedly succeeded")
session.close()
print(json.dumps({"record_id": record_id, "error": error}))
"""
    lifecycle = subprocess.run(
        [
            sys.executable,
            "-c",
            lifecycle_code,
            str(database),
            str(remote_module),
            address,
            committed_name,
            discarded_name,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
        timeout=45,
    )
    assert lifecycle.returncode == 0, lifecycle.stderr or lifecycle.stdout
    retired = json.loads(lifecycle.stdout)
    assert "simulated preview rollback failure" in retired["error"]

    readback = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", committed_name)
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    reopened = [
        row
        for row in targets
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
    ]

    assert readback["name"] == committed_name
    assert readback["name"] != discarded_name
    assert len(reopened) == 1
    assert reopened[0]["record_id"] != retired["record_id"]


def test_binary_created_database_autosave_survives_fresh_reopen(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    tmp_path: Path,
) -> None:
    build_dir = tmp_path / "build"
    build_env = dict(os.environ)
    build_env["FIXTURES_BUILD_DIR"] = str(build_dir)
    build = subprocess.run(
        ["bash", "fixtures/scripts/build_tiny.sh"],
        check=False,
        capture_output=True,
        text=True,
        env=build_env,
    )
    assert build.returncode == 0, build.stderr or build.stdout
    binary = build_dir / "tiny"
    assert binary.is_file()

    mutation = run_nexus_json(
        idac_cmd,
        idac_env,
        binary,
        "misc",
        "rename",
        "add",
        "binary_lifecycle_saved",
        "--timeout",
        "120",
    )
    assert mutation["changed"] is True
    database = Path(f"{binary}.i64")
    assert database.is_file()
    retired = _shutdown_without_save(binary, idac_env)

    readback = run_nexus_json(
        idac_cmd,
        idac_env,
        binary,
        "function",
        "metadata",
        "binary_lifecycle_saved",
        "--timeout",
        "120",
    )
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    reopened = [
        row
        for row in targets
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
    ]

    assert readback["name"] == "binary_lifecycle_saved"
    assert len(reopened) == 1
    assert reopened[0]["record_id"] != retired["record_id"]


def test_timed_out_python_mutation_is_saved_and_lease_is_released(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    initial = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    address = initial["address"]
    code = (
        f"ida_name.set_name({int(address, 16)}, 'lifecycle_timeout_saved', ida_name.SN_FORCE)\nwhile True:\n    pass\n"
    )

    timed_out = subprocess.run(
        [
            *idac_cmd,
            "py",
            "exec",
            "--code",
            code,
            "-c",
            str(database),
            "--timeout",
            "1",
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
        timeout=20,
    )

    assert timed_out.returncode == 1
    assert "timed out" in timed_out.stderr.lower()
    retired = _shutdown_without_save(database, idac_env)

    readback = run_nexus_json(
        idac_cmd,
        idac_env,
        database,
        "function",
        "metadata",
        "lifecycle_timeout_saved",
    )
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    reopened = [
        row
        for row in targets
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
    ]

    assert readback["name"] == "lifecycle_timeout_saved"
    assert len(reopened) == 1
    assert reopened[0]["record_id"] != retired["record_id"]


def test_interrupted_python_discards_uncertain_worker_and_exits_cleanly(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
    tmp_path: Path,
) -> None:
    database = copy_database(tiny_database)
    initial = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    address = initial["address"]
    started_marker = tmp_path / "interrupt-operation-started"
    code = (
        f"ida_name.set_name({int(address, 16)}, 'discarded_interrupt', ida_name.SN_FORCE)\n"
        f"with open({str(started_marker)!r}, 'w') as marker:\n    marker.write('started')\n"
        "while True:\n    pass\n"
    )
    process = subprocess.Popen(
        [
            *idac_cmd,
            "py",
            "exec",
            "--code",
            code,
            "-c",
            str(database),
            "--timeout",
            "10",
            "--format",
            "json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=idac_env,
    )
    interrupted_record: dict[str, object] | None = None
    release_watcher: subprocess.Popen[str] | None = None
    watcher_stdout = ""
    watcher_stderr = ""
    try:
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and process.poll() is None and not started_marker.is_file():
            time.sleep(0.1)

        assert started_marker.is_file(), "the interrupted operation never reached its mutation marker"
        assert started_marker.read_text(encoding="utf-8") == "started"
        targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "2")
        matches = [
            row
            for row in targets
            if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
        ]
        if matches:
            interrupted_record = matches[0]
        assert interrupted_record is not None, "the Nexus worker never became discoverable"

        watcher_marker = tmp_path / "interrupt-release-watcher-started"
        watcher_code = r"""
import json
import sys
from pathlib import Path

from ida_nexus import find_database_owner, wait_database_released

instance = find_database_owner(sys.argv[1], timeout=5.0)
if instance is None:
    raise RuntimeError("the interrupted worker has no database owner")
Path(sys.argv[2]).write_text(instance.record_id, encoding="utf-8")
released = wait_database_released(instance, timeout=30.0)
print(json.dumps({"record_id": instance.record_id, "released": released}))
"""
        release_watcher = subprocess.Popen(
            [sys.executable, "-c", watcher_code, str(database), str(watcher_marker)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=idac_env,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and release_watcher.poll() is None and not watcher_marker.is_file():
            time.sleep(0.05)
        assert watcher_marker.is_file(), "the worker-release watcher never recorded the interrupted worker"
        assert watcher_marker.read_text(encoding="utf-8") == interrupted_record["record_id"]

        os.kill(process.pid, signal.SIGINT)
        stdout, stderr = process.communicate(timeout=20)
        watcher_stdout, watcher_stderr = release_watcher.communicate(timeout=35)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        if release_watcher is not None and release_watcher.poll() is None:
            release_watcher.kill()
            release_watcher.communicate(timeout=5)

    assert process.returncode == 130
    assert stdout == ""
    assert "interrupted" in stderr.lower()
    assert "Traceback" not in stderr
    assert release_watcher is not None and release_watcher.returncode == 0, watcher_stderr
    release_result = json.loads(watcher_stdout)
    assert release_result == {"record_id": interrupted_record["record_id"], "released": True}

    readback = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    reopened = [
        row
        for row in targets
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
    ]

    assert readback["name"] == "add"
    assert len(reopened) == 1
    assert reopened[0]["record_id"] != interrupted_record["record_id"]


def test_crashed_headless_worker_fails_once_and_fresh_command_recovers(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    tiny_database: Path,
) -> None:
    database = copy_database(tiny_database)
    process = subprocess.Popen(
        [
            *idac_cmd,
            "py",
            "exec",
            "--code",
            "while True:\n    pass\n",
            "-c",
            str(database),
            "--timeout",
            "30",
            "--format",
            "json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=idac_env,
    )
    crashed_record: dict[str, object] | None = None
    try:
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and process.poll() is None:
            targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "2")
            matches = [
                row
                for row in targets
                if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
            ]
            if matches:
                crashed_record = matches[0]
                break
            time.sleep(0.1)

        assert crashed_record is not None, "the Nexus worker never became discoverable"
        pid = crashed_record["pid"]
        assert isinstance(pid, int) and pid > 0
        os.kill(pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)

    assert process.returncode not in {None, 0}
    assert stderr.strip() or stdout.strip()

    readback = run_nexus_json(idac_cmd, idac_env, database, "function", "metadata", "add")
    targets = run_cli_json(idac_cmd, idac_env, "targets", "list", "--timeout", "10")
    reopened = [
        row
        for row in targets
        if isinstance(row, dict) and row.get("backend") == "idalib" and row.get("idb_path") == str(database)
    ]

    assert readback["name"] == "add"
    assert len(reopened) == 1
    assert reopened[0]["record_id"] != crashed_record["record_id"]
