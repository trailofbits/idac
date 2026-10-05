from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import ida_nexus
import pytest

from idac import host
from idac.nexus import NexusSessionError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux host sessions")


class StartupWorker:
    def __init__(self, database: Path, host_id: str) -> None:
        self.instance = SimpleNamespace(
            record_id="startup-worker",
            backend="idalib",
            managed=True,
            pid=12345,
            started_at=123.0,
            idb_path=str(database),
            exe_path=str(database.with_suffix("")),
        )
        self.identity_results: list[object] = [host_id]
        self.shutdown_errors: list[BaseException] = []
        self.running = True
        self.saved: bool | None = None

    def execute_python(self, code: str, **kwargs) -> dict[str, object]:
        result = self.identity_results[0]
        if len(self.identity_results) > 1:
            self.identity_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return {"result": result}

    def wait_autoanalysis(self, **kwargs) -> dict[str, bool]:
        return {"complete": True}

    def shutdown_database(self, *, save: bool) -> dict[str, bool]:
        if self.shutdown_errors:
            raise self.shutdown_errors.pop(0)
        self.running = False
        self.saved = save
        return {"shutting_down": True, "save": save}

    def close(self, **kwargs) -> None:
        pass


@pytest.fixture
def startup_worker(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(host, "_host_root", lambda: tmp_path)
    directory = tmp_path / ("a" * 32)
    directory.mkdir()
    database = tmp_path / "database.i64"
    host._write_state(directory, {"host_id": directory.name, "database": str(database), "status": "starting"})
    worker = StartupWorker(database, directory.name)
    monkeypatch.setattr(ida_nexus.DatabaseHandle, "open", lambda *args, **kwargs: worker)
    monkeypatch.setattr(ida_nexus, "wait_database_released", lambda *args, **kwargs: not worker.running)
    monkeypatch.setattr(host.signal, "signal", lambda *args: None)

    def fail_environment(*args, **kwargs):
        raise NexusSessionError("environment probe failed", kind="unsupported_remote_environment")

    monkeypatch.setattr(host, "read_remote_environment", fail_environment)
    return directory, worker


@pytest.mark.parametrize("shutdown_busy", [False, True])
@pytest.mark.parametrize("probe_timeout", [False, True])
def test_failed_environment_probe_discards_owned_worker(
    startup_worker, monkeypatch, shutdown_busy: bool, probe_timeout: bool
) -> None:
    directory, worker = startup_worker
    if probe_timeout:

        def fail_environment(*args, **kwargs):
            raise TimeoutError("environment probe failed")

        monkeypatch.setattr(host, "read_remote_environment", fail_environment)
    if shutdown_busy:
        worker.shutdown_errors.append(ida_nexus.RemoteError("instance_busy", "probe still finishing", 409))
    with pytest.raises((NexusSessionError, TimeoutError), match="environment probe failed"):
        host._serve(directory.name, timeout=0.2)
    assert worker.running is False
    assert worker.saved is False
    state = host.host_status(directory.name)
    assert state["status"] == "failed"
    assert "cleanup_error" not in state
    assert state["exe_path"] == worker.instance.exe_path
    assert host.HostedCommand.for_instance(worker.instance.record_id).directory == directory


@pytest.mark.parametrize(
    "token,backend,managed", [("foreign", "idalib", True), (None, "idalib", True), ("a" * 32, "gui", False)]
)
def test_startup_does_not_retire_reused_instance(startup_worker, token, backend: str, managed: bool) -> None:
    directory, worker = startup_worker
    worker.instance.backend = backend
    worker.instance.managed = managed
    worker.identity_results = [token]
    with pytest.raises(NexusSessionError, match="did not launch"):
        host._serve(directory.name, timeout=0.2)
    assert worker.running is True
    assert worker.saved is None
    assert host.HostedCommand.for_instance(worker.instance.record_id) is None


def test_transient_identity_failure_can_still_retire_owned_worker(startup_worker) -> None:
    directory, worker = startup_worker
    worker.identity_results = [TimeoutError("identity request timed out"), directory.name]
    with pytest.raises(TimeoutError, match="identity request timed out"):
        host._serve(directory.name, timeout=0.2)
    assert worker.running is False
    assert worker.saved is False
    assert "cleanup_error" not in host.host_status(directory.name)


def test_unverifiable_identity_is_reported_without_retiring_worker(startup_worker) -> None:
    directory, worker = startup_worker
    worker.identity_results = [TimeoutError("identity request timed out")]
    with pytest.raises(TimeoutError, match="identity request timed out"):
        host._serve(directory.name, timeout=0.2)
    assert worker.running is True
    assert worker.saved is None
    assert "could not verify worker ownership" in host.host_status(directory.name)["cleanup_error"]
    assert host.HostedCommand.for_instance(worker.instance.record_id) is None


def test_cancelled_startup_discards_owned_worker(startup_worker, monkeypatch) -> None:
    directory, worker = startup_worker
    monkeypatch.setattr(host, "read_remote_environment", lambda *args, **kwargs: {})
    monkeypatch.setattr(host, "validate_remote_environment", lambda environment: None)
    (directory / "cancel").touch()
    with pytest.raises(NexusSessionError, match="startup was cancelled"):
        host._serve(directory.name, timeout=0.2)
    assert worker.running is False
    assert worker.saved is False
    assert host.host_status(directory.name)["status"] == "failed"


@pytest.mark.requires_ida
def test_failed_environment_probe_releases_real_database(idac_env, copy_database, tiny_database) -> None:
    database = copy_database(tiny_database)
    code = """
import sys
from ida_nexus import DatabaseHandle, find_database_owner, wait_database_released
from idac import host
from idac.nexus import NexusSessionError

host_id = "a" * 32
directory = host._host_directory(host_id)
directory.mkdir(parents=True)
host._write_state(directory, {"host_id": host_id, "database": sys.argv[1], "status": "starting"})

def fail_environment(*args, **kwargs):
    raise NexusSessionError("environment probe failed", kind="unsupported_remote_environment")

host.read_remote_environment = fail_environment
try:
    host._serve(host_id, timeout=20.0)
except NexusSessionError as error:
    assert "environment probe failed" in str(error), error
else:
    raise AssertionError("startup unexpectedly succeeded")
assert find_database_owner(sys.argv[1]) is None
handle = DatabaseHandle.open(sys.argv[1])
try:
    handle.shutdown_database(save=False)
finally:
    handle.close(wait_for_database=True, timeout=20.0)
assert wait_database_released(handle.instance, timeout=20.0)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(database)],
        env=idac_env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
