from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import ida_nexus
import pytest

from idac.host import HostLock, _write_state, host_status, stop_host
from idac.nexus import NexusSessionError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux host sessions")


@pytest.fixture
def orphaned_worker(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("IDA_NEXUS_STATE_DIR", str(tmp_path))
    directory = tmp_path / "idac-hosts" / ("a" * 32)
    directory.mkdir(parents=True)
    instance = SimpleNamespace(
        record_id="owned-worker",
        pid=123,
        backend="idalib",
        managed=True,
        started_at=1.0,
        idb_path=str(tmp_path / "tiny.i64"),
    )
    worker = SimpleNamespace(
        directory=directory,
        instance=instance,
        host_id=directory.name,
        attached=False,
        retired=False,
        released=False,
        keepalive=None,
        database_released=True,
    )
    state = {
        "host_id": directory.name,
        "status": "recovery_required",
        "record_id": instance.record_id,
        "pid": instance.pid,
        "started_at": instance.started_at,
        "idb_path": instance.idb_path,
    }
    _write_state(directory, state)
    discovered = SimpleNamespace(instance=instance, state=ida_nexus.InstanceState.READY)
    monkeypatch.setattr(ida_nexus, "discover_databases", lambda **kwargs: [discovered])

    def assert_recovery_locked() -> None:
        for name in ("command.lock", "owner.lock"):
            lock = HostLock(directory / name)
            acquired = lock.acquire()
            lock.release()
            assert not acquired, f"{name} released before worker retirement completed"

    class Handle:
        def execute_python(self, *args, **kwargs):
            return {"result": worker.host_id}

        def shutdown_database(self, *, save):
            assert_recovery_locked()
            assert save is False
            worker.retired = True

        def close(self):
            worker.released = True

    def attach(selected, *, keepalive):
        assert selected is instance
        worker.attached = True
        worker.keepalive = keepalive
        return Handle()

    def wait_database_released(selected, *, timeout):
        assert selected is instance
        assert_recovery_locked()
        return worker.database_released

    monkeypatch.setattr(ida_nexus, "DatabaseHandle", SimpleNamespace(attach=attach))
    monkeypatch.setattr(ida_nexus, "wait_database_released", wait_database_released)
    monkeypatch.setattr(ida_nexus, "find_database_owner", lambda *args, **kwargs: instance)
    return worker, state, discovered


@pytest.mark.parametrize("status", ["ready", "busy", "recovery_required", "failed"])
def test_dead_host_discard_retires_worker_and_records_completion(orphaned_worker, status: str) -> None:
    worker, state, _ = orphaned_worker
    state["status"] = status
    _write_state(worker.directory, state)
    result = stop_host(worker.directory.name, discard=True, timeout=0.1)
    assert result["status"] == "stopped" and result["saved"] is False
    assert worker.retired and worker.released
    assert host_status(worker.directory.name) == result


def test_dead_host_requires_explicit_discard(orphaned_worker) -> None:
    worker, _, _ = orphaned_worker
    with pytest.raises(NexusSessionError, match="use --discard"):
        stop_host(worker.directory.name, timeout=0.1)
    assert not worker.attached and not worker.retired


def test_dead_host_keeps_an_already_accepted_discard(orphaned_worker) -> None:
    worker, state, _ = orphaned_worker
    state.update(status="stopping", discard=True)
    _write_state(worker.directory, state)
    result = stop_host(worker.directory.name, timeout=0.1)
    assert result["status"] == "stopped" and result["saved"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [("record_id", "replacement"), ("pid", 456), ("backend", "gui"), ("managed", False), ("started_at", 2.0)],
)
def test_dead_host_never_adopts_a_different_worker(orphaned_worker, field: str, value: object) -> None:
    worker, _, _ = orphaned_worker
    setattr(worker.instance, field, value)
    with pytest.raises(NexusSessionError):
        stop_host(worker.directory.name, discard=True, timeout=0.1)
    assert not worker.attached and not worker.retired


def test_dead_host_requires_exact_ready_record(orphaned_worker) -> None:
    worker, _, discovered = orphaned_worker
    discovered.state = ida_nexus.InstanceState.BLOCKED
    with pytest.raises(NexusSessionError, match="no longer READY"):
        stop_host(worker.directory.name, discard=True, timeout=0.1)
    assert not worker.attached and not worker.retired


def test_dead_host_rejects_another_launch_identity_without_zero_keepalive(orphaned_worker) -> None:
    worker, _, _ = orphaned_worker
    worker.host_id = "b" * 32
    with pytest.raises(NexusSessionError, match="belongs to another host"):
        stop_host(worker.directory.name, discard=True, timeout=0.1)
    assert worker.released and not worker.retired
    assert worker.keepalive > 0


def test_dead_host_discard_waits_for_command_lock(orphaned_worker) -> None:
    worker, _, _ = orphaned_worker
    command = HostLock(worker.directory / "command.lock")
    assert command.acquire()
    try:
        with pytest.raises(NexusSessionError, match="active idac command"):
            stop_host(worker.directory.name, discard=True, timeout=0.01)
        assert not worker.attached
    finally:
        command.release()


def test_dead_host_discard_does_not_claim_success_before_worker_release(orphaned_worker) -> None:
    worker, _, _ = orphaned_worker
    worker.database_released = False
    with pytest.raises(NexusSessionError, match="did not release"):
        stop_host(worker.directory.name, discard=True, timeout=0.1)
    assert worker.retired and worker.released
    assert host_status(worker.directory.name)["status"] != "stopped"


@pytest.mark.parametrize("remaining_owner", ["original", "none", "replacement"])
def test_acknowledged_discard_retry_converges_without_adopting_replacements(
    orphaned_worker, monkeypatch, remaining_owner: str
) -> None:
    worker, _, discovered = orphaned_worker
    worker.database_released = False
    with pytest.raises(NexusSessionError, match="did not release"):
        stop_host(worker.directory.name, discard=True, timeout=0.1)
    assert host_status(worker.directory.name)["discard_acknowledged"] is True
    worker.attached = False
    discovered.state = ida_nexus.InstanceState.BLOCKED
    if remaining_owner != "original":
        replacement = (
            SimpleNamespace(record_id="replacement", idb_path=worker.instance.idb_path)
            if remaining_owner == "replacement"
            else None
        )
        monkeypatch.setattr(ida_nexus, "find_database_owner", lambda *args, **kwargs: replacement)
        monkeypatch.setattr(ida_nexus, "discover_databases", lambda **kwargs: [])
    else:
        with pytest.raises(NexusSessionError, match="did not release"):
            stop_host(worker.directory.name, timeout=0.1)
        assert host_status(worker.directory.name)["status"] != "stopped"
    worker.database_released = True
    result = stop_host(worker.directory.name, timeout=0.1)
    assert result["status"] == "stopped" and result["saved"] is False
    assert not worker.attached
