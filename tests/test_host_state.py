from __future__ import annotations

import sys
from pathlib import Path

import pytest

from idac.host import HostedCommand, HostLock, _write_state, host_status, stop_host
from idac.nexus import NexusSessionError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux host sessions")


@pytest.fixture
def host_state(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("IDA_NEXUS_STATE_DIR", str(tmp_path))
    directory = tmp_path / "idac-hosts" / ("a" * 32)
    directory.mkdir(parents=True)
    owner = HostLock(directory / "owner.lock")
    assert owner.acquire()
    try:
        yield directory
    finally:
        owner.release()


@pytest.mark.parametrize("discard", [False, True])
def test_shutdown_retry_cannot_change_pending_discard_decision(host_state: Path, discard: bool) -> None:
    _write_state(host_state, {"host_id": host_state.name, "status": "stopping", "discard": True})
    # Simulate an owner that has not yet processed its accepted stop request.
    # Retrying with default save semantics must still leave discard pending.
    with pytest.raises(NexusSessionError, match="shutdown still pending"):
        stop_host(host_state.name, discard=discard, timeout=0.01)
    assert host_status(host_state.name)["discard"] is True


def test_abandoned_command_blocks_save_and_requires_discard(host_state: Path) -> None:
    _write_state(host_state, {"host_id": host_state.name, "status": "busy"})
    command = HostedCommand(host_state.name)
    with pytest.raises(NexusSessionError, match="recovery_required"):
        command.acquire(timeout=0.01)
    with pytest.raises(NexusSessionError, match="--discard"):
        stop_host(host_state.name, timeout=0.01)
    assert host_status(host_state.name)["status"] == "recovery_required"


def test_lost_owner_prevents_commands(host_state: Path) -> None:
    _write_state(host_state, {"host_id": host_state.name, "status": "ready"})
    (host_state / "owner.lock").rename(host_state / "old-owner.lock")
    command = HostedCommand(host_state.name)
    with pytest.raises(NexusSessionError, match="host process is gone"):
        command.acquire(timeout=0.01)
    assert host_status(host_state.name)["status"] == "dead"
