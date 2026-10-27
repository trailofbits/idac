"""Host-owned Nexus workers and cooperative command finalization on Linux.

The files here belong to idac, not Nexus's registry. Database access and shutdown
always use Nexus's public API. Every cooperating idac command holds the command
lock through checkpoint/release; an abandoned command requires explicit discard.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .nexus import (
    KEEPALIVE_SECONDS,
    NexusSessionError,
    read_remote_environment,
    translate_nexus_error,
    validate_remote_environment,
)


class HostLock:
    """A process-scoped lock that is released even when a client is killed."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def acquire(self, timeout: float = 0.0) -> bool:
        if sys.platform != "linux":
            raise NexusSessionError("persistent idac targets currently require Linux", kind="host_unsupported")
        import fcntl

        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.fd = fd
                    return True
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        os.close(fd)
                        return False
                    time.sleep(min(0.05, remaining))
        except BaseException:
            os.close(fd)
            raise

    def release(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def _host_root() -> Path:
    from ida_nexus import get_state_dir

    return get_state_dir().resolve() / "idac-hosts"


def _record_path(record_id: str) -> Path:
    return _host_root() / ("record-" + hashlib.sha256(record_id.encode()).hexdigest() + ".json")


def _read_state(directory: Path) -> dict[str, Any]:
    try:
        value = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("host_id") != directory.name:
            raise ValueError("invalid host state")
        return value
    except (OSError, ValueError) as exc:
        raise NexusSessionError(f"cannot read host {directory.name}: {exc}", kind="host_state_error") from exc


def _write_state(directory: Path, state: dict[str, Any]) -> None:
    temporary = directory / f".state-{uuid.uuid4().hex}.tmp"
    try:
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        temporary.replace(directory / "state.json")
    finally:
        temporary.unlink(missing_ok=True)


def read_worker_host_id(handle: Any, *, timeout: float) -> str | None:
    """Read launch identity using only stdlib, independently of compatibility."""
    execution = handle.execute_python(
        'import os\nresult = os.environ.get("IDAC_HOST_ID")',
        timeout=timeout,
        operation_label="idac: host identity check",
        persist_globals=False,
        filename="<idac-host-identity>",
    )
    if not isinstance(execution, dict) or "result" not in execution:
        raise NexusSessionError("Nexus returned an invalid host identity response", kind="host_identity_error")
    token = execution["result"]
    if token is not None and not isinstance(token, str):
        raise NexusSessionError("Nexus returned an invalid host identity", kind="host_identity_error")
    return token


def shutdown_worker(handle: Any, *, timeout: float) -> None:
    """Request discard after ownership is proven, waiting out busy/shared leases."""
    from ida_nexus import RemoteError

    deadline = time.monotonic() + timeout
    while True:
        try:
            handle.shutdown_database(save=False)
            return
        except RemoteError as exc:
            remaining = deadline - time.monotonic()
            if exc.code not in {"instance_shared", "instance_busy"} or remaining <= 0:
                raise
            time.sleep(min(0.05, remaining))


class HostedCommand:
    """Serialize one complete idac command against a hosted worker."""

    def __init__(self, host_id: str) -> None:
        self.directory = _host_directory(host_id)
        self.lock = HostLock(self.directory / "command.lock")

    @classmethod
    def for_instance(cls, record_id: str) -> HostedCommand | None:
        path = _record_path(record_id)
        if not path.exists():
            return None
        try:
            host_id = json.loads(path.read_text(encoding="utf-8"))["host_id"]
            return cls(host_id)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise NexusSessionError("invalid idac host registration", kind="host_state_error") from exc

    def acquire(self, timeout: float) -> None:
        if not self.lock.acquire(timeout):
            raise NexusSessionError("timed out waiting for another hosted idac command", kind="host_busy")
        try:
            owner = HostLock(self.directory / "owner.lock")
            if owner.acquire():
                owner.release()
                raise NexusSessionError("the idac host process is gone; do not save this worker", kind="host_dead")
            state = _read_state(self.directory)
            if state["status"] == "busy":
                state.update(status="recovery_required", error="a previous idac command exited without finalization")
                _write_state(self.directory, state)
            if state["status"] != "ready":
                raise NexusSessionError(
                    f"database is {state['status']}; inspect `idac targets list --json`",
                    kind="host_unavailable",
                )
            state.update(status="busy")
            _write_state(self.directory, state)
        except BaseException:
            self.lock.release()
            raise

    def finish(self, *, uncertain: bool) -> None:
        if self.lock.fd is None:
            return
        try:
            state = _read_state(self.directory)
            if state["status"] == "busy":
                state["status"] = "recovery_required" if uncertain else "ready"
                if uncertain:
                    state["error"] = "command state is uncertain; use database close --discard before reopening"
                _write_state(self.directory, state)
        finally:
            self.lock.release()


def _host_directory(host_id: str) -> Path:
    if not isinstance(host_id, str) or len(host_id) != 32 or any(c not in "0123456789abcdef" for c in host_id):
        raise NexusSessionError("invalid host ID", kind="host_not_found")
    return _host_root() / host_id


def host_status(host_id: str) -> dict[str, Any]:
    directory = _host_directory(host_id)
    state = _read_state(directory)
    owner = HostLock(directory / "owner.lock")
    if owner.acquire():
        owner.release()
        if state["status"] not in {"stopped", "failed"}:
            state.update(status="dead", error="host process is not running")
    return state


def start_host(
    database: Path,
    *,
    timeout: float = 120.0,
    validate_state: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Launch outside the caller's sandbox; this function cannot grant that permission."""
    from ida_nexus import NexusError, find_database_owner

    if sys.platform != "linux":
        raise NexusSessionError("persistent idac targets currently require Linux", kind="host_unsupported")
    database = database.expanduser().resolve(strict=True)
    if not database.is_file() or database.suffix.lower() == ".idb":
        raise NexusSessionError("host requires an .i64 database or input binary", kind="invalid_context")
    root = _host_root()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    startup = HostLock(root / "startup.lock")
    if not startup.acquire(timeout):
        raise NexusSessionError("another idac host is starting", kind="host_busy")
    try:
        instance = find_database_owner(str(database), timeout=timeout)
        if instance is not None:
            command = HostedCommand.for_instance(instance.record_id)
            if command is not None:
                state = host_status(command.directory.name)
                if state["status"] in {"ready", "busy"}:
                    if validate_state is not None:
                        validate_state(state)
                    return state
            raise NexusSessionError(
                "database already has a worker; attaching here cannot relocate it outside its original sandbox",
                kind="host_existing_worker",
            )
        directory = root / uuid.uuid4().hex
        directory.mkdir(mode=0o700)
        state = {"host_id": directory.name, "database": str(database), "status": "starting"}
        _write_state(directory, state)
        with (directory / "host.log").open("ab") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "idac.host", directory.name, str(timeout)],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        deadline = time.monotonic() + timeout
        try:
            while True:
                state = _read_state(directory)
                if state["status"] == "ready":
                    if validate_state is not None:
                        validate_state(state)
                    return state
                if state["status"] == "failed" or process.poll() is not None:
                    raise NexusSessionError(
                        f"host startup failed: {state.get('error', 'see ' + str(directory / 'host.log'))}",
                        kind="host_start_failed",
                    )
                if time.monotonic() >= deadline:
                    raise NexusSessionError(f"host startup timed out: {directory.name}", kind="host_start_timeout")
                time.sleep(0.05)
        except BaseException:
            # Let the owner finish startup and close IDA cleanly, rather than
            # killing it midway through opening a database.
            (directory / "cancel").touch()
            raise
    except NexusError as exc:
        raise translate_nexus_error(exc) from exc
    finally:
        startup.release()


def _discard_orphaned_worker(directory: Path, state: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    """Retire the exact surviving worker while its absent owner's locks are held."""
    from ida_nexus import (
        DatabaseHandle,
        InstanceState,
        NexusError,
        discover_databases,
        find_database_owner,
        wait_database_released,
    )

    record_id = state.get("record_id")
    pid = state.get("pid")
    if not isinstance(record_id, str) or not isinstance(pid, int) or isinstance(pid, bool):
        raise NexusSessionError("host has no recorded worker identity to discard", kind="host_state_error")
    try:
        if state.get("discard_acknowledged") is True:
            idb_path = state.get("idb_path")
            if not isinstance(idb_path, str) or not idb_path:
                raise NexusSessionError("acknowledged discard has no recorded database path", kind="host_state_error")
            instance = find_database_owner(idb_path, timeout=timeout)
            # Only an acknowledged discard permits completion after the old
            # record disappears. A new owner is observed, never attached to.
            if instance is not None and instance.record_id != record_id:
                instance = None
        else:
            matches = [
                item.instance
                for item in discover_databases(timeout=timeout)
                if item.state is InstanceState.READY and item.instance.record_id == record_id
            ]
            if len(matches) != 1:
                raise NexusSessionError("the recorded host worker is no longer READY", kind="host_worker_unavailable")
            instance = matches[0]
            if (
                instance.pid != pid
                or instance.backend != "idalib"
                or not instance.managed
                or ("started_at" in state and instance.started_at != state["started_at"])
            ):
                raise NexusSessionError("the recorded host worker identity changed", kind="host_identity_mismatch")
            # A failed identity check must not introduce a zero-keepalive lease
            # whose release could cause Nexus to save this uncertain database.
            handle = DatabaseHandle.attach(instance, keepalive=KEEPALIVE_SECONDS)
            try:
                if read_worker_host_id(handle, timeout=timeout) != directory.name:
                    raise NexusSessionError(
                        "the recorded worker belongs to another host", kind="host_identity_mismatch"
                    )
                state.update(status="stopping", discard=True, idb_path=instance.idb_path)
                state.pop("error", None)
                _write_state(directory, state)
                shutdown_worker(handle, timeout=timeout)
                state["discard_acknowledged"] = True
                _write_state(directory, state)
            finally:
                handle.close()
        if instance is not None and not wait_database_released(instance, timeout=timeout):
            raise NexusSessionError("worker did not release its database", kind="host_stop_timeout")
    except NexusError as exc:
        raise translate_nexus_error(exc) from exc
    state.update(status="stopped", saved=False)
    _write_state(directory, state)
    return state


def stop_host(host_id: str, *, discard: bool = False, timeout: float = 120.0) -> dict[str, Any]:
    directory = _host_directory(host_id)
    state = host_status(host_id)
    if state["status"] == "stopped":
        return state
    command = HostLock(directory / "command.lock")
    if not command.acquire(timeout):
        raise NexusSessionError("timed out waiting for the active idac command", kind="host_busy")
    try:
        state = _read_state(directory)
        if state["status"] == "stopped":
            return state
        owner = HostLock(directory / "owner.lock")
        if owner.acquire():
            try:
                if not discard and not (state["status"] == "stopping" and state.get("discard") is True):
                    raise NexusSessionError(
                        "the idac host process is gone; use --discard to close without saving", kind="host_uncertain"
                    )
                return _discard_orphaned_worker(directory, state, timeout=timeout)
            finally:
                owner.release()
        if state["status"] in {"failed", "starting"}:
            raise NexusSessionError(f"cannot stop host in state {state['status']}", kind="host_unavailable")
        if state["status"] in {"busy", "recovery_required"} and not discard:
            raise NexusSessionError(
                "host state is uncertain; use --discard to close without saving", kind="host_uncertain"
            )
        # A submitted shutdown decision is immutable. In particular, a second
        # caller must never turn an accepted discard of poisoned state into a
        # save while the owner is waiting to acquire this lock.
        if state["status"] not in {"stopped", "stopping"}:
            state.update(status="stopping", discard=discard)
            state.pop("error", None)
            _write_state(directory, state)
    finally:
        command.release()
    deadline = time.monotonic() + timeout
    while True:
        state = host_status(host_id)
        if state["status"] == "stopped":
            return state
        if state["status"] == "dead" and state.get("discard") is True:
            # The owner may disappear after accepting a discard request.
            # Recovery takes both locks again before touching its worker.
            remaining = deadline - time.monotonic()
            if remaining > 0:
                return stop_host(host_id, discard=True, timeout=remaining)
        if state["status"] != "stopping":
            raise NexusSessionError(
                f"host shutdown failed: {state.get('error', state['status'])}", kind="host_stop_failed"
            )
        if time.monotonic() >= deadline:
            raise NexusSessionError(f"host shutdown still pending: {host_id}", kind="host_stop_timeout")
        time.sleep(0.05)


def _serve(host_id: str, timeout: float) -> None:
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, wait_database_released

    directory = _host_directory(host_id)
    owner = HostLock(directory / "owner.lock")
    if not owner.acquire():
        raise NexusSessionError("host is already running", kind="host_busy")
    handle = None
    owns_worker = False
    ownership_checked = False
    stop_requested = False
    disconnected: str | None = None

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True

    def record_disconnect(_handle: Any, reason: str) -> None:
        nonlocal disconnected
        disconnected = reason

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        state = _read_state(directory)
        handle = DatabaseHandle.open(
            state["database"],
            options=DatabaseOpenOptions(
                keepalive=KEEPALIVE_SECONDS,
                idle_timeout=None,
                startup_timeout=timeout,
                worker_env={**os.environ, "IDAC_HOST_ID": host_id},
                auto_analysis=True,
            ),
            on_disconnect=record_disconnect,
        )
        instance = handle.instance
        state.update(
            record_id=instance.record_id,
            pid=instance.pid,
            idb_path=instance.idb_path,
            exe_path=instance.exe_path,
            started_at=instance.started_at,
        )
        _write_state(directory, state)
        if instance.backend != "idalib" or not instance.managed:
            ownership_checked = True
            raise NexusSessionError("Nexus reused a worker this host did not launch", kind="host_existing_worker")
        token = read_worker_host_id(handle, timeout=timeout)
        ownership_checked = True
        if token != host_id:
            raise NexusSessionError("Nexus reused a worker this host did not launch", kind="host_existing_worker")
        owns_worker = True
        _record_path(instance.record_id).write_text(json.dumps({"host_id": host_id}), encoding="utf-8")
        environment = read_remote_environment(handle, timeout=timeout)
        analysis = handle.wait_autoanalysis(timeout=timeout)
        if analysis.get("complete") is not True:
            raise NexusSessionError("headless autoanalysis did not complete", kind="analysis_incomplete")
        validate_remote_environment(environment)
        if stop_requested or (directory / "cancel").exists():
            raise NexusSessionError("host startup was cancelled", kind="host_start_cancelled")
        state.update(status="ready")
        _write_state(directory, state)
        while True:
            if disconnected is not None:
                raise NexusSessionError(f"host worker disconnected: {disconnected}", kind="host_disconnected")
            command = HostLock(directory / "command.lock")
            if command.acquire():
                try:
                    state = _read_state(directory)
                    cancelled = (directory / "cancel").exists()
                    if (stop_requested or cancelled) and state["status"] != "stopping":
                        state.update(status="stopping", discard=cancelled or state["status"] != "ready")
                        stop_requested = False
                        _write_state(directory, state)
                    if state["status"] == "stopping":
                        discard = state["discard"]
                        try:
                            if not discard:
                                saved = handle.save_database()
                                if saved.get("saved") is not True:
                                    raise NexusSessionError("Nexus did not confirm save", kind="save_failed")
                            # Saving is explicit above so failure cannot be
                            # hidden by the worker's final shutdown response.
                            shutdown_worker(handle, timeout=timeout)
                            if discard:
                                state["discard_acknowledged"] = True
                                _write_state(directory, state)
                        except Exception as exc:
                            state.update(status="recovery_required", error=str(exc))
                            _write_state(directory, state)
                        else:
                            handle.close(wait_for_database=True, timeout=timeout)
                            if not wait_database_released(instance, timeout=timeout):
                                raise NexusSessionError("worker did not release its database", kind="host_stop_timeout")
                            state.update(status="stopped", saved=not discard)
                            _write_state(directory, state)
                            return
                finally:
                    command.release()
            time.sleep(0.05)
    except BaseException as exc:
        state = _read_state(directory)
        state.update(status="failed", error=str(exc))
        if handle is not None and not ownership_checked:
            # A failed identity request proves nothing about launch ownership.
            # Retry this read-only check once, without cancelling operations or
            # touching a potentially reused worker's database.
            try:
                token = read_worker_host_id(handle, timeout=timeout)
                owns_worker = token == host_id and handle.instance.backend == "idalib" and handle.instance.managed
                if owns_worker:
                    _record_path(handle.instance.record_id).write_text(
                        json.dumps({"host_id": host_id}), encoding="utf-8"
                    )
            except Exception as identity_error:
                state["cleanup_error"] = f"could not verify worker ownership; worker was not retired: {identity_error}"
        _write_state(directory, state)
        if handle is not None and owns_worker:
            try:
                shutdown_worker(handle, timeout=timeout)
                state.update(discard=True, discard_acknowledged=True)
                _write_state(directory, state)
                handle.close(wait_for_database=True, timeout=timeout)
                if not wait_database_released(handle.instance, timeout=timeout):
                    raise NexusSessionError("worker did not release its database", kind="host_stop_timeout")
            except Exception as cleanup_error:
                state["cleanup_error"] = str(cleanup_error)
                _write_state(directory, state)
        raise
    finally:
        try:
            if handle is not None:
                handle.close()
        finally:
            owner.release()


if __name__ == "__main__":
    _serve(sys.argv[1], float(sys.argv[2]))
