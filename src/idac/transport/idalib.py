from __future__ import annotations

import contextlib
import json
import os
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..metadata import WIRE_PROTOCOL_VERSION
from ..paths import (
    ensure_user_runtime_dir,
    idalib_registry_path,
    idalib_registry_paths,
)
from .common import normalize_timeout, pid_is_live, recv_all, require_timeout_for_operation
from .idalib_common import build_target_row, load_registry, normalize_database_path
from .schema import RequestEnvelope, response_ok

IDALIB_CONNECT_RETRIES = 3
IDALIB_READY_MAX_BYTES = 65_536


@dataclass(frozen=True)
class IdaLibInstance:
    pid: int
    socket_path: Path
    registry_path: Path
    database_path: str
    started_at: str | None
    meta: dict[str, Any]


def _timeout_text(timeout: float | None) -> str:
    return "blocking mode" if timeout is None else f"{timeout:g}s"


def _timeout_error(op: str, timeout: float | None) -> RuntimeError:
    return RuntimeError(f"idalib request timed out after {_timeout_text(timeout)}: {op}")


def _purge_instance_files(
    *,
    registry_path: Path | None = None,
    socket_path: Path | None = None,
) -> None:
    if registry_path is not None:
        with contextlib.suppress(FileNotFoundError):
            registry_path.unlink()
    if socket_path is not None:
        with contextlib.suppress(FileNotFoundError):
            socket_path.unlink()


def _instance_from_registry(path: Path) -> IdaLibInstance | None:
    payload = load_registry(path)
    if payload is None:
        _purge_instance_files(registry_path=path)
        return None
    try:
        pid = int(payload["pid"])
        socket_path = Path(str(payload["socket_path"]))
        database_path = normalize_database_path(str(payload["database_path"]))
    except (KeyError, TypeError, ValueError):
        _purge_instance_files(registry_path=path)
        return None
    if not pid_is_live(pid) or not socket_path.exists():
        _purge_instance_files(registry_path=path, socket_path=socket_path)
        return None
    started_at = payload.get("started_at")
    return IdaLibInstance(
        pid=pid,
        socket_path=socket_path,
        registry_path=path,
        database_path=database_path,
        started_at=None if started_at in (None, "") else str(started_at),
        meta=dict(payload),
    )


def _list_instances() -> list[IdaLibInstance]:
    ensure_user_runtime_dir()
    rows: list[IdaLibInstance] = []
    for registry_path in idalib_registry_paths():
        instance = _instance_from_registry(registry_path)
        if instance is not None:
            rows.append(instance)
    return rows


def _find_instance_for_database(database_path: str) -> IdaLibInstance | None:
    requested = normalize_database_path(database_path)
    for instance in _list_instances():
        if instance.database_path == requested:
            return instance
    return None


def _socket_request(
    socket_path: Path,
    payload: dict[str, Any],
    *,
    timeout: float | None,
) -> dict[str, Any]:
    encoded = json.dumps(payload).encode("utf-8")
    last_error: OSError | None = None
    for _ in range(IDALIB_CONNECT_RETRIES):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(str(socket_path))
            sock.sendall(encoded)
            sock.shutdown(socket.SHUT_WR)
            chunks = recv_all(sock)
            response = json.loads(b"".join(chunks).decode("utf-8"))
            if not isinstance(response, dict):
                raise RuntimeError("idalib daemon returned a non-object JSON payload")
            return response
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
        finally:
            sock.close()
    detail = "idalib daemon is not running" if last_error is None else str(last_error)
    raise RuntimeError(detail)


def _probe_instance(
    instance: IdaLibInstance,
    *,
    timeout: float | None,
    purge_on_failure: bool = True,
) -> bool:
    try:
        response = _socket_request(
            instance.socket_path,
            {"version": WIRE_PROTOCOL_VERSION, "op": "daemon_status", "params": {}},
            timeout=timeout,
        )
    except socket.timeout:
        raise
    except RuntimeError:
        if purge_on_failure:
            _purge_instance_files(
                registry_path=instance.registry_path,
                socket_path=instance.socket_path,
            )
        return False
    return bool(response.get("ok"))


def _build_target_row(instance: IdaLibInstance) -> dict[str, Any]:
    return build_target_row(
        pid=instance.pid,
        database_path=instance.database_path,
        socket_path=instance.socket_path,
    )


def _terminate_process(proc: subprocess.Popen[str]) -> None:
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5.0)


def _read_ready_payload(read_fd: int, *, timeout: float | None) -> dict[str, Any]:
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(read_fd, selectors.EVENT_READ)
            events = selector.select(timeout)
            if not events:
                raise socket.timeout()
            raw = os.read(read_fd, IDALIB_READY_MAX_BYTES + 1)
    finally:
        with contextlib.suppress(OSError):
            os.close(read_fd)

    if not raw:
        raise EOFError("idalib daemon exited before reporting readiness")
    if len(raw) > IDALIB_READY_MAX_BYTES:
        raise RuntimeError("idalib daemon readiness payload is too large")
    raw = raw.split(b"\n", 1)[0].strip()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("idalib daemon returned a non-object readiness payload")
    return payload


def _start_daemon_for_database(
    database_path: str,
    *,
    startup_timeout: float | None,
    run_auto_analysis: bool,
) -> IdaLibInstance:
    ensure_user_runtime_dir()
    cmd = [
        sys.executable,
        "-m",
        "idac.transport.idalib_server",
        "--database",
        database_path,
    ]
    if not run_auto_analysis:
        cmd.append("--no-auto-analysis")
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    cmd.extend(["--ready-fd", str(write_fd)])
    with tempfile.TemporaryFile("w+", encoding="utf-8") as stderr_log:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_log,
                text=True,
                start_new_session=True,
                pass_fds=(write_fd,),
            )
        except Exception:
            with contextlib.suppress(OSError):
                os.close(read_fd)
            raise
        finally:
            with contextlib.suppress(OSError):
                os.close(write_fd)

        expected_registry = idalib_registry_path(proc.pid)
        try:
            payload = _read_ready_payload(read_fd, timeout=startup_timeout)
            if not bool(payload.get("ok")):
                raise RuntimeError(str(payload.get("error") or "idalib daemon failed to start"))
            instance = _instance_from_registry(expected_registry)
            if instance is None:
                raise RuntimeError("idalib daemon reported readiness but registry was unavailable")
            if instance.database_path != database_path:
                raise RuntimeError(
                    f"idalib daemon opened `{instance.database_path}` while `{database_path}` was requested"
                )
            return instance
        except socket.timeout as exc:
            _terminate_process(proc)
            raise RuntimeError(
                f"timed out after {_timeout_text(startup_timeout)} waiting for idalib daemon "
                f"to start for `{database_path}`"
            ) from exc
        except EOFError as exc:
            stderr_log.seek(0)
            detail = stderr_log.read().strip()
            if detail:
                raise RuntimeError(detail) from exc
            raise RuntimeError(f"idalib daemon failed to start for `{database_path}`") from exc


def _ensure_instance_for_database(
    database_path: str,
    *,
    timeout: float | None,
    run_auto_analysis: bool,
    start_if_missing: bool,
) -> tuple[IdaLibInstance, bool]:
    normalized = normalize_database_path(database_path)
    instance = _find_instance_for_database(normalized)
    if instance is not None:
        if _probe_instance(instance, timeout=timeout):
            return instance, True
        instance = None
    if not start_if_missing:
        raise RuntimeError(
            f"idalib database is not open: {normalized}; use `idac database open {shlex_quote(normalized)}`"
        )
    return (
        _start_daemon_for_database(
            normalized,
            startup_timeout=timeout,
            run_auto_analysis=run_auto_analysis,
        ),
        False,
    )


def _already_closed_result(database: str) -> dict[str, Any]:
    return {
        "closed": False,
        "database": normalize_database_path(database),
        "already_closed": True,
    }


def shlex_quote(value: str) -> str:
    if value and all(ch.isalnum() or ch in "._/-" for ch in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


class IdaLibBackend:
    name = "idalib"

    def send(self, request: RequestEnvelope) -> dict[str, Any]:
        timeout = normalize_timeout(request.timeout)
        require_timeout_for_operation(request.op, timeout)
        if request.op == "list_targets":
            return response_ok(
                [_build_target_row(instance) for instance in _list_instances()],
                backend="idalib",
            )

        if request.op == "db_open":
            raw_path = str(request.params.get("path") or "").strip()
            if not raw_path:
                raise RuntimeError("database open requires a path")
            try:
                instance, already_open = _ensure_instance_for_database(
                    raw_path,
                    timeout=timeout,
                    run_auto_analysis=bool(request.params.get("run_auto_analysis", True)),
                    start_if_missing=True,
                )
            except socket.timeout as exc:
                raise _timeout_error("db_open", timeout) from exc
            return response_ok(
                {
                    "opened": True,
                    "database": instance.database_path,
                    "already_open": already_open,
                    "pid": instance.pid,
                    "socket_path": str(instance.socket_path),
                },
                backend="idalib",
            )

        database = str(request.database or "").strip()
        if not database:
            raise RuntimeError("idalib commands require a database context")

        if request.op == "db_close":
            instance = _find_instance_for_database(database)
            if instance is None:
                return response_ok(_already_closed_result(database), backend="idalib")
            try:
                if not _probe_instance(instance, timeout=timeout):
                    return response_ok(_already_closed_result(database), backend="idalib")
            except socket.timeout as exc:
                raise _timeout_error(request.op, timeout) from exc
        else:
            try:
                instance, _ = _ensure_instance_for_database(
                    database,
                    timeout=timeout,
                    run_auto_analysis=True,
                    start_if_missing=True,
                )
            except socket.timeout as exc:
                raise _timeout_error(request.op, timeout) from exc

        payload = {
            "version": WIRE_PROTOCOL_VERSION,
            "op": request.op,
            "params": request.params,
        }
        try:
            return _socket_request(instance.socket_path, payload, timeout=timeout)
        except socket.timeout as exc:
            raise _timeout_error(request.op, timeout) from exc
