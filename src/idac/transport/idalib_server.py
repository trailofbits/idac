from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import socketserver
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Optional

from ..metadata import WIRE_PROTOCOL_VERSION, idalib_registry_payload
from ..ops.dispatch import build_operation_registry
from ..ops.runtime import IdaOperationError, IdaRuntime
from ..paths import (
    ensure_user_runtime_dir,
    idalib_registry_path,
    idalib_registry_paths,
    idalib_socket_path,
)
from .common import atomic_write_json, pid_is_live, read_request_bytes
from .idalib_common import (
    WorkerError,
    bootstrap_idapro,
    build_target_row,
    load_registry,
    normalize_database_path,
)
from .schema import response_error, response_ok

OPEN_DATABASE_AUTO_ANALYSIS = True
REQUEST_MAX_BYTES = 1_048_576
REQUEST_READ_TIMEOUT = 300.0


def _idalib_log(message: str, *, exc: BaseException | None = None) -> None:
    lines = [f"[idac-idalib] {message}\n"]
    if exc is not None:
        lines.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    sys.stderr.write("".join(lines))


def _format_open_error(path: str, rc: int) -> str:
    if rc == 4:
        return f"failed to open database `{path}`: rc=4 (database busy or locked)"
    return f"failed to open database `{path}`: rc={rc}"


def _write_ready(ready_fd: int | None, payload: dict[str, Any]) -> None:
    if ready_fd is None:
        return
    try:
        os.write(ready_fd, (json.dumps(payload) + "\n").encode("utf-8"))
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            os.close(ready_fd)


def _other_live_instance_for_database(database_path: str) -> dict[str, Any] | None:
    normalized = normalize_database_path(database_path)
    for registry_path in idalib_registry_paths():
        payload = load_registry(registry_path)
        if payload is None:
            continue
        try:
            pid = int(payload["pid"])
            candidate_path = normalize_database_path(str(payload["database_path"]))
        except (KeyError, TypeError, ValueError):
            continue
        if pid == os.getpid():
            continue
        if candidate_path != normalized:
            continue
        socket_path = Path(str(payload.get("socket_path") or ""))
        if pid_is_live(pid) and socket_path.exists():
            return payload
    return None


def _parse_request(payload: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise WorkerError(f"unsupported payload type: {type(payload).__name__}")
    version = payload.get("version")
    if version != WIRE_PROTOCOL_VERSION:
        raise WorkerError(f"unsupported protocol version: expected {WIRE_PROTOCOL_VERSION}, got {version!r}")
    op = str(payload.get("op") or "").strip()
    if not op:
        raise WorkerError("idalib backend requires an operation name")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        raise WorkerError("params must be a JSON object")
    return op, dict(params)


class IdaLibService:
    def __init__(self, *, database_path: str, run_auto_analysis: bool) -> None:
        self.idapro = bootstrap_idapro()
        self.database_path = normalize_database_path(database_path)
        self.run_auto_analysis = run_auto_analysis
        self.python_scope: dict[str, Any] = {}
        self._open = False
        self.exit_requested = False
        self._started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._open_database()

    def _open_database(self) -> None:
        open_rc = self.idapro.open_database(self.database_path, self.run_auto_analysis)
        if open_rc != 0:
            raise WorkerError(_format_open_error(self.database_path, open_rc))
        self._open = True

    def close_runtime(self, *, save: bool) -> None:
        if not self._open:
            return
        self.idapro.close_database(save)
        self._open = False

    def list_targets(self) -> list[dict[str, Any]]:
        return [
            build_target_row(
                pid=os.getpid(),
                database_path=self.database_path,
                socket_path=idalib_socket_path(os.getpid()),
            )
        ]

    def _write_registry(self) -> None:
        destination = idalib_registry_path(os.getpid())
        payload = idalib_registry_payload(
            pid=os.getpid(),
            socket_path=str(idalib_socket_path(os.getpid())),
            started_at=self._started_at,
            database_path=self.database_path,
        )
        atomic_write_json(destination, payload)

    def _build_registry(self) -> dict[str, Any]:
        runtime = IdaRuntime(
            database_path=self.database_path,
            python_scope=self.python_scope,
        )
        return build_operation_registry(runtime)

    def _validate_db_save(self, params: dict[str, Any]) -> str | None:
        raw_path = str(params.get("path") or "").strip()
        if not raw_path:
            return None
        normalized = normalize_database_path(raw_path)
        other = _other_live_instance_for_database(normalized)
        if other is not None:
            raise WorkerError(f"another idalib daemon already has `{normalized}` open")
        return normalized

    def _handle_db_close(self, params: dict[str, Any]) -> dict[str, Any]:
        save = not bool(params.get("discard"))
        current_path = self.database_path
        self.close_runtime(save=save)
        self.exit_requested = True
        return {"closed": True, "database": current_path, "saved": save}

    def _dispatch_builtin(self, op: str, params: dict[str, Any]) -> dict[str, Any] | None:
        if op == "daemon_status":
            return response_ok(
                {
                    "running": True,
                    "database_path": self.database_path,
                    "pid": os.getpid(),
                },
                backend="idalib",
            )
        if self.exit_requested:
            return response_error("idalib daemon is shutting down", backend="idalib")
        if op == "list_targets":
            return response_ok(self.list_targets(), backend="idalib")
        if op == "db_close":
            return response_ok(self._handle_db_close(params), backend="idalib")
        return None

    def _dispatch(self, payload: Any) -> dict[str, Any]:
        op = "<unknown>"
        try:
            op, params = _parse_request(payload)
            builtin_response = self._dispatch_builtin(op, params)
            if builtin_response is not None:
                return builtin_response

            registry = self._build_registry()
            if op not in registry:
                return response_error(f"unsupported idalib operation: {op}", backend="idalib")

            requested_save_path = None
            if op == "db_save":
                requested_save_path = self._validate_db_save(params)

            result = registry[op](params)

            if op == "db_save":
                saved_path = requested_save_path or str(result.get("path") or "").strip()
                if saved_path:
                    self.database_path = normalize_database_path(saved_path)
                    self._write_registry()

            return response_ok(result, backend="idalib")
        except (WorkerError, IdaOperationError) as exc:
            return response_error(str(exc), backend="idalib")
        except Exception as exc:
            _idalib_log(f"unexpected server failure while handling `{op}`", exc=exc)
            return response_error(f"unexpected idalib server failure: {exc}", backend="idalib")


class _IdaLibRequestHandler(socketserver.StreamRequestHandler):
    def _write_response(self, response: dict[str, Any]) -> None:
        with contextlib.suppress(BrokenPipeError, OSError):
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))

    def _read_request(self) -> bytes:
        return read_request_bytes(
            self.connection,
            timeout=REQUEST_READ_TIMEOUT,
            max_bytes=REQUEST_MAX_BYTES,
        )

    def handle(self) -> None:
        service = self.server.service  # type: ignore[attr-defined]
        try:
            raw = self._read_request()
        except socket.timeout:
            self._write_response(
                response_error(
                    f"request body read timed out after {int(REQUEST_READ_TIMEOUT)} seconds",
                    backend="idalib",
                )
            )
            return
        except ValueError as exc:
            self._write_response(response_error(str(exc), backend="idalib"))
            return
        if not raw.strip():
            return
        self._write_response(service._dispatch(raw))
        if service.exit_requested:
            threading.Thread(target=self.server.shutdown, daemon=True).start()


class _UnixIdaLibServer(socketserver.UnixStreamServer):
    allow_reuse_address = True
    request_queue_size = 64


def serve(*, database_path: str, run_auto_analysis: bool, ready_fd: int | None = None) -> int:
    ensure_user_runtime_dir()
    socket_path = idalib_socket_path(os.getpid())
    registry_path = idalib_registry_path(os.getpid())
    with contextlib.suppress(FileNotFoundError):
        socket_path.unlink()
    service: IdaLibService | None = None
    server: _UnixIdaLibServer | None = None
    try:
        service = IdaLibService(
            database_path=database_path,
            run_auto_analysis=run_auto_analysis,
        )
        server = _UnixIdaLibServer(str(socket_path), _IdaLibRequestHandler)
        server.service = service  # type: ignore[attr-defined]
        service._write_registry()
        _write_ready(ready_fd, {"ok": True})
        ready_fd = None
        server.serve_forever()
    except Exception as exc:
        _write_ready(ready_fd, {"ok": False, "error": str(exc)})
        raise
    finally:
        if server is not None:
            server.server_close()
        with contextlib.suppress(FileNotFoundError):
            socket_path.unlink()
        with contextlib.suppress(FileNotFoundError):
            registry_path.unlink()
        if service is not None:
            with contextlib.suppress(Exception):
                service.close_runtime(save=False)
        with contextlib.suppress(OSError):
            if ready_fd is not None:
                os.close(ready_fd)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m idac.transport.idalib_server")
    parser.add_argument("--database", required=True, help="Database or input path to open")
    parser.add_argument("--ready-fd", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--no-auto-analysis",
        dest="run_auto_analysis",
        action="store_false",
        help="Open without waiting for auto-analysis",
    )
    parser.set_defaults(run_auto_analysis=OPEN_DATABASE_AUTO_ANALYSIS)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return serve(
            database_path=args.database,
            run_auto_analysis=bool(args.run_auto_analysis),
            ready_fd=args.ready_fd,
        )
    except WorkerError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
