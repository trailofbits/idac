"""Bridge core for parsing envelopes and dispatching operations."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import socketserver
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

import ida_kernwin  # type: ignore

from idac.metadata import BRIDGE_PLUGIN_NAME, bridge_registry_payload
from idac.ops.runtime import IdaOperationError
from idac.transport.common import atomic_write_json, read_request_bytes
from idac.transport.dispatch import DispatcherBusyError, DispatcherStoppedError, DispatchMetrics, SerializedDispatcher
from idac.transport.schema import response_error, response_ok
from idac.version import VERSION

from .handlers import HandlerFn, TargetValidator, build_default_registry
from .protocol import (
    BridgeError,
    EnvelopeParseError,
    UnsupportedOperationError,
    parse_request_envelope,
    registry_path,
    runtime_dir,
    socket_path,
)

BRIDGE_REQUEST_READ_TIMEOUT = 300.0
BRIDGE_REQUEST_MAX_BYTES = 1_048_576
BRIDGE_MAX_PENDING_CALLS = 16
BRIDGE_STOP_DRAIN_TIMEOUT = 5.0


def _bridge_log(message: str, *, exc: BaseException | None = None) -> None:
    lines = [f"[idac] {message}\n"]
    if exc is not None:
        lines.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    text = "".join(lines)
    writer = getattr(ida_kernwin, "msg", None)
    if callable(writer):
        writer(text)
        return
    sys.stderr.write(text)


def _format_log_payload(payload: Any) -> str:
    try:
        if isinstance(payload, bytes):
            text = payload.decode("utf-8", errors="replace").strip()
            if not text:
                return "<empty>"
            payload = json.loads(text)
        if isinstance(payload, (dict, list)):
            return json.dumps(payload, ensure_ascii=False, sort_keys=True)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return str(payload)


class IdacBridge:
    """Minimal backend-contract oriented bridge facade."""

    def __init__(
        self,
        handlers: Optional[dict[str, HandlerFn]] = None,
        *,
        validate_target: TargetValidator | None = None,
        status_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        if handlers is None:
            handlers, default_validate = build_default_registry()
            if validate_target is None:
                validate_target = default_validate
        self.handlers = handlers
        self.validate_target = validate_target
        self.status_provider = status_provider

    def _dispatch(self, op_name: str, params: dict[str, Any], *, target: Optional[str]) -> Any:
        if op_name == "bridge_status":
            if self.status_provider is None:
                raise UnsupportedOperationError("bridge status is unavailable")
            return self.status_provider()
        if op_name != "list_targets" and self.validate_target is not None:
            self.validate_target(target)
        try:
            handler = self.handlers[op_name]
        except KeyError as exc:
            raise UnsupportedOperationError(f"unknown operation '{op_name}'") from exc
        return handler(params)

    def handle_request(self, payload: Any) -> dict[str, Any]:
        request_id: Optional[str] = None
        op_name = "<unknown>"
        try:
            envelope = parse_request_envelope(payload)
            request_id = envelope.request_id
            op_name = envelope.operation
            result = self._dispatch(
                envelope.operation,
                envelope.params,
                target=envelope.target,
            )
            return response_ok(result, backend="gui", request_id=request_id)
        except EnvelopeParseError as exc:
            return response_error(str(exc), backend="gui", request_id=request_id)
        except UnsupportedOperationError as exc:
            return response_error(str(exc), backend="gui", request_id=request_id)
        except IdaOperationError as exc:
            return response_error(str(exc), backend="gui", request_id=request_id)
        except BridgeError as exc:
            _bridge_log(f"GUI bridge request failed for `{op_name}`", exc=exc)
            return response_error(str(exc), backend="gui", request_id=request_id)
        except Exception as exc:
            _bridge_log(f"GUI bridge request raised an internal error for `{op_name}`", exc=exc)
            return response_error(str(exc) or exc.__class__.__name__, backend="gui", request_id=request_id)


class _BridgeRequestHandler(socketserver.StreamRequestHandler):
    def _write_response(self, response: dict[str, Any]) -> None:
        with contextlib.suppress(BrokenPipeError, OSError):
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))

    def _read_request(self) -> bytes:
        return read_request_bytes(
            self.connection,
            timeout=BRIDGE_REQUEST_READ_TIMEOUT,
            max_bytes=BRIDGE_REQUEST_MAX_BYTES,
        )

    def handle(self) -> None:
        service = self.server.service  # type: ignore[attr-defined]
        try:
            raw = self._read_request()
        except socket.timeout:
            self._write_response(
                response_error(
                    f"request body read timed out after {int(BRIDGE_REQUEST_READ_TIMEOUT)} seconds",
                    backend="gui",
                )
            )
            return
        except ValueError as exc:
            self._write_response(response_error(str(exc), backend="gui"))
            return
        if not raw.strip():
            return

        self._write_response(service.dispatch_request(raw))


class _ThreadedUnixBridgeServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


def _run_on_main_thread(fn: Any) -> Any:
    holder: dict[str, Any] = {}

    def _dispatch() -> int:
        holder["result"] = fn()
        return 1

    # Possible future improvement: dispatch obviously non-mutating ops with
    # MFF_READ. In practice this is probably not worth doing. Read-only IDA
    # work such as decompilation can still trigger database writes, and users
    # have reported hangs with MFF_READ in similar bridges.
    ida_kernwin.execute_sync(_dispatch, ida_kernwin.MFF_WRITE)
    return holder.get("result")


class BridgeService:
    """Minimal Unix-socket service wrapper for the GUI bridge."""

    def __init__(self, bridge: Optional[IdacBridge] = None) -> None:
        self._instance_id = str(uuid.uuid4())
        self._started_at: str | None = None
        self._state = "stopped"
        self.bridge = bridge or IdacBridge()
        self.bridge.status_provider = self.status_snapshot
        self._dispatcher = SerializedDispatcher(
            "idac-gui",
            runner=_run_on_main_thread,
            max_pending=BRIDGE_MAX_PENDING_CALLS,
        )
        self._server: Optional[_ThreadedUnixBridgeServer] = None
        self._thread: Optional[threading.Thread] = None
        self.request_logging_enabled = False
        self.response_logging_enabled = False

    def start(self) -> None:
        runtime_dir().mkdir(parents=True, exist_ok=True)
        pid = os.getpid()
        path = socket_path(pid)
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        self._started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._state = "starting"
        self._dispatcher.start()
        server = _ThreadedUnixBridgeServer(str(path), _BridgeRequestHandler)
        server.service = self  # type: ignore[attr-defined]
        self._server = server
        self._write_registry(path)
        thread = threading.Thread(target=server.serve_forever, name="idac-bridge", daemon=True)
        thread.start()
        self._thread = thread
        self._state = "ready"
        self._write_registry(path)

    def stop(self) -> None:
        server = self._server
        self._state = "draining"
        if server is not None:
            self._write_registry(socket_path(os.getpid()))
            server.shutdown()
            server.server_close()
            self._server = None
            if not self._dispatcher.wait_for_idle(timeout=BRIDGE_STOP_DRAIN_TIMEOUT):
                _bridge_log("GUI bridge drain timed out; forcing dispatcher shutdown")
        self._dispatcher.stop()
        with contextlib.suppress(FileNotFoundError):
            socket_path(os.getpid()).unlink()
        with contextlib.suppress(FileNotFoundError):
            registry_path(os.getpid()).unlink()
        self._thread = None
        self._state = "stopped"

    def dispatch_request(self, raw: bytes) -> dict[str, Any]:
        request_id, op_name = _best_effort_request_info(raw)
        if self.request_logging_enabled:
            _bridge_log(f"GUI bridge request: {_format_log_payload(raw)}")
        metrics: DispatchMetrics | None = None
        if self._state == "starting":
            response = response_error(
                "IDA GUI bridge is still starting",
                backend="gui",
                request_id=request_id,
                error_kind="startup_incomplete",
            )
        elif self._state != "ready":
            response = response_error(
                "IDA GUI bridge is draining",
                backend="gui",
                request_id=request_id,
                error_kind="draining",
            )
        else:
            try:
                response, metrics = self._dispatcher.call_with_metrics(
                    "bridge-request",
                    lambda: self.bridge.handle_request(raw),
                )
            except DispatcherBusyError as exc:
                response = response_error(
                    str(exc),
                    backend="gui",
                    request_id=request_id,
                    error_kind="busy",
                )
            except DispatcherStoppedError as exc:
                response = response_error(
                    str(exc),
                    backend="gui",
                    request_id=request_id,
                    error_kind="draining",
                )
        if self.response_logging_enabled:
            _bridge_log(f"GUI bridge response: {_format_log_payload(response)}")
        if (self.request_logging_enabled or self.response_logging_enabled) and metrics is not None:
            _bridge_log(
                "GUI bridge timings: "
                f"id={request_id or '<unknown>'}, op={op_name}, "
                f"queue_depth={metrics.queue_depth_at_enqueue}, "
                f"queue_wait={metrics.queue_wait_seconds:.3f}s, "
                f"run={metrics.run_seconds:.3f}s"
            )
        return response

    def status_snapshot(self) -> dict[str, Any]:
        pid = os.getpid()
        return {
            "pid": pid,
            "socket_path": str(socket_path(pid)),
            "instance_id": self._instance_id,
            "state": self._state,
            "plugin_name": BRIDGE_PLUGIN_NAME,
            "plugin_version": VERSION,
            "started_at": self._started_at,
            "queue_depth": self._dispatcher.pending_count(),
            "queue_capacity": self._dispatcher.max_pending(),
        }

    def set_request_logging_enabled(self, enabled: bool) -> bool:
        self.request_logging_enabled = bool(enabled)
        return self.request_logging_enabled

    def toggle_request_logging(self) -> bool:
        return self.set_request_logging_enabled(not self.request_logging_enabled)

    def set_response_logging_enabled(self, enabled: bool) -> bool:
        self.response_logging_enabled = bool(enabled)
        return self.response_logging_enabled

    def toggle_response_logging(self) -> bool:
        return self.set_response_logging_enabled(not self.response_logging_enabled)

    def _write_registry(self, sock_path: Path) -> None:
        payload = bridge_registry_payload(
            pid=os.getpid(),
            socket_path=str(sock_path),
            started_at=self._started_at,
        )
        payload["instance_id"] = self._instance_id
        payload["state"] = self._state
        destination = registry_path(os.getpid())
        atomic_write_json(destination, payload)


def _best_effort_request_info(raw: bytes) -> tuple[Optional[str], str]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return None, "<unknown>"
    if not isinstance(payload, dict):
        return None, "<unknown>"
    request_id = payload.get("id")
    op_name = str(payload.get("op") or "<unknown>")
    return (None if request_id in (None, "") else str(request_id), op_name)
