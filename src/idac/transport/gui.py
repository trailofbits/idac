from __future__ import annotations

import contextlib
import errno
import json
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..metadata import WIRE_PROTOCOL_VERSION
from ..paths import bridge_registry_paths, bridge_socket_filename, user_runtime_dir
from ..version import VERSION
from .common import normalize_timeout, pid_is_live, recv_all, require_timeout_for_operation
from .schema import RequestEnvelope, response_ok

TRANSIENT_SOCKET_ERRNOS = {
    errno.ECONNREFUSED,
    errno.ENOENT,
}

_IGNORED_SHUTDOWN_ERRNOS = {
    errno.ENOTCONN,
}


class StaleBridgeInstanceError(RuntimeError):
    """Raised when a GUI bridge registry entry points at a dead instance."""

    pass


def _format_discovery_warning(message: str, *, registry_path: Optional[Path] = None) -> str:
    """Attach registry context to a GUI discovery warning when available."""

    if registry_path is None:
        return message
    return f"{message} [{registry_path}]"


def _append_discovery_warning(
    warnings: Optional[list[str]],
    message: str,
    *,
    registry_path: Optional[Path] = None,
) -> None:
    if warnings is not None:
        warnings.append(_format_discovery_warning(message, registry_path=registry_path))


@dataclass
class BridgeInstance:
    """A single live GUI bridge instance discovered from the registry."""

    pid: int
    socket_path: Path
    registry_path: Path
    plugin_name: str
    plugin_version: str
    started_at: Optional[str] = None
    instance_id: Optional[str] = None
    state: str = "ready"
    meta: dict[str, Any] = field(default_factory=dict)


class GuiBackend:
    name = "gui"

    def send(self, request: RequestEnvelope) -> dict[str, Any]:
        """Route a request to the correct GUI instance and merge warnings."""

        timeout = normalize_timeout(request.timeout)
        require_timeout_for_operation(request.op, timeout)
        if request.op == "list_targets":
            warnings: list[str] = []
            return response_ok(
                list_targets(
                    timeout=timeout,
                    warnings=warnings,
                    require_matching_version=True,
                ),
                backend="gui",
                warnings=warnings,
            )
        warnings = []
        instance, normalized_target = choose_instance(
            request.target,
            timeout=timeout,
            warnings=warnings,
        )
        _ensure_instance_version_match(instance)
        forwarded = RequestEnvelope(
            op=request.op,
            params=dict(request.params),
            backend=request.backend,
            target=normalized_target,
            database=request.database,
            timeout=timeout,
        )
        response = _send_request_to_instance(instance, forwarded)
        if warnings:
            response = dict(response)
            response["warnings"] = warnings + list(response.get("warnings") or [])
        return response


def _list_targets_request(*, timeout: Optional[float] = None) -> RequestEnvelope:
    """Build the internal ``list_targets`` request used during discovery."""

    return RequestEnvelope(op="list_targets", backend="gui", timeout=timeout)


def _bridge_status_request(*, timeout: Optional[float] = None) -> RequestEnvelope:
    """Build the internal ``bridge_status`` probe request used during discovery."""

    return RequestEnvelope(op="bridge_status", backend="gui", timeout=timeout)


def _purge_stale_registry(registry_path: Path) -> None:
    """Best-effort removal of a stale GUI bridge registry file."""

    with contextlib.suppress(OSError):
        registry_path.unlink()


def _is_expected_bridge_socket_path(*, pid: int, socket_path: Path) -> bool:
    """Return whether ``socket_path`` is the expected runtime bridge socket for ``pid``."""

    expected = (user_runtime_dir() / bridge_socket_filename(pid)).resolve(strict=False)
    candidate = socket_path.expanduser().resolve(strict=False)
    return candidate == expected


def _purge_stale_instance_files(*, registry_path: Path, socket_path: Optional[Path] = None) -> None:
    """Best-effort removal of stale GUI bridge registry/socket files."""

    _purge_stale_registry(registry_path)
    if socket_path is None:
        return
    pid_text = registry_path.stem.rsplit("-", 1)[-1]
    try:
        pid = int(pid_text)
    except ValueError:
        return
    if not _is_expected_bridge_socket_path(pid=pid, socket_path=socket_path):
        return
    with contextlib.suppress(OSError):
        socket_path.unlink()


def _pid_command_line(pid: int) -> Optional[str]:
    """Return the process command line for ``pid`` when it can be queried safely."""

    try:
        proc = subprocess.run(
            ["ps", "-o", "args=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    return lines[0]


def _pid_non_gui_bridge_reason(pid: int) -> Optional[str]:
    """Return a rejection reason when a live pid clearly is not an IDA GUI host."""

    command_line = _pid_command_line(pid)
    if not command_line:
        return None
    if "idac.transport.idalib_server" in command_line:
        return "process is running the idalib worker, not an IDA GUI session"
    return None


def _load_instance(
    path: Path,
    *,
    warnings: Optional[list[str]] = None,
) -> Optional[BridgeInstance]:
    """Load one registry file, purging obviously stale entries on the way."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        socket_path = Path(payload["socket_path"])
        pid = int(payload["pid"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        _append_discovery_warning(
            warnings,
            "ignored unreadable or malformed GUI bridge registry",
            registry_path=path,
        )
        return None

    if not socket_path.exists():
        _append_discovery_warning(
            warnings,
            f"purged stale GUI bridge registry for pid {pid}: missing socket {socket_path}",
            registry_path=path,
        )
        _purge_stale_registry(path)
        return None

    if not pid_is_live(pid):
        _append_discovery_warning(
            warnings,
            f"purged stale GUI bridge registry for pid {pid}: process is not running",
            registry_path=path,
        )
        _purge_stale_instance_files(registry_path=path, socket_path=socket_path)
        return None

    non_gui_reason = _pid_non_gui_bridge_reason(pid)
    if non_gui_reason is not None:
        _append_discovery_warning(
            warnings,
            f"purged stale GUI bridge registry for pid {pid}: {non_gui_reason}",
            registry_path=path,
        )
        _purge_stale_instance_files(registry_path=path, socket_path=socket_path)
        return None

    return BridgeInstance(
        pid=pid,
        socket_path=socket_path,
        registry_path=path,
        plugin_name=str(payload.get("plugin_name", "idac_bridge")),
        plugin_version=str(payload.get("plugin_version", "0")),
        started_at=payload.get("started_at"),
        instance_id=None if payload.get("instance_id") in (None, "") else str(payload.get("instance_id")),
        state=str(payload.get("state") or "ready"),
        meta=payload,
    )


def _is_stale_instance(instance: BridgeInstance, *, error: Optional[OSError] = None) -> bool:
    """Classify a bridge instance as stale using both pid and socket state."""

    socket_exists = instance.socket_path.exists()
    pid_live = pid_is_live(instance.pid)
    if error is not None and error.errno in TRANSIENT_SOCKET_ERRNOS and socket_exists and pid_live:
        return False
    return not socket_exists or not pid_live


def _ensure_instance_version_match(instance: BridgeInstance) -> None:
    """Reject GUI bridge instances built from a different idac version."""

    if instance.plugin_version == VERSION:
        return
    raise RuntimeError(
        "IDA GUI bridge version mismatch for "
        f"pid {instance.pid}: plugin={instance.plugin_version}, cli={VERSION}. "
        "Reinstall the plugin so the versions match."
    )


def _probe_timeout(timeout: Optional[float]) -> Optional[float]:
    return timeout


def _validate_instance_status(instance: BridgeInstance, status: dict[str, Any]) -> BridgeInstance:
    """Validate a live bridge status payload against the discovered registry."""

    try:
        status_pid = int(status["pid"])
        status_socket_path = Path(str(status["socket_path"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("bridge_status payload was missing required identity fields") from exc

    if status_pid != instance.pid:
        raise StaleBridgeInstanceError(
            f"GUI bridge pid changed during discovery: registry={instance.pid}, socket={status_pid}"
        )
    if status_socket_path != instance.socket_path:
        raise StaleBridgeInstanceError(
            "GUI bridge socket path changed during discovery: "
            f"registry={instance.socket_path}, socket={status_socket_path}"
        )

    status_instance_id_raw = status.get("instance_id")
    status_instance_id = None if status_instance_id_raw in (None, "") else str(status_instance_id_raw)
    if instance.instance_id is not None and status_instance_id != instance.instance_id:
        raise StaleBridgeInstanceError(
            "GUI bridge instance id changed during discovery: "
            f"registry={instance.instance_id}, socket={status_instance_id}"
        )

    status_started_at_raw = status.get("started_at")
    status_started_at = None if status_started_at_raw in (None, "") else str(status_started_at_raw)
    if instance.started_at is not None and status_started_at is not None and status_started_at != instance.started_at:
        raise StaleBridgeInstanceError(
            "GUI bridge start time changed during discovery: "
            f"registry={instance.started_at}, socket={status_started_at}"
        )

    return BridgeInstance(
        pid=status_pid,
        socket_path=status_socket_path,
        registry_path=instance.registry_path,
        plugin_name=str(status.get("plugin_name", instance.plugin_name)),
        plugin_version=str(status.get("plugin_version", instance.plugin_version)),
        started_at=status_started_at,
        instance_id=status_instance_id,
        state=str(status.get("state") or instance.state or "ready"),
        meta={**instance.meta, **status},
    )


def _probe_instance_status(instance: BridgeInstance, *, timeout: Optional[float]) -> BridgeInstance:
    """Probe a bridge instance over the socket and confirm its identity/state."""

    response = _send_request_to_instance(instance, _bridge_status_request(timeout=timeout))
    if not response.get("ok"):
        detail = str(response.get("error") or "bridge_status failed")
        error_kind = str(response.get("error_kind") or "")
        if error_kind == "startup_incomplete":
            raise RuntimeError(f"IDA GUI bridge pid {instance.pid} is still starting")
        if error_kind == "draining":
            raise RuntimeError(f"IDA GUI bridge pid {instance.pid} is draining")
        if "unknown operation" in detail and "bridge_status" in detail:
            return instance
        raise RuntimeError(f"IDA GUI bridge pid {instance.pid} failed bridge_status: {detail}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"IDA GUI bridge pid {instance.pid} returned malformed bridge_status")
    validated = _validate_instance_status(instance, result)
    if validated.state != "ready":
        raise RuntimeError(f"IDA GUI bridge pid {instance.pid} is not ready: state={validated.state}")
    return validated


def _discovered_instances(
    *,
    warnings: Optional[list[str]] = None,
) -> list[BridgeInstance]:
    """Return GUI bridge instances discovered from registry files only."""

    instances: list[BridgeInstance] = []
    for registry in bridge_registry_paths():
        instance = _load_instance(registry, warnings=warnings)
        if instance is not None:
            instances.append(instance)
    return instances


def _probe_discovered_instance(
    instance: BridgeInstance,
    *,
    timeout: Optional[float] = None,
    warnings: Optional[list[str]] = None,
) -> Optional[BridgeInstance]:
    """Validate one registry-discovered bridge instance over the socket."""

    probe_timeout = _probe_timeout(timeout)
    try:
        return _probe_instance_status(instance, timeout=probe_timeout)
    except StaleBridgeInstanceError:
        _append_discovery_warning(
            warnings,
            f"purged stale GUI bridge registry for pid {instance.pid}: bridge identity changed",
            registry_path=instance.registry_path,
        )
        _purge_stale_registry(instance.registry_path)
        return None
    except RuntimeError as exc:
        _append_discovery_warning(
            warnings,
            str(exc),
            registry_path=instance.registry_path,
        )
        return None


def _live_instances(
    *,
    timeout: Optional[float] = None,
    warnings: Optional[list[str]] = None,
) -> list[BridgeInstance]:
    """Return registry-discovered instances that also pass live bridge probing."""

    instances: list[BridgeInstance] = []
    for instance in _discovered_instances(warnings=warnings):
        validated = _probe_discovered_instance(instance, timeout=timeout, warnings=warnings)
        if validated is not None:
            instances.append(validated)
    return instances


def list_instances(
    *,
    timeout: Optional[float] = None,
    warnings: Optional[list[str]] = None,
) -> list[BridgeInstance]:
    """Return all currently discoverable live GUI bridge instances."""

    return _live_instances(timeout=timeout, warnings=warnings)


def list_discovered_instances(
    *,
    warnings: Optional[list[str]] = None,
) -> list[BridgeInstance]:
    """Return registry-discovered GUI bridge instances before socket probing."""

    return _discovered_instances(warnings=warnings)


def _instance_selector(instance: BridgeInstance) -> str:
    """Return the canonical selector string for a bridge instance."""

    return f"pid:{instance.pid}"


def _normalize_target_row(instance: BridgeInstance, item: dict[str, Any]) -> dict[str, Any]:
    """Expand a per-instance target row into the CLI's global target shape."""

    local_target_id = str(item.get("target_id") or "active")
    local_selector = str(item.get("selector") or local_target_id)
    instance_selector = _instance_selector(instance)
    return {
        **item,
        "local_target_id": local_target_id,
        "local_selector": local_selector,
        "target_id": f"{instance.pid}:{local_target_id}",
        "selector": instance_selector,
        "instance_pid": instance.pid,
        "instance_selector": instance_selector,
    }


def _pid_selector_match(instance: BridgeInstance, selector_text: str) -> Optional[str]:
    """Match selectors that name an instance without naming a subtarget."""

    if selector_text in {str(instance.pid), _instance_selector(instance)}:
        return "active"
    return None


def _target_aliases(item: dict[str, Any]) -> set[str]:
    """Return all textual aliases that may identify one GUI target row."""

    return {
        str(item.get("target_id") or ""),
        str(item.get("selector") or ""),
        str(item.get("local_selector") or ""),
        str(item.get("filename") or ""),
        str(item.get("module") or ""),
        str(item.get("instance_selector") or ""),
    }


def _select_instance_target(
    instance: BridgeInstance,
    selector_text: str,
    *,
    timeout: Optional[float] = None,
    warnings: Optional[list[str]] = None,
) -> Optional[str]:
    """Return the local target id selected within a single GUI instance."""

    pid_match = _pid_selector_match(instance, selector_text)
    if pid_match is not None:
        return pid_match
    for item in _instance_target_rows(instance, timeout=timeout, warnings=warnings):
        if selector_text in _target_aliases(item):
            return str(item.get("local_target_id") or "active")
    return None


def _instance_target_rows(
    instance: BridgeInstance,
    *,
    timeout: Optional[float] = None,
    warnings: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """Fetch and normalize ``list_targets`` rows for one GUI instance."""

    try:
        response = _send_request_to_instance(instance, _list_targets_request(timeout=timeout))
    except StaleBridgeInstanceError:
        _append_discovery_warning(
            warnings,
            f"purged stale GUI bridge registry for pid {instance.pid}: bridge socket stopped responding",
            registry_path=instance.registry_path,
        )
        _purge_stale_registry(instance.registry_path)
        return []
    if not response.get("ok"):
        detail = str(response.get("error") or "request failed")
        raise RuntimeError(f"IDA GUI bridge pid {instance.pid} failed list_targets: {detail}")
    result = response.get("result")
    if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
        raise RuntimeError(f"IDA GUI bridge pid {instance.pid} returned malformed list_targets")
    return [_normalize_target_row(instance, item) for item in result]


def _selection_error(message: str, *, warnings: Optional[list[str]] = None) -> RuntimeError:
    detail_parts = [f"runtime_dir={user_runtime_dir()}"]
    if warnings:
        detail_parts.append("diagnostics=" + " | ".join(warnings[:3]))
    return RuntimeError(f"{message}. " + "; ".join(detail_parts))


def list_targets(
    *,
    timeout: Optional[float] = None,
    warnings: Optional[list[str]] = None,
    require_matching_version: bool = False,
) -> list[dict[str, Any]]:
    """List all GUI targets currently exposed across running bridge instances."""

    rows: list[dict[str, Any]] = []
    for instance in list_instances(timeout=timeout, warnings=warnings):
        if require_matching_version:
            _ensure_instance_version_match(instance)
        rows.extend(_instance_target_rows(instance, timeout=timeout, warnings=warnings))
    rows.sort(key=lambda item: (str(item.get("module") or ""), int(item.get("instance_pid") or 0)))
    return rows


def _explicit_instance_match(instance: BridgeInstance, selector_text: str) -> bool:
    """Return whether ``selector_text`` explicitly identifies ``instance``."""

    if _pid_selector_match(instance, selector_text) is not None:
        return True
    pid_text, sep, _rest = selector_text.partition(":")
    return bool(sep and pid_text == str(instance.pid))


def choose_instance(
    selector: Optional[str],
    *,
    timeout: Optional[float] = None,
    warnings: Optional[list[str]] = None,
) -> tuple[BridgeInstance, Optional[str]]:
    """Resolve a user selector to a specific GUI bridge instance and target."""

    discovered = _discovered_instances(warnings=warnings)
    if not discovered:
        raise _selection_error("No running IDA GUI bridge instances found", warnings=warnings)
    if selector in (None, ""):
        instances = _live_instances(timeout=timeout, warnings=warnings)
        if not instances:
            raise _selection_error("No running IDA GUI bridge instances found", warnings=warnings)
        if len(instances) == 1:
            return instances[0], None
        raise RuntimeError("Multiple running IDA GUI bridge instances found; pass -c pid:<pid>")

    selector_text = str(selector).strip()
    explicit_matches = [instance for instance in discovered if _explicit_instance_match(instance, selector_text)]
    if len(explicit_matches) == 1:
        validated = _probe_discovered_instance(explicit_matches[0], timeout=timeout, warnings=warnings)
        if validated is None:
            raise _selection_error(
                f"No running IDA GUI target matched {selector_text!r}",
                warnings=warnings,
            )
        local_target_id = _select_instance_target(
            validated,
            selector_text,
            timeout=timeout,
            warnings=warnings,
        )
        if local_target_id is None:
            raise _selection_error(
                f"No running IDA GUI target matched {selector_text!r}",
                warnings=warnings,
            )
        return validated, local_target_id

    instances = _live_instances(timeout=timeout, warnings=warnings)
    if not instances:
        raise _selection_error("No running IDA GUI bridge instances found", warnings=warnings)
    matches: list[tuple[BridgeInstance, str]] = []
    for instance in instances:
        local_target_id = _select_instance_target(
            instance,
            selector_text,
            timeout=timeout,
            warnings=warnings,
        )
        if local_target_id is not None:
            matches.append((instance, local_target_id))

    if not matches:
        raise _selection_error(
            f"No running IDA GUI target matched {selector_text!r}",
            warnings=warnings,
        )
    if len(matches) > 1:
        raise RuntimeError(
            f"Target selector {selector_text!r} is ambiguous; use a more specific selector such as pid:<pid>"
        )
    return matches[0]


def _request_payload(request: RequestEnvelope) -> dict[str, Any]:
    """Encode a request envelope into the wire payload sent to the plugin."""

    payload = {
        "version": WIRE_PROTOCOL_VERSION,
        "id": str(uuid.uuid4()),
        "op": request.op,
        "params": request.params,
    }
    if request.target is not None:
        payload["target"] = request.target
    return payload


def _socket_request(
    socket_path: Path,
    encoded: bytes,
    *,
    timeout: float | None,
) -> list[bytes]:
    """Perform one request/response round-trip over the GUI bridge socket."""

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.connect(str(socket_path))
        sock.sendall(encoded)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError as exc:
            if exc.errno not in _IGNORED_SHUTDOWN_ERRNOS:
                raise
        return recv_all(sock)


def _decode_response(chunks: list[bytes]) -> dict[str, Any]:
    """Decode a JSON response from raw socket chunks."""

    if not chunks:
        raise RuntimeError("IDA GUI bridge returned an empty response")
    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("IDA GUI bridge returned malformed JSON") from exc
    if not isinstance(response, dict):
        raise RuntimeError("IDA GUI bridge returned a malformed response")
    return response


def _send_request_to_instance(
    instance: BridgeInstance,
    request: RequestEnvelope,
    *,
    connect_retries: int = 4,
) -> dict[str, Any]:
    """Send a request to one GUI instance with transient socket retries."""

    encoded = (json.dumps(_request_payload(request)) + "\n").encode("utf-8")
    chunks: list[bytes] = []
    last_error: Optional[OSError] = None
    timeout = normalize_timeout(request.timeout)
    for attempt in range(connect_retries):
        try:
            chunks = _socket_request(instance.socket_path, encoded, timeout=timeout)
            break
        except OSError as exc:
            last_error = exc
            if exc.errno not in TRANSIENT_SOCKET_ERRNOS or attempt == connect_retries - 1:
                break
            time.sleep(0.05 * (attempt + 1))

    if last_error is not None and not chunks:
        message = f"Failed to contact IDA GUI bridge pid {instance.pid} at {instance.socket_path}: {last_error}"
        if _is_stale_instance(instance, error=last_error):
            raise StaleBridgeInstanceError(message) from last_error
        raise RuntimeError(message) from last_error

    return _decode_response(chunks)
