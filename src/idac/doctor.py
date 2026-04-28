from __future__ import annotations

import filecmp
import json
import sys
from pathlib import Path
from typing import Any, Optional

from .metadata import BRIDGE_SOCKET_PREFIX, IDALIB_SOCKET_PREFIX
from .paths import (
    bridge_registry_paths,
    idalib_registry_paths,
    plugin_bootstrap_install_path,
    plugin_bootstrap_source_path,
    plugin_install_dir,
    plugin_runtime_package_install_dir,
    plugin_runtime_package_source_dir,
    plugin_source_dir,
    user_runtime_dir,
)
from .transport import gui, send_request
from .transport.common import pid_is_live
from .transport.idalib_common import bootstrap_idapro as _bootstrap_idapro
from .transport.idalib_common import candidate_ida_dirs as _candidate_ida_dirs
from .transport.schema import RequestEnvelope
from .version import VERSION


def _check(status: str, component: str, name: str, summary: str, **details: Any) -> dict[str, Any]:
    return {
        "status": status,
        "component": component,
        "name": name,
        "summary": summary,
        "details": details,
    }


def _symlink_target(path: Path) -> Optional[Path]:
    try:
        return path.resolve(strict=True)
    except OSError:
        return None


def _relative_file_set(root: Path) -> set[Path]:
    return {path.relative_to(root) for path in root.rglob("*") if path.is_file()}


def _install_matches_source(install_path: Path, source_path: Path) -> tuple[bool, str, dict[str, Any]]:
    source_resolved = source_path.resolve()
    install_resolved = _symlink_target(install_path)
    details: dict[str, Any] = {
        "install_path": str(install_path),
        "source_path": str(source_path),
        "resolved_path": None if install_resolved is None else str(install_resolved),
    }
    if install_resolved == source_resolved:
        return True, "installed path points at the repo source", details
    if source_path.is_dir() != install_path.is_dir():
        return False, "installed path kind does not match the repo source", details
    if source_path.is_file():
        matches = filecmp.cmp(source_path, install_path, shallow=False)
        return (
            matches,
            "installed file matches the repo source" if matches else "installed file differs from the repo source",
            details,
        )

    source_files = _relative_file_set(source_path)
    install_files = _relative_file_set(install_path)
    if source_files != install_files:
        details["missing_files"] = sorted(str(path) for path in source_files - install_files)[:10]
        details["extra_files"] = sorted(str(path) for path in install_files - source_files)[:10]
        return False, "installed directory contents differ from the repo source", details
    for relative_path in sorted(source_files):
        if not filecmp.cmp(source_path / relative_path, install_path / relative_path, shallow=False):
            details["mismatched_file"] = str(relative_path)
            return False, "installed directory contents differ from the repo source", details
    return True, "installed directory contents match the repo source", details


def _plugin_check(component: str, name: str, install_path: Path, source_path: Path) -> dict[str, Any]:
    if not source_path.exists():
        return _check(
            "error",
            component,
            name,
            f"missing source path: {source_path}",
            install_path=str(install_path),
            source_path=str(source_path),
        )
    if not install_path.exists():
        return _check(
            "error",
            component,
            name,
            f"missing install path: {install_path}",
            install_path=str(install_path),
            source_path=str(source_path),
        )
    matches, summary, details = _install_matches_source(install_path, source_path)
    if not matches:
        return _check("error", component, name, summary, **details)
    return _check(
        "ok",
        component,
        name,
        summary,
        **details,
    )


def _doctor_gui(*, timeout: Optional[float]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    checks.append(
        _plugin_check(
            "gui",
            "plugin_package",
            plugin_install_dir(),
            plugin_source_dir(),
        )
    )
    checks.append(
        _plugin_check(
            "gui",
            "plugin_bootstrap",
            plugin_bootstrap_install_path(),
            plugin_bootstrap_source_path(),
        )
    )
    checks.append(
        _plugin_check(
            "gui",
            "plugin_runtime_package",
            plugin_runtime_package_install_dir(),
            plugin_runtime_package_source_dir(),
        )
    )

    runtime_dir = user_runtime_dir()
    registry_paths = bridge_registry_paths()
    checks.append(
        _check(
            "ok",
            "gui",
            "runtime_dir",
            "runtime directory is available",
            runtime_dir=str(runtime_dir),
            registry_count=len(registry_paths),
        )
    )

    discovery_warnings: list[str] = []
    try:
        targets = gui.list_targets(timeout=timeout, warnings=discovery_warnings)
        instances = gui.list_instances()
    except (OSError, RuntimeError, ValueError) as exc:
        checks.append(
            _check(
                "error",
                "gui",
                "bridge_targets",
                f"failed to enumerate running GUI bridge targets: {exc}",
                timeout=timeout,
            )
        )
        return checks

    if discovery_warnings:
        checks.append(
            _check(
                "warn",
                "gui",
                "bridge_discovery",
                f"GUI bridge discovery reported {len(discovery_warnings)} issue(s)",
                warnings=discovery_warnings,
            )
        )

    if not instances:
        checks.append(
            _check(
                "warn",
                "gui",
                "bridge_targets",
                "no running GUI bridge instances found",
                timeout=timeout,
            )
        )
        return checks

    for item in checks:
        if (
            item.get("component") == "gui"
            and item.get("name") in {"plugin_package", "plugin_bootstrap", "plugin_runtime_package"}
            and item.get("status") == "error"
        ):
            item["status"] = "warn"
            item["summary"] = (
                f"{item.get('summary', '')}; this install mismatch does not block the current running GUI bridge"
            ).strip()

    mismatched = [
        {
            "pid": instance.pid,
            "plugin_version": instance.plugin_version,
        }
        for instance in instances
        if instance.plugin_version != VERSION
    ]
    if mismatched:
        checks.append(
            _check(
                "error",
                "gui",
                "bridge_version",
                "running GUI bridge version does not match the CLI",
                cli_version=VERSION,
                mismatched=mismatched,
            )
        )
    else:
        checks.append(
            _check(
                "ok",
                "gui",
                "bridge_version",
                "running GUI bridge versions match the CLI",
                cli_version=VERSION,
                instance_count=len(instances),
            )
        )

    checks.append(
        _check(
            "ok",
            "gui",
            "bridge_targets",
            f"found {len(targets)} GUI target(s)",
            targets=targets,
        )
    )
    return checks


def _idalib_candidate_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in _candidate_ida_dirs():
        python_dir = candidate / "idalib" / "python"
        rows.append(
            {
                "path": str(candidate),
                "python_dir": str(python_dir),
                "exists": python_dir.exists(),
            }
        )
    return rows


def _idalib_install_dirs_check() -> dict[str, Any]:
    candidate_rows = _idalib_candidate_rows()
    status = "ok" if any(item["exists"] for item in candidate_rows) else "error"
    summary = (
        "found at least one usable IDA install directory"
        if status == "ok"
        else "no usable IDA install directories were found"
    )
    return _check(
        status,
        "idalib",
        "install_dirs",
        summary,
        candidates=candidate_rows,
    )


def _idalib_import_checks(database: Optional[str]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    candidates = _candidate_ida_dirs()
    try:
        idapro = _bootstrap_idapro()
    except RuntimeError as exc:
        checks.append(
            _check(
                "error",
                "idalib",
                "idapro_import",
                f"failed to import idapro: {exc}",
            )
        )
        return checks

    checks.append(
        _check(
            "ok",
            "idalib",
            "idapro_import",
            "idapro imported successfully",
            module_path=str(getattr(idapro, "__file__", "")),
            candidates=[str(path) for path in candidates],
        )
    )
    checks.append(_idalib_hexrays_check(database))
    return checks


def _idalib_hexrays_probe(database: str) -> bool:
    probe = send_request(
        RequestEnvelope(
            op="python_exec",
            backend="idalib",
            database=database,
            params={"script": ("import ida_hexrays\nresult = {'available': bool(ida_hexrays.init_hexrays_plugin())}")},
        )
    )
    probe_result = probe.get("result") if isinstance(probe, dict) else None
    result = probe_result.get("result") if isinstance(probe_result, dict) else None
    return bool(isinstance(result, dict) and result.get("available"))


def _idalib_hexrays_check(database: Optional[str]) -> dict[str, Any]:
    if not database:
        return _check(
            "warn",
            "idalib",
            "hexrays",
            "Hex-Rays availability was not checked because no database was provided",
        )

    try:
        available = _idalib_hexrays_probe(database)
    except (OSError, RuntimeError, ValueError) as exc:
        return _check(
            "error",
            "idalib",
            "hexrays",
            f"failed to probe Hex-Rays availability through idalib: {exc}",
            database=database,
            python=sys.executable,
        )

    status = "ok" if available else "error"
    summary = (
        "Hex-Rays decompiler is available" if available else "Hex-Rays decompiler could not be initialized in idalib"
    )
    return _check(
        status,
        "idalib",
        "hexrays",
        summary,
        database=database,
        python=sys.executable,
    )


def _idalib_database_path_check(database: str) -> dict[str, Any]:
    database_path = Path(database).expanduser()
    exists = database_path.exists()
    suffix = database_path.suffix.lower()
    recognized_suffix = suffix in {".i64", ".idb"}
    if not exists:
        status = "warn"
        summary = "database path is missing"
    elif recognized_suffix:
        status = "ok"
        summary = "database path looks usable"
    else:
        status = "warn"
        summary = "database path exists but does not use a standard IDA DB suffix"
    return _check(
        status,
        "idalib",
        "database_path",
        summary,
        database=str(database_path),
        exists=exists,
        suffix=suffix,
        recognized_suffix=recognized_suffix,
    )


def _doctor_idalib(*, database: Optional[str]) -> list[dict[str, Any]]:
    checks = [_idalib_install_dirs_check()]
    checks.extend(_idalib_import_checks(database))
    if database:
        checks.append(_idalib_database_path_check(database))
    return checks


def run_doctor(
    *,
    backend: str = "all",
    timeout: Optional[float] = None,
    database: Optional[str] = None,
) -> dict[str, Any]:
    selected = backend.strip().lower() if backend else "all"
    if selected not in {"all", "gui", "idalib"}:
        raise ValueError(f"unsupported doctor backend: {backend}")

    checks: list[dict[str, Any]] = []
    if selected in {"all", "gui"}:
        checks.extend(_doctor_gui(timeout=timeout))
    if selected in {"all", "idalib"}:
        checks.extend(_doctor_idalib(database=database))

    status_order = {"ok": 0, "warn": 1, "error": 2}
    overall_status = "ok"
    if checks:
        overall_status = max(checks, key=lambda item: status_order.get(str(item.get("status")), 99)).get("status", "ok")
    return {
        "healthy": overall_status != "error",
        "backend": selected,
        "status": overall_status,
        "check_count": len(checks),
        "checks": checks,
    }


def _safe_unlink(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def _cleanup_entry(
    kind: str,
    path: Path,
    status: str,
    reason: str,
    *,
    backend: Optional[str] = None,
) -> dict[str, Any]:
    entry = {
        "kind": kind,
        "path": str(path),
        "status": status,
        "reason": reason,
    }
    if backend not in (None, ""):
        entry["backend"] = backend
    return entry


def _non_gui_pid_reason(*, backend: str, pid: int) -> Optional[str]:
    if backend != "gui":
        return None
    return gui._pid_non_gui_bridge_reason(pid)


def _registry_cleanup_entries(
    *,
    backend: str,
    registry_paths: list[Path],
) -> tuple[list[dict[str, Any]], set[Path]]:
    entries: list[dict[str, Any]] = []
    live_socket_paths: set[Path] = set()
    for registry in registry_paths:
        try:
            payload = json.loads(registry.read_text(encoding="utf-8"))
            pid = int(payload["pid"])
            socket_path = Path(payload["socket_path"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            removed = _safe_unlink(registry)
            entries.append(
                _cleanup_entry(
                    "registry",
                    registry,
                    "removed" if removed else "missing",
                    "malformed registry payload",
                    backend=backend,
                )
            )
            continue

        if not socket_path.exists():
            removed = _safe_unlink(registry)
            entries.append(
                _cleanup_entry(
                    "registry",
                    registry,
                    "removed" if removed else "missing",
                    f"missing socket {socket_path}",
                    backend=backend,
                )
            )
            continue

        if not pid_is_live(pid):
            removed = _safe_unlink(registry)
            entries.append(
                _cleanup_entry(
                    "registry",
                    registry,
                    "removed" if removed else "missing",
                    f"dead pid {pid}",
                    backend=backend,
                )
            )
            socket_removed = _safe_unlink(socket_path)
            entries.append(
                _cleanup_entry(
                    "socket",
                    socket_path,
                    "removed" if socket_removed else "missing",
                    f"dead pid {pid}",
                    backend=backend,
                )
            )
            continue

        non_gui_reason = _non_gui_pid_reason(backend=backend, pid=pid)
        if non_gui_reason is not None:
            removed = _safe_unlink(registry)
            entries.append(
                _cleanup_entry(
                    "registry",
                    registry,
                    "removed" if removed else "missing",
                    non_gui_reason,
                    backend=backend,
                )
            )
            socket_removed = _safe_unlink(socket_path)
            entries.append(
                _cleanup_entry(
                    "socket",
                    socket_path,
                    "removed" if socket_removed else "missing",
                    non_gui_reason,
                    backend=backend,
                )
            )
            continue

        live_socket_paths.add(socket_path)
        entries.append(_cleanup_entry("registry", registry, "kept", f"live pid {pid}", backend=backend))
    return entries, live_socket_paths


def _runtime_socket_cleanup_entries(
    *,
    backend: str,
    socket_prefix: str,
    live_socket_paths: set[Path],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    runtime_dir = user_runtime_dir()
    if not runtime_dir.exists():
        return entries

    for socket_path in sorted(runtime_dir.glob(f"{socket_prefix}-*.sock")):
        if socket_path in live_socket_paths:
            continue
        pid_text = socket_path.stem.rsplit("-", 1)[-1]
        try:
            pid = int(pid_text)
        except ValueError:
            pid = None

        if pid is not None and pid_is_live(pid):
            non_gui_reason = None if pid is None else _non_gui_pid_reason(backend=backend, pid=pid)
            if non_gui_reason is not None:
                removed = _safe_unlink(socket_path)
                entries.append(
                    _cleanup_entry(
                        "socket",
                        socket_path,
                        "removed" if removed else "missing",
                        non_gui_reason,
                        backend=backend,
                    )
                )
                continue
            entries.append(
                _cleanup_entry(
                    "socket",
                    socket_path,
                    "kept",
                    f"live pid {pid} without registry",
                    backend=backend,
                )
            )
            continue

        removed = _safe_unlink(socket_path)
        reason = "orphaned socket"
        if pid is not None:
            reason = f"dead pid {pid}"
        entries.append(
            _cleanup_entry(
                "socket",
                socket_path,
                "removed" if removed else "missing",
                reason,
                backend=backend,
            )
        )
    return entries


def run_doctor_cleanup() -> dict[str, Any]:
    runtime_dir = user_runtime_dir()
    gui_registry_entries, gui_live_socket_paths = _registry_cleanup_entries(
        backend="gui",
        registry_paths=bridge_registry_paths(),
    )
    idalib_registry_entries, idalib_live_socket_paths = _registry_cleanup_entries(
        backend="idalib",
        registry_paths=idalib_registry_paths(),
    )
    gui_socket_entries = _runtime_socket_cleanup_entries(
        backend="gui",
        socket_prefix=BRIDGE_SOCKET_PREFIX,
        live_socket_paths=gui_live_socket_paths,
    )
    idalib_socket_entries = _runtime_socket_cleanup_entries(
        backend="idalib",
        socket_prefix=IDALIB_SOCKET_PREFIX,
        live_socket_paths=idalib_live_socket_paths,
    )
    entries = gui_registry_entries + idalib_registry_entries + gui_socket_entries + idalib_socket_entries
    removed = [entry for entry in entries if entry["status"] == "removed"]
    kept = [entry for entry in entries if entry["status"] == "kept"]
    missing = [entry for entry in entries if entry["status"] == "missing"]
    return {
        "ok": True,
        "runtime_dir": str(runtime_dir),
        "removed_count": len(removed),
        "kept_count": len(kept),
        "missing_count": len(missing),
        "entries": entries,
    }
