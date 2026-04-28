"""Operation handlers and dispatch registry for the IDA GUI bridge."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any, Callable, Optional

from idac.ops.dispatch import build_operation_registry
from idac.ops.manifest import SUPPORTED_OPERATIONS
from idac.ops.runtime import IdaRuntime

HandlerFn = Callable[[dict[str, Any]], Any]
TargetValidator = Callable[[Optional[str]], None]


class DefaultHandlers:
    """Thin adapter from the GUI bridge to the shared IDA operation registry."""

    def __init__(self) -> None:
        self.runtime = IdaRuntime()

    def _current_target(self) -> dict[str, Any]:
        path = ""
        module = ""
        with contextlib.suppress(ImportError, AttributeError, RuntimeError, OSError, ValueError):
            import idaapi  # type: ignore

            path = idaapi.get_input_file_path() or ""
            module = idaapi.get_root_filename() or ""
        selector = module or Path(path).name or "active"
        return {
            "target_id": "active",
            "selector": selector,
            "filename": path,
            "module": module,
            "active": True,
        }

    def current_target_info(self) -> dict[str, Any]:
        info = dict(self._current_target())
        pid = os.getpid()
        info["instance_pid"] = pid
        info["instance_selector"] = f"pid:{pid}"
        info["global_target_id"] = f"{pid}:{info['target_id']}"
        return info

    def list_targets(self, _params: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._current_target()]

    def validate_target(self, target: Optional[str]) -> None:
        if target in (None, "", "active"):
            return
        current = self._current_target()
        aliases = {
            "active",
            str(current.get("selector") or ""),
            str(current.get("filename") or ""),
            str(current.get("module") or ""),
        }
        if target not in aliases:
            from .protocol import UnsupportedOperationError

            raise UnsupportedOperationError(f"target '{target}' does not match the active IDA database")


def build_default_registry() -> tuple[dict[str, HandlerFn], TargetValidator]:
    """Create the default GUI bridge handler map plus target validator."""

    handlers = DefaultHandlers()
    registry = build_operation_registry(handlers.runtime, list_targets=handlers.list_targets)

    missing = set(SUPPORTED_OPERATIONS) - set(registry.keys())
    if missing:
        raise RuntimeError(f"default registry missing operations: {sorted(missing)!r}")

    return registry, handlers.validate_target


def current_target_info() -> dict[str, Any]:
    return DefaultHandlers().current_target_info()
