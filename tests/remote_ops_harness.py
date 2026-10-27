from __future__ import annotations

from types import MappingProxyType, ModuleType
from typing import Any

from idac import remote_ops as default_remote_ops


def dispatch_with_runtime(
    runtime: object,
    op: str,
    params: dict[str, object],
    *,
    preview: bool = False,
    module: ModuleType = default_remote_ops,
    operation: object | None = None,
) -> Any:
    """Invoke the real remote dispatch with a supplied runtime and optional synthetic operation."""
    original_runtime = module.IdaRuntime
    original_operations = module._OPERATIONS
    module.IdaRuntime = lambda: runtime
    if operation is not None:
        module._OPERATIONS = MappingProxyType({op: operation})
    try:
        return module.dispatch(object(), op, params, preview)
    finally:
        module.IdaRuntime = original_runtime
        module._OPERATIONS = original_operations
