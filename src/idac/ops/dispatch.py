from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .base import OperationContext
from .manifest import operation_specs
from .preview import PreviewOutcome, PreviewUnsupportedError
from .registry import OperationRegistry
from .runtime import IdaOperationError, IdaRuntime


def _finalize_result(result: Any) -> Any:
    if isinstance(result, PreviewOutcome):
        return {
            "result": result.result,
            "before": result.before,
            "after": result.after,
            "persisted": result.persisted,
            "preview": result.preview,
            "preview_mode": result.preview_mode,
        }
    return result


def build_operation_registry(
    runtime: IdaRuntime,
    *,
    list_targets: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Callable[[dict[str, Any]], Any]]:
    registry = OperationRegistry(operation_specs())

    def make_handler(name: str) -> Callable[[dict[str, Any]], Any]:
        def handler(params: dict[str, Any]) -> Any:
            payload = dict(params)
            preview_requested = bool(payload.pop("preview", False))
            context = OperationContext(runtime=runtime, preview=preview_requested)
            try:
                result = registry.execute(name, params=payload, context=context)
            except PreviewUnsupportedError as exc:
                raise IdaOperationError(str(exc)) from exc
            return _finalize_result(result)

        return handler

    handlers = {name: make_handler(name) for name in registry.names()}
    if list_targets is not None:
        handlers["list_targets"] = list_targets
    return handlers


__all__ = ["build_operation_registry"]
