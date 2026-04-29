from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .manifest import OPERATIONS
from .preview import PreviewOutcome, PreviewUnsupportedError, run_preview
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


def dispatch(
    runtime: IdaRuntime,
    name: str,
    params: dict[str, Any],
) -> Any:
    payload = dict(params)
    preview_requested = bool(payload.pop("preview", False))
    op = OPERATIONS.get(name)
    if op is None:
        raise IdaOperationError(f"unknown operation: {name}")
    try:
        if preview_requested:
            outcome = run_preview(runtime, name, payload, op.run, op.preview)
            return _finalize_result(outcome)
        return _finalize_result(op.run(runtime, payload))
    except PreviewUnsupportedError as exc:
        raise IdaOperationError(str(exc)) from exc


def build_operation_registry(
    runtime: IdaRuntime,
    *,
    list_targets: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Callable[[dict[str, Any]], Any]]:
    def make_handler(name: str) -> Callable[[dict[str, Any]], Any]:
        def handler(params: dict[str, Any]) -> Any:
            return dispatch(runtime, name, params)

        return handler

    handlers = {name: make_handler(name) for name in OPERATIONS}
    if list_targets is not None:
        handlers["list_targets"] = list_targets
    return handlers


__all__ = ["build_operation_registry", "dispatch"]
