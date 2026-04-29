from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .base import Params, Runner
from .runtime import IdaRuntime, ida_undo_restore_point

PreviewPrepare = Callable[[IdaRuntime, Params], Mapping[str, Any]]
PreviewCapture = Callable[[IdaRuntime, Params], Any]
PreviewRollback = Callable[[IdaRuntime, Params, Any, Any], None]
PreviewCleanup = Callable[[IdaRuntime, Params], None]


class PreviewUnsupportedError(RuntimeError):
    """Raised when an operation is executed in preview mode without preview support."""


@dataclass(frozen=True)
class PreviewOutcome:
    result: Any
    before: Any
    after: Any
    persisted: bool = False
    preview: bool = True
    preview_mode: str = "undo"


@dataclass(frozen=True)
class PreviewSpec:
    capture_before: PreviewCapture
    capture_after: PreviewCapture
    rollback: PreviewRollback | None = None
    prepare: PreviewPrepare | None = None
    cleanup: PreviewCleanup | None = None
    use_undo: bool = False

    def prepare_params(self, runtime: IdaRuntime, params: Params) -> Params:
        if self.prepare is None:
            return params
        return self.prepare(runtime, params)


def run_preview(
    runtime: IdaRuntime,
    name: str,
    params: Params,
    runner: Runner,
    spec: PreviewSpec | None,
) -> PreviewOutcome:
    if spec is None:
        raise PreviewUnsupportedError("preview is not supported for this operation")

    prepared = spec.prepare_params(runtime, params)
    if spec.use_undo:
        cleanup_error: BaseException | None = None
        try:
            with ida_undo_restore_point(
                runtime,
                action_name=f"idac_preview_{name}",
                label=f"idac preview {name}",
                unavailable_message="preview is unavailable because IDA undo is disabled",
                restore_error_message=f"preview failed to restore changes via undo for {name}",
                restore_failure_message=f"preview failed and IDA could not restore changes via undo for {name}",
            ):
                before = spec.capture_before(runtime, prepared)
                result = runner(runtime, prepared)
                after = spec.capture_after(runtime, prepared)
        finally:
            if spec.cleanup is not None:
                try:
                    spec.cleanup(runtime, prepared)
                except BaseException as exc:  # pragma: no cover - defensive cleanup branch.
                    cleanup_error = exc
        if cleanup_error is not None:
            raise cleanup_error
        return PreviewOutcome(result=result, before=before, after=after, preview_mode="undo")

    if spec.rollback is None:
        raise PreviewUnsupportedError(f"preview is not supported for this operation: {name}")

    result: Any = None
    after: Any = None
    mutation_succeeded = False
    primary_error: BaseException | None = None
    rollback_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        before = spec.capture_before(runtime, prepared)
        try:
            result = runner(runtime, prepared)
            mutation_succeeded = True
            after = spec.capture_after(runtime, prepared)
        except BaseException as exc:
            primary_error = exc
        finally:
            if mutation_succeeded:
                try:
                    spec.rollback(runtime, prepared, before, result)
                except BaseException as exc:
                    rollback_error = exc
    finally:
        if spec.cleanup is not None:
            try:
                spec.cleanup(runtime, prepared)
            except BaseException as exc:  # pragma: no cover - defensive cleanup branch.
                cleanup_error = exc
    if rollback_error is not None:
        if primary_error is not None:
            raise rollback_error from primary_error
        raise rollback_error
    if primary_error is not None:
        raise primary_error
    if cleanup_error is not None:
        raise cleanup_error
    return PreviewOutcome(result=result, before=before, after=after)


__all__ = [
    "PreviewOutcome",
    "PreviewSpec",
    "PreviewUnsupportedError",
    "run_preview",
]
