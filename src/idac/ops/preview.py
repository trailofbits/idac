from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic

from .base import OperationContext, RequestT, ResultT, RunOperation
from .runtime import ida_undo_restore_point

PreviewPrepare = Callable[[OperationContext, RequestT], RequestT]
PreviewCapture = Callable[[OperationContext, RequestT], Any]
PreviewRollback = Callable[[OperationContext, RequestT, Any, ResultT], None]
PreviewCleanup = Callable[[OperationContext, RequestT], None]


class PreviewUnsupportedError(RuntimeError):
    """Raised when an operation is executed in preview mode without preview support."""


@dataclass(frozen=True)
class PreviewOutcome(Generic[ResultT]):
    result: ResultT
    before: Any
    after: Any
    persisted: bool = False
    preview: bool = True
    preview_mode: str = "undo"


@dataclass(frozen=True)
class PreviewSpec(Generic[RequestT, ResultT]):
    capture_before: PreviewCapture
    capture_after: PreviewCapture
    rollback: PreviewRollback[RequestT, ResultT] | None = None
    prepare: PreviewPrepare[RequestT] | None = None
    cleanup: PreviewCleanup[RequestT] | None = None
    use_undo: bool = False

    def prepare_request(self, context: OperationContext, request: RequestT) -> RequestT:
        if self.prepare is None:
            return request
        return self.prepare(context, request)


def run_preview(
    context: OperationContext,
    name: str,
    request: RequestT,
    runner: RunOperation[RequestT, ResultT],
    spec: PreviewSpec[RequestT, ResultT] | None,
) -> PreviewOutcome[ResultT]:
    if spec is None:
        raise PreviewUnsupportedError("preview is not supported for this operation")

    prepared = spec.prepare_request(context, request)
    if spec.use_undo:
        cleanup_error: BaseException | None = None
        try:
            with ida_undo_restore_point(
                context.runtime,
                action_name=f"idac_preview_{name}",
                label=f"idac preview {name}",
                unavailable_message="preview is unavailable because IDA undo is disabled",
                restore_error_message=f"preview failed to restore changes via undo for {name}",
                restore_failure_message=f"preview failed and IDA could not restore changes via undo for {name}",
            ):
                before = spec.capture_before(context, prepared)
                result = runner(context, prepared)
                after = spec.capture_after(context, prepared)
        finally:
            if spec.cleanup is not None:
                try:
                    spec.cleanup(context, prepared)
                except BaseException as exc:  # pragma: no cover - defensive cleanup branch.
                    cleanup_error = exc
        if cleanup_error is not None:
            raise cleanup_error
        return PreviewOutcome(result=result, before=before, after=after, preview_mode="undo")

    if spec.rollback is None:
        raise PreviewUnsupportedError(f"preview is not supported for this operation: {name}")

    result: ResultT | None = None
    after: Any = None
    mutation_succeeded = False
    primary_error: BaseException | None = None
    rollback_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        before = spec.capture_before(context, prepared)
        try:
            result = runner(context, prepared)
            mutation_succeeded = True
            after = spec.capture_after(context, prepared)
        except BaseException as exc:
            primary_error = exc
        finally:
            if mutation_succeeded:
                try:
                    spec.rollback(context, prepared, before, result)
                except BaseException as exc:
                    rollback_error = exc
    finally:
        if spec.cleanup is not None:
            try:
                spec.cleanup(context, prepared)
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
