from __future__ import annotations

from dataclasses import dataclass

import pytest

from idac.ops import (
    OperationContext,
    OperationRegistry,
    OperationSpec,
    PreviewOutcome,
    PreviewSpec,
    PreviewUnsupportedError,
)


@dataclass(frozen=True)
class CounterRequest:
    amount: int


@dataclass(frozen=True)
class CounterResult:
    value: int


class _CounterRuntime:
    def __init__(self) -> None:
        self.value = 0


def _parse_counter(params: dict[str, object]) -> CounterRequest:
    return CounterRequest(amount=int(params["amount"]))


def _increment(context: OperationContext, request: CounterRequest) -> CounterResult:
    runtime = context.runtime
    assert isinstance(runtime, _CounterRuntime)
    runtime.value += request.amount
    return CounterResult(value=runtime.value)


def _capture_value(context: OperationContext, request: CounterRequest) -> int:
    del request
    runtime = context.runtime
    assert isinstance(runtime, _CounterRuntime)
    return runtime.value


def _rollback_increment(
    context: OperationContext,
    request: CounterRequest,
    before: int,
    result: CounterResult,
) -> None:
    del result, before
    runtime = context.runtime
    assert isinstance(runtime, _CounterRuntime)
    runtime.value -= request.amount


def test_operation_registry_executes_typed_operation() -> None:
    registry = OperationRegistry(
        [
            OperationSpec(
                name="counter.increment",
                parse=_parse_counter,
                run=_increment,
                mutating=True,
            )
        ]
    )
    runtime = _CounterRuntime()

    result = registry.execute(
        "counter.increment",
        params={"amount": "3"},
        context=OperationContext(runtime=runtime),
    )

    assert result == CounterResult(value=3)
    assert runtime.value == 3


def test_operation_registry_runs_preview_and_rolls_back_state() -> None:
    registry = OperationRegistry(
        [
            OperationSpec(
                name="counter.increment",
                parse=_parse_counter,
                run=_increment,
                mutating=True,
                preview=PreviewSpec(
                    capture_before=_capture_value,
                    capture_after=_capture_value,
                    rollback=_rollback_increment,
                ),
            )
        ]
    )
    runtime = _CounterRuntime()

    result = registry.execute(
        "counter.increment",
        params={"amount": "5"},
        context=OperationContext(runtime=runtime, preview=True),
    )

    assert result == PreviewOutcome(
        result=CounterResult(value=5),
        before=0,
        after=5,
    )
    assert runtime.value == 0


def test_preview_requires_preview_support() -> None:
    registry = OperationRegistry(
        [
            OperationSpec(
                name="counter.increment",
                parse=_parse_counter,
                run=_increment,
                mutating=True,
            )
        ]
    )

    with pytest.raises(PreviewUnsupportedError, match="preview is not supported"):
        registry.execute(
            "counter.increment",
            params={"amount": "1"},
            context=OperationContext(runtime=_CounterRuntime(), preview=True),
        )


