from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest

from idac.ops import Op, PreviewOutcome, PreviewSpec, PreviewUnsupportedError
from idac.ops.preview import run_preview
from idac.ops.runtime import IdaRuntime


class _CounterRuntime(IdaRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.value = 0


@dataclass(frozen=True)
class CounterRequest:
    amount: int


def _parse_counter(params: Mapping[str, Any]) -> CounterRequest:
    return CounterRequest(amount=int(params["amount"]))


def _run_increment(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, int]:
    request = _parse_counter(params)
    assert isinstance(runtime, _CounterRuntime)
    runtime.value += request.amount
    return {"value": runtime.value}


def _capture_value(runtime: IdaRuntime, _params: Mapping[str, Any]) -> int:
    assert isinstance(runtime, _CounterRuntime)
    return runtime.value


def _rollback_increment(
    runtime: IdaRuntime,
    params: Mapping[str, Any],
    before: int,
    result: dict[str, int],
) -> None:
    del result, before
    request = _parse_counter(params)
    assert isinstance(runtime, _CounterRuntime)
    runtime.value -= request.amount


def test_op_runs_typed_operation() -> None:
    op = Op(run=_run_increment, mutating=True)
    runtime = _CounterRuntime()

    result = op.run(runtime, {"amount": "3"})

    assert result == {"value": 3}
    assert runtime.value == 3


def test_run_preview_rolls_back_state() -> None:
    op = Op(
        run=_run_increment,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_value,
            capture_after=_capture_value,
            rollback=_rollback_increment,
        ),
    )
    runtime = _CounterRuntime()

    outcome = run_preview(runtime, "counter.increment", {"amount": "5"}, op.run, op.preview)

    assert outcome == PreviewOutcome(result={"value": 5}, before=0, after=5)
    assert runtime.value == 0


def test_preview_requires_preview_support() -> None:
    op = Op(run=_run_increment, mutating=True)

    with pytest.raises(PreviewUnsupportedError, match="preview is not supported"):
        run_preview(_CounterRuntime(), "counter.increment", {"amount": "1"}, op.run, op.preview)
