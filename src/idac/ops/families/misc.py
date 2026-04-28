from __future__ import annotations

import contextlib
import io
import json
from dataclasses import dataclass

from ..base import OperationContext, OperationSpec
from ..helpers.params import optional_str, require_str
from ..runtime import IdaOperationError


@dataclass(frozen=True)
class ReanalyzeRequest:
    identifier: str
    end: str | None = None


@dataclass(frozen=True)
class ReanalyzeRangeResult:
    mode: str
    start: str
    end: str
    waited: bool


@dataclass(frozen=True)
class ReanalyzeFunctionResult:
    mode: str
    function: str
    start: str
    end: str
    waited: bool


@dataclass(frozen=True)
class PythonExecRequest:
    script: str
    persist: bool = False


@dataclass(frozen=True)
class PythonExecResult:
    stdout: str
    result: object
    result_repr: str


def _parse_reanalyze(params: dict[str, object]) -> ReanalyzeRequest:
    return ReanalyzeRequest(
        identifier=require_str(params.get("identifier"), field="identifier"),
        end=optional_str(params.get("end")),
    )


def _json_payload_result(value: object) -> tuple[object, str]:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return None, repr(value)
    return value, repr(value)


def _parse_python_exec(params: dict[str, object]) -> PythonExecRequest:
    script = str(params.get("script") or "")
    if not script.strip():
        raise IdaOperationError("python_exec requires non-empty script")
    return PythonExecRequest(script=script, persist=bool(params.get("persist")))


def _reanalyze(
    context: OperationContext,
    request: ReanalyzeRequest,
) -> ReanalyzeRangeResult | ReanalyzeFunctionResult:
    runtime = context.runtime
    ida_auto = runtime.mod("ida_auto")
    ida_funcs = runtime.mod("ida_funcs")
    if request.end is not None:
        start_ea = runtime.resolve_address(request.identifier)
        end_ea = runtime.resolve_address(request.end)
        if end_ea <= start_ea:
            raise IdaOperationError("reanalyze range end must be greater than the start")
        ida_auto.plan_and_wait(start_ea, end_ea, True)
        return ReanalyzeRangeResult(mode="range", start=hex(start_ea), end=hex(end_ea), waited=True)
    try:
        func = runtime.resolve_function(request.identifier)
    except IdaOperationError:
        ea = runtime.resolve_address(request.identifier)
        ida_auto.plan_and_wait(ea, ea + 1, True)
        return ReanalyzeRangeResult(mode="address", start=hex(ea), end=hex(ea + 1), waited=True)
    ea = func.start_ea
    ida_funcs.reanalyze_function(func)
    ida_auto.auto_wait()
    return ReanalyzeFunctionResult(
        mode="function",
        function=ida_funcs.get_func_name(ea),
        start=hex(ea),
        end=hex(func.end_ea),
        waited=True,
    )


def _python_exec(context: OperationContext, request: PythonExecRequest) -> PythonExecResult:
    runtime = context.runtime
    stdout = io.StringIO()
    scope = runtime.python_exec_scope(persist=request.persist)
    try:
        with contextlib.redirect_stdout(stdout):
            exec(request.script, scope, scope)
    except Exception as exc:
        raise IdaOperationError(f"python_exec failed: {exc.__class__.__name__}: {exc}") from exc
    payload_result, result_repr = _json_payload_result(scope.get("result"))
    return PythonExecResult(stdout=stdout.getvalue(), result=payload_result, result_repr=result_repr)


def misc_operations() -> tuple[OperationSpec[object, object], ...]:
    return (
        OperationSpec(
            name="reanalyze",
            parse=_parse_reanalyze,
            run=_reanalyze,
            mutating=True,
        ),
        OperationSpec(
            name="python_exec",
            parse=_parse_python_exec,
            run=_python_exec,
            mutating=True,
        ),
    )


__all__ = [
    "PythonExecRequest",
    "PythonExecResult",
    "ReanalyzeFunctionResult",
    "ReanalyzeRangeResult",
    "ReanalyzeRequest",
    "misc_operations",
]
