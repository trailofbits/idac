from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.params import optional_str, require_str
from ..runtime import IdaOperationError, IdaRuntime


@dataclass(frozen=True)
class ReanalyzeRequest:
    identifier: str
    end: str | None = None


@dataclass(frozen=True)
class PythonExecRequest:
    script: str
    persist: bool = False


def _parse_reanalyze(params: Mapping[str, Any]) -> ReanalyzeRequest:
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


def _parse_python_exec(params: Mapping[str, Any]) -> PythonExecRequest:
    script = str(params.get("script") or "")
    if not script.strip():
        raise IdaOperationError("python_exec requires non-empty script")
    return PythonExecRequest(script=script, persist=bool(params.get("persist")))


def _reanalyze(runtime: IdaRuntime, request: ReanalyzeRequest) -> dict[str, object]:
    ida_auto = runtime.mod("ida_auto")
    ida_funcs = runtime.mod("ida_funcs")
    if request.end is not None:
        start_ea = runtime.resolve_address(request.identifier)
        end_ea = runtime.resolve_address(request.end)
        if end_ea <= start_ea:
            raise IdaOperationError("reanalyze range end must be greater than the start")
        ida_auto.plan_and_wait(start_ea, end_ea, True)
        return {"mode": "range", "start": hex(start_ea), "end": hex(end_ea), "waited": True}
    try:
        func = runtime.resolve_function(request.identifier)
    except IdaOperationError:
        ea = runtime.resolve_address(request.identifier)
        ida_auto.plan_and_wait(ea, ea + 1, True)
        return {"mode": "address", "start": hex(ea), "end": hex(ea + 1), "waited": True}
    ea = func.start_ea
    ida_funcs.reanalyze_function(func)
    ida_auto.auto_wait()
    return {
        "mode": "function",
        "function": ida_funcs.get_func_name(ea),
        "start": hex(ea),
        "end": hex(func.end_ea),
        "waited": True,
    }


def _python_exec(runtime: IdaRuntime, request: PythonExecRequest) -> dict[str, object]:
    stdout = io.StringIO()
    scope = runtime.python_exec_scope(persist=request.persist)
    try:
        with contextlib.redirect_stdout(stdout):
            exec(request.script, scope, scope)
    except Exception as exc:
        raise IdaOperationError(f"python_exec failed: {exc.__class__.__name__}: {exc}") from exc
    payload_result, result_repr = _json_payload_result(scope.get("result"))
    return {"stdout": stdout.getvalue(), "result": payload_result, "result_repr": result_repr}


def _run_reanalyze(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _reanalyze(runtime, _parse_reanalyze(params))


def _run_python_exec(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _python_exec(runtime, _parse_python_exec(params))


MISC_OPS: dict[str, Op] = {
    "reanalyze": Op(run=_run_reanalyze, mutating=True),
    "python_exec": Op(run=_run_python_exec, mutating=True),
}


__all__ = [
    "MISC_OPS",
    "PythonExecRequest",
    "ReanalyzeRequest",
]
