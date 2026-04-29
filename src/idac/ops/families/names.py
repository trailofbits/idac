from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.params import require_str
from ..preview import PreviewSpec
from ..runtime import IdaOperationError, IdaRuntime


@dataclass(frozen=True)
class NameSetRequest:
    identifier: str
    new_name: str


def _parse_name_set(params: Mapping[str, Any]) -> NameSetRequest:
    identifier = require_str(params.get("identifier"), field="address or identifier")
    new_name = require_str(params.get("new_name"), field="new name")
    return NameSetRequest(identifier=identifier, new_name=new_name)


def _name_state(runtime: IdaRuntime, request: NameSetRequest) -> dict[str, object]:
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    return {"address": hex(ea), "name": ida_name.get_name(ea) or ""}


def _set_name(runtime: IdaRuntime, request: NameSetRequest) -> dict[str, object]:
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    if not ida_name.set_name(ea, request.new_name, ida_name.SN_CHECK):
        raise IdaOperationError(f"failed to set name at {hex(ea)}")
    return {"address": hex(ea), "name": request.new_name, "changed": True}


def _run_name_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _set_name(runtime, _parse_name_set(params))


def _prepare_name_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, Any]:
    request = _parse_name_set(params)
    return {
        **dict(params),
        "identifier": hex(runtime.resolve_address(request.identifier)),
        "new_name": request.new_name,
    }


def _capture_name(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _name_state(runtime, _parse_name_set(params))


def _restore_name(
    runtime: IdaRuntime,
    params: Mapping[str, Any],
    before: dict[str, object],
    result: Any,
) -> None:
    del result
    request = _parse_name_set(params)
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    if not ida_name.set_name(ea, str(before.get("name") or ""), ida_name.SN_CHECK):
        raise IdaOperationError(f"failed to restore name at {hex(ea)}")


NAME_OPS: dict[str, Op] = {
    "name_set": Op(
        run=_run_name_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_name,
            capture_after=_capture_name,
            rollback=_restore_name,
            prepare=_prepare_name_set,
        ),
    ),
}


__all__ = [
    "NAME_OPS",
    "NameSetRequest",
]
