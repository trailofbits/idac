from __future__ import annotations

from dataclasses import dataclass

from ..base import OperationContext, OperationSpec
from ..helpers.params import require_str
from ..preview import PreviewSpec
from ..runtime import IdaOperationError


@dataclass(frozen=True)
class NameSetRequest:
    identifier: str
    new_name: str


@dataclass(frozen=True)
class NameState:
    address: str
    name: str


@dataclass(frozen=True)
class NameMutationResult:
    address: str
    name: str
    changed: bool


def _parse_name_set(params: dict[str, object]) -> NameSetRequest:
    identifier = require_str(params.get("identifier"), field="address or identifier")
    new_name = require_str(params.get("new_name"), field="new name")
    return NameSetRequest(identifier=identifier, new_name=new_name)


def _prepare_name_set(context: OperationContext, request: NameSetRequest) -> NameSetRequest:
    runtime = context.runtime
    return NameSetRequest(identifier=hex(runtime.resolve_address(request.identifier)), new_name=request.new_name)


def _name_state(context: OperationContext, request: NameSetRequest) -> NameState:
    runtime = context.runtime
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    return NameState(address=hex(ea), name=ida_name.get_name(ea) or "")


def _set_name(context: OperationContext, request: NameSetRequest) -> NameMutationResult:
    runtime = context.runtime
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    if not ida_name.set_name(ea, request.new_name, ida_name.SN_CHECK):
        raise IdaOperationError(f"failed to set name at {hex(ea)}")
    return NameMutationResult(address=hex(ea), name=request.new_name, changed=True)


def _restore_name(
    context: OperationContext,
    request: NameSetRequest,
    before: NameState,
    result: NameMutationResult,
) -> None:
    del result
    runtime = context.runtime
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    if not ida_name.set_name(ea, before.name, ida_name.SN_CHECK):
        raise IdaOperationError(f"failed to restore name at {hex(ea)}")


def name_operations() -> tuple[OperationSpec[object, object], ...]:
    return (
        OperationSpec(
            name="name_set",
            parse=_parse_name_set,
            run=_set_name,
            mutating=True,
            preview=PreviewSpec(
                capture_before=_name_state,
                capture_after=_name_state,
                rollback=_restore_name,
                prepare=_prepare_name_set,
            ),
        ),
    )


__all__ = [
    "NameMutationResult",
    "NameSetRequest",
    "NameState",
    "name_operations",
]
