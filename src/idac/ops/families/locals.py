from __future__ import annotations

import contextlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.params import optional_param_int, require_str
from ..preview import PreviewSpec
from ..runtime import (
    IdaOperationError,
    IdaRuntime,
    is_recoverable_ida_error,
    suppress_recoverable_ida_errors,
)


@dataclass(frozen=True)
class LocalSelector:
    name: str | None = None
    local_id: str | None = None
    index: int | None = None

    def stable_selector(self) -> tuple[str, Any] | None:
        if self.local_id is not None:
            return "local_id", self.local_id
        if self.index is not None:
            return "index", self.index
        return None


@dataclass(frozen=True)
class LocalListRequest:
    identifier: str


@dataclass(frozen=True)
class LocalRenameRequest:
    identifier: str
    selector: LocalSelector
    new_name: str


@dataclass(frozen=True)
class LocalRetypeRequest:
    identifier: str
    selector: LocalSelector
    decl: str


@dataclass(frozen=True)
class LocalUpdateRequest:
    identifier: str
    selector: LocalSelector
    new_name: str | None = None
    decl: str | None = None


@dataclass(frozen=True)
class SelectedLocal:
    name: str
    locator: Any
    display_name: str | None = None

    def label(self) -> str:
        return self.display_name or self.name or "<unnamed local>"


_LOCAL_ID_NEW_RE = re.compile(
    r"^(?P<kind>stack|reg|regpair)\((?P<body>[^)]*)\)@(?P<defea>0x[0-9a-fA-F]+|\d+)$",
    re.IGNORECASE,
)
_LOCAL_SELECTOR_GUIDANCE = (
    "list locals again to confirm current names and prefer a stable selector such as local_id or index"
)


def _require_identifier(params: Mapping[str, Any]) -> str:
    return require_str(params.get("identifier"), field="address or identifier")


def _parse_local_selector(params: Mapping[str, Any], *, name_key: str) -> LocalSelector:
    name = str(params.get(name_key) or "").strip() or None
    local_id = str(params.get("local_id") or "").strip() or None
    index = optional_param_int(params, "index", label="local index", minimum=0)
    stable_count = sum(value is not None for value in (local_id, index))
    if name is None and stable_count == 0:
        raise IdaOperationError(f"local selector is required via {name_key}, local_id, or index")
    if stable_count > 1:
        raise IdaOperationError("--local-id and --index are mutually exclusive; got: local_id, index")
    return LocalSelector(name=name, local_id=local_id, index=index)


def _parse_local_list(params: Mapping[str, Any]) -> LocalListRequest:
    return LocalListRequest(identifier=_require_identifier(params))


def _parse_local_rename(params: Mapping[str, Any]) -> LocalRenameRequest:
    new_name = str(params.get("new_name") or "")
    if not new_name:
        raise IdaOperationError("new local variable name is required")
    return LocalRenameRequest(
        identifier=_require_identifier(params),
        selector=_parse_local_selector(params, name_key="old_name"),
        new_name=new_name,
    )


def _parse_local_retype(params: Mapping[str, Any]) -> LocalRetypeRequest:
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("local variable declaration is required")
    return LocalRetypeRequest(
        identifier=_require_identifier(params),
        selector=_parse_local_selector(params, name_key="local_name"),
        decl=decl,
    )


def _parse_local_update(params: Mapping[str, Any]) -> LocalUpdateRequest:
    new_name = str(params.get("new_name") or "").strip() or None
    decl = str(params.get("decl") or "").strip() or None
    if new_name is None and decl is None:
        raise IdaOperationError("at least one of new_name or decl is required")
    return LocalUpdateRequest(
        identifier=_require_identifier(params),
        selector=_parse_local_selector(params, name_key="local_name"),
        new_name=new_name,
        decl=decl,
    )


def _vdloc_text(location) -> str:
    if location.is_stkoff():
        return f"stack({location.stkoff()})"
    if location.is_reg1():
        return f"reg({location.reg1()})"
    if location.is_reg2():
        return f"regpair({location.reg1()},{location.reg2()})"
    return "unknown"


def _local_identity(lvar) -> tuple[str, str, str]:
    definition_address = hex(lvar.defea)
    location = _vdloc_text(lvar.location)
    return definition_address, location, f"{location}@{definition_address}"


def _normalize_local_location_text(text: str) -> str:
    value = str(text).strip()
    match = re.fullmatch(r"(?P<kind>stack|reg|regpair)\((?P<body>[^)]*)\)", value, re.IGNORECASE)
    if match:
        kind = match.group("kind").lower()
        body = match.group("body").strip()
        if kind in {"stack", "reg"} and body:
            with contextlib.suppress(ValueError):
                body = str(int(body, 0))
        elif kind == "regpair" and body:
            left, sep, right = body.partition(",")
            if sep:
                with contextlib.suppress(ValueError):
                    left = str(int(left.strip(), 0))
                with contextlib.suppress(ValueError):
                    right = str(int(right.strip(), 0))
                body = f"{left},{right}"
        return f"{kind}({body})"
    return value


def _normalize_local_id_text(local_id: str) -> str:
    text = str(local_id).strip()
    match = _LOCAL_ID_NEW_RE.match(text)
    if match:
        defea_text = match.group("defea")
        with contextlib.suppress(ValueError):
            defea_text = hex(int(defea_text, 0))
        location_text = _normalize_local_location_text(f"{match.group('kind')}({match.group('body')})")
        return f"{location_text}@{defea_text}"
    return text


def _parse_var_decl(runtime: IdaRuntime, decl: str, *, error_message: str):
    tif = runtime.ida_typeinf.tinfo_t()
    parse_text = decl.strip()
    if not parse_text.endswith(";"):
        parse_text += ";"
    parse_flags = runtime.ida_typeinf.PT_VAR | runtime.ida_typeinf.PT_SIL | runtime.ida_typeinf.PT_SEMICOLON
    if not runtime.ida_typeinf.parse_decl(tif, None, parse_text, parse_flags):
        raise IdaOperationError(error_message)
    return tif


def _decompile_locals(runtime: IdaRuntime, func_ea: int, *, action: str):
    cfunc = runtime.require_hexrays().decompile(func_ea)
    if cfunc is None:
        raise IdaOperationError(f"failed to {action} for {hex(func_ea)}")
    return cfunc


def _lvar_locator(runtime: IdaRuntime, lvar):
    locator = runtime.require_hexrays().lvar_locator_t()
    locator.defea = lvar.defea
    locator.location = lvar.location
    return locator


def _local_row(runtime: IdaRuntime, index: int, lvar, saved) -> dict[str, object]:
    stack_offset = None
    if lvar.is_stk_var():
        with suppress_recoverable_ida_errors():
            stack_offset = lvar.get_stkoff()
    definition_address, location, local_id = _local_identity(lvar)
    name = lvar.name or ""
    if saved is not None and saved.name:
        name = str(saved.name)
    type_text = runtime.tinfo_decl(lvar.tif, multi=False)
    if saved is not None:
        try:
            saved_type = saved.type._print() if saved.type else ""
        except Exception as exc:
            if not is_recoverable_ida_error(exc):
                raise
            saved_type = ""
        if saved_type:
            type_text = saved_type
    return {
        "index": index,
        "local_id": local_id,
        "definition_address": definition_address,
        "location": location,
        "name": name,
        "display_name": name or f"<unnamed_{index}>",
        "type": type_text,
        "is_arg": lvar.is_arg_var,
        "is_stack": lvar.is_stk_var(),
        "stack_offset": stack_offset,
        "size": lvar.width,
    }


def _local_rows(runtime: IdaRuntime, func_ea: int) -> list[dict[str, object]]:
    ida_hexrays = runtime.require_hexrays()
    cfunc = _decompile_locals(runtime, func_ea, action="inspect locals")
    user_rows: dict[tuple[int, str], Any] = {}
    user_info = ida_hexrays.lvar_uservec_t()
    if ida_hexrays.restore_user_lvar_settings(user_info, func_ea):
        for saved in user_info.lvvec:
            user_rows[(saved.ll.defea, _vdloc_text(saved.ll.location))] = saved

    rows: list[dict[str, object]] = []
    for index, lvar in enumerate(cfunc.get_lvars()):
        saved = user_rows.get((lvar.defea, _vdloc_text(lvar.location)))
        rows.append(_local_row(runtime, index, lvar, saved))
    return rows


def _local_list_result(runtime: IdaRuntime, func_ea: int) -> dict[str, object]:
    return {
        "function": runtime.function_name(func_ea),
        "address": hex(func_ea),
        "locals": _local_rows(runtime, func_ea),
    }


def _stable_local_matches(
    lvars: list[Any], *, selector_name: str, selector_value: Any
) -> tuple[list[tuple[int, Any]], str]:
    if selector_name == "local_id":
        normalized_local_id = _normalize_local_id_text(str(selector_value))
        matches = [
            (index, lvar)
            for index, lvar in enumerate(lvars)
            if _normalize_local_id_text(_local_identity(lvar)[2]) == normalized_local_id
        ]
        return matches, f"local id `{selector_value}`"
    matches = [(index, lvar) for index, lvar in enumerate(lvars) if index == selector_value]
    return matches, f"local index {selector_value}"


def _resolve_lvar_by_name(runtime: IdaRuntime, func_ea: int, name: str):
    local_name = name.strip()
    if not local_name:
        raise IdaOperationError("local variable name is required")
    locator = runtime.require_hexrays().lvar_locator_t()
    if not runtime.require_hexrays().locate_lvar(locator, func_ea, local_name):
        raise IdaOperationError(
            f"local variable not found: {local_name}; {_LOCAL_SELECTOR_GUIDANCE}"
            f"{_available_locals_suffix(runtime, func_ea)}"
        )
    return locator


def _select_local(runtime: IdaRuntime, func_ea: int, selector: LocalSelector) -> SelectedLocal:
    stable = selector.stable_selector()
    if stable is None:
        if selector.name is None:
            raise IdaOperationError("local selector name is required")
        resolved_name = selector.name.strip()
        return SelectedLocal(
            name=resolved_name,
            locator=_resolve_lvar_by_name(runtime, func_ea, resolved_name),
            display_name=resolved_name,
        )

    selector_name, selector_value = stable
    cfunc = _decompile_locals(runtime, func_ea, action="inspect locals")
    matches, label = _stable_local_matches(
        list(cfunc.get_lvars()),
        selector_name=selector_name,
        selector_value=selector_value,
    )
    if not matches:
        raise IdaOperationError(
            f"local variable not found for {label}; {_LOCAL_SELECTOR_GUIDANCE}"
            f"{_available_locals_suffix(runtime, func_ea)}"
        )
    if len(matches) > 1:
        raise IdaOperationError(f"multiple locals matched {label}; use local_id or index instead")
    index, lvar = matches[0]
    resolved_name = lvar.name or ""
    return SelectedLocal(
        name=resolved_name,
        locator=_lvar_locator(runtime, lvar),
        display_name=resolved_name or f"<unnamed_{index}>",
    )


def _available_locals_suffix(runtime: IdaRuntime, func_ea: int) -> str:
    try:
        rows = _local_rows(runtime, func_ea)
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise
        return ""
    if not rows:
        return ""
    rendered: list[str] = []
    for row in rows[:12]:
        index = int(row["index"])
        name = str(row.get("display_name") or row.get("name") or f"<unnamed_{index}>")
        rendered.append(f"#{index} {name} ({row['local_id']})")
    suffix = "; available locals: " + ", ".join(rendered)
    if len(rows) > 12:
        suffix += f", ... {len(rows) - 12} more"
    return suffix


def _resolve_lvar_selection(
    runtime: IdaRuntime,
    func_ea: int,
    params: Mapping[str, Any],
    *,
    name_key: str,
) -> tuple[str, Any]:
    selector = _parse_local_selector(params, name_key=name_key)
    selected = _select_local(runtime, func_ea, selector)
    return selected.name, selected.locator


def _local_saved_info(runtime: IdaRuntime, locator):
    info = runtime.require_hexrays().lvar_saved_info_t()
    info.ll = locator
    return info


def _readback_local_change(runtime: IdaRuntime, func_ea: int, *, success_message: str) -> dict[str, object]:
    try:
        refreshed = _local_list_result(runtime, func_ea)
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"{success_message} but failed to read back locals: {detail}") from exc
    return {
        "function": refreshed["function"],
        "address": refreshed["address"],
        "locals": refreshed["locals"],
        "changed": True,
    }


def _rename_local_by_name(
    runtime: IdaRuntime,
    func_ea: int,
    current_name: str,
    new_name: str,
    *,
    failure_message: str,
    success_message: str,
) -> dict[str, object] | None:
    rename_lvar = getattr(runtime.require_hexrays(), "rename_lvar", None)
    if not callable(rename_lvar):
        return None
    if not rename_lvar(func_ea, current_name, new_name):
        raise IdaOperationError(failure_message)
    return _readback_local_change(runtime, func_ea, success_message=success_message)


def _apply_local_change(
    runtime: IdaRuntime,
    func_ea: int,
    info,
    *,
    modify_flag: int,
    failure_message: str,
    success_message: str,
) -> dict[str, object]:
    if not runtime.require_hexrays().modify_user_lvar_info(func_ea, modify_flag, info):
        raise IdaOperationError(failure_message)
    return _readback_local_change(runtime, func_ea, success_message=success_message)


def _local_list(runtime: IdaRuntime, request: LocalListRequest) -> dict[str, object]:
    func_ea = runtime.function_ea(request.identifier)
    return _local_list_result(runtime, func_ea)


def _local_list_for_change(
    runtime: IdaRuntime,
    request: LocalRenameRequest | LocalRetypeRequest | LocalUpdateRequest,
) -> dict[str, object]:
    func_ea = runtime.function_ea(request.identifier)
    return _local_list_result(runtime, func_ea)


def _local_rename(runtime: IdaRuntime, request: LocalRenameRequest) -> dict[str, object]:
    func_ea = runtime.function_ea(request.identifier)
    selected = _select_local(runtime, func_ea, request.selector)
    failure_message = f"failed to rename local variable: {selected.label()}"
    success_message = f"renamed local variable `{selected.label()}` to `{request.new_name}`"
    if request.selector.stable_selector() is None and selected.name:
        renamed = _rename_local_by_name(
            runtime,
            func_ea,
            selected.name,
            request.new_name,
            failure_message=failure_message,
            success_message=success_message,
        )
        if renamed is not None:
            return renamed
    info = _local_saved_info(runtime, selected.locator)
    info.name = request.new_name
    return _apply_local_change(
        runtime,
        func_ea,
        info,
        modify_flag=runtime.require_hexrays().MLI_NAME,
        failure_message=failure_message,
        success_message=success_message,
    )


def _local_retype(runtime: IdaRuntime, request: LocalRetypeRequest) -> dict[str, object]:
    func_ea = runtime.function_ea(request.identifier)
    selected = _select_local(runtime, func_ea, request.selector)
    info = _local_saved_info(runtime, selected.locator)
    info.name = selected.name
    info.type = _parse_var_decl(
        runtime,
        request.decl,
        error_message=f"failed to parse local variable declaration: {request.decl}",
    )
    return _apply_local_change(
        runtime,
        func_ea,
        info,
        modify_flag=runtime.require_hexrays().MLI_TYPE,
        failure_message=f"failed to update local variable type: {selected.label()}",
        success_message=f"updated local variable type for `{selected.label()}`",
    )


def _local_update(runtime: IdaRuntime, request: LocalUpdateRequest) -> dict[str, object]:
    func_ea = runtime.function_ea(request.identifier)
    selected = _select_local(runtime, func_ea, request.selector)
    info = _local_saved_info(runtime, selected.locator)
    modify_flag = 0
    if request.new_name is not None:
        info.name = request.new_name
        modify_flag |= runtime.require_hexrays().MLI_NAME
    if request.decl is not None:
        info.name = request.new_name or selected.name
        info.type = _parse_var_decl(
            runtime,
            request.decl,
            error_message=f"failed to parse local variable declaration: {request.decl}",
        )
        modify_flag |= runtime.require_hexrays().MLI_TYPE
    if modify_flag == 0:
        raise IdaOperationError("at least one of new_name or decl is required")
    success_message_parts: list[str] = []
    if request.new_name is not None:
        success_message_parts.append(f"renamed local variable `{selected.label()}` to `{request.new_name}`")
    if request.decl is not None:
        success_message_parts.append(f"updated local variable type for `{request.new_name or selected.label()}`")
    return _apply_local_change(
        runtime,
        func_ea,
        info,
        modify_flag=modify_flag,
        failure_message=f"failed to update local variable: {selected.label()}",
        success_message=" and ".join(success_message_parts),
    )


def _run_local_list(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _local_list(runtime, _parse_local_list(params))


def _run_local_rename(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _local_rename(runtime, _parse_local_rename(params))


def _run_local_retype(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _local_retype(runtime, _parse_local_retype(params))


def _run_local_update(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _local_update(runtime, _parse_local_update(params))


def _capture_local_rename(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _local_list_for_change(runtime, _parse_local_rename(params))


def _capture_local_retype(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _local_list_for_change(runtime, _parse_local_retype(params))


def _capture_local_update(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _local_list_for_change(runtime, _parse_local_update(params))


def _cleanup_local_preview(runtime: IdaRuntime, params: Mapping[str, Any]) -> None:
    identifier = require_str(params.get("identifier"), field="address or identifier")
    try:
        func_ea = runtime.function_ea(identifier)
        runtime.require_hexrays().mark_cfunc_dirty(func_ea, False)
        runtime.require_hexrays().clear_cached_cfuncs()
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise


LOCAL_OPS: dict[str, Op] = {
    "local_list": Op(run=_run_local_list),
    "local_rename": Op(
        run=_run_local_rename,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_local_rename,
            capture_after=_capture_local_rename,
            cleanup=_cleanup_local_preview,
            use_undo=True,
        ),
    ),
    "local_retype": Op(
        run=_run_local_retype,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_local_retype,
            capture_after=_capture_local_retype,
            cleanup=_cleanup_local_preview,
            use_undo=True,
        ),
    ),
    "local_update": Op(
        run=_run_local_update,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_local_update,
            capture_after=_capture_local_update,
            cleanup=_cleanup_local_preview,
            use_undo=True,
        ),
    ),
}


__all__ = [
    "LOCAL_OPS",
    "LocalListRequest",
    "LocalRenameRequest",
    "LocalRetypeRequest",
    "LocalSelector",
    "LocalUpdateRequest",
]
