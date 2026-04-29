from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.params import require_str
from ..preview import PreviewSpec
from ..runtime import (
    IdaOperationError,
    IdaRuntime,
    suppress_recoverable_ida_errors,
)

_PROTO_BUILTIN_TOKENS = {
    "__cdecl",
    "__fastcall",
    "__hidden",
    "__int128",
    "__int16",
    "__int32",
    "__int64",
    "__int8",
    "__noreturn",
    "__pascal",
    "__ptr32",
    "__ptr64",
    "__stdcall",
    "__thiscall",
    "__usercall",
    "__userpurge",
    "__return_ptr",
    "bool",
    "char",
    "class",
    "const",
    "double",
    "enum",
    "float",
    "int",
    "long",
    "short",
    "signed",
    "size_t",
    "struct",
    "u16",
    "u32",
    "u64",
    "u8",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uint8_t",
    "uintptr_t",
    "union",
    "unsigned",
    "void",
    "volatile",
    "wchar_t",
    "s8",
    "s16",
    "s32",
    "s64",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
}


@dataclass(frozen=True)
class PrototypeGetRequest:
    identifier: str


@dataclass(frozen=True)
class PrototypeSetRequest:
    identifier: str
    decl: str
    preview_decompile: bool = False
    propagate_callers: bool = False


def _require_identifier(params: Mapping[str, Any]) -> str:
    return require_str(params.get("identifier"), field="address or identifier")


def _parse_proto_get(params: Mapping[str, Any]) -> PrototypeGetRequest:
    return PrototypeGetRequest(identifier=_require_identifier(params))


def _parse_proto_set(params: Mapping[str, Any]) -> PrototypeSetRequest:
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("prototype declaration is required")
    return PrototypeSetRequest(
        identifier=_require_identifier(params),
        decl=decl,
        preview_decompile=bool(params.get("preview_decompile")),
        propagate_callers=bool(params.get("propagate_callers")),
    )


def _prototype_view(
    runtime: IdaRuntime,
    request: PrototypeGetRequest | PrototypeSetRequest,
) -> dict[str, object]:
    ea = runtime.function_ea(request.identifier)
    prototype = runtime.ida_typeinf.print_type(ea, runtime.ida_typeinf.PRTYPE_1LINE) or ""
    if not isinstance(request, PrototypeSetRequest) or not request.preview_decompile:
        return {"address": hex(ea), "prototype": prototype}
    try:
        cfunc = runtime.require_hexrays().decompile(ea)
        if cfunc is None:
            raise IdaOperationError(f"failed to decompile function at {hex(ea)}")
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        return {
            "address": hex(ea),
            "prototype": prototype,
            "decompile": None,
            "decompile_error": detail,
        }
    return {"address": hex(ea), "prototype": prototype, "decompile": runtime.pseudocode_text(cfunc)}


def _propagate_callee_tinfo(runtime: IdaRuntime, callee_ea: int, tif) -> tuple[int, int, int]:
    callers_considered = 0
    callers_updated = 0
    callers_failed = 0
    seen: set[int] = set()
    for ref in runtime.idautils.CodeRefsTo(callee_ea, 0):
        if ref in seen:
            continue
        seen.add(ref)
        insn = runtime.ida_ua.insn_t()
        if not runtime.ida_ua.decode_insn(insn, ref):
            continue
        if not runtime.ida_idp.is_call_insn(insn):
            continue
        callers_considered += 1
        if runtime.ida_typeinf.apply_callee_tinfo(ref, tif):
            callers_updated += 1
        else:
            callers_failed += 1
    return callers_considered, callers_updated, callers_failed


def _unknown_proto_types(runtime: IdaRuntime, decl: str) -> list[str]:
    working = decl.strip().rstrip(";")
    working = re.sub(r"@<[^>]+>", "", working)
    header, _, params_text = working.partition("(")
    prefix = header
    if prefix:
        parts = prefix.split()
        if parts:
            prefix = " ".join(parts[:-1])
    param_chunks = [prefix]
    if params_text:
        params_body = params_text.rsplit(")", 1)[0]
        for raw_param in params_body.split(","):
            segment = raw_param.strip()
            if not segment or segment == "void":
                continue
            param_name = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", segment)
            if param_name:
                segment = segment[: param_name.start()].strip()
            param_chunks.append(segment)

    unknown: list[str] = []
    seen: set[str] = set()
    for chunk in param_chunks:
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", chunk):
            if token in _PROTO_BUILTIN_TOKENS or token in seen:
                continue
            if runtime.find_named_type(token) is not None:
                continue
            seen.add(token)
            unknown.append(token)
    return unknown


def _decl_looks_like_destructor(decl: str) -> bool:
    return bool(re.search(r"~[A-Za-z_][A-Za-z0-9_]*\s*\(", decl))


def _parse_prototype_decl(runtime: IdaRuntime, decl: str):
    ida_typeinf = runtime.ida_typeinf
    parse_text = decl.strip()
    if not parse_text.endswith(";"):
        parse_text += ";"
    base_flags = ida_typeinf.PT_VAR | ida_typeinf.PT_SIL | ida_typeinf.PT_SEMICOLON
    flag_candidates = [base_flags]
    relaxed_flags = base_flags | getattr(ida_typeinf, "PT_RELAXED", 0)
    if "::" in parse_text and relaxed_flags != base_flags:
        flag_candidates.append(relaxed_flags)
    for parse_flags in flag_candidates:
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(tif, None, parse_text, parse_flags):
            return tif
    return None


def _proto_get(runtime: IdaRuntime, request: PrototypeGetRequest) -> dict[str, object]:
    return _prototype_view(runtime, request)


def _proto_set(runtime: IdaRuntime, request: PrototypeSetRequest) -> dict[str, object]:
    ea = runtime.function_ea(request.identifier)
    decl = request.decl
    original_name = runtime.ida_name.get_name(ea) or ""
    unknown_types = _unknown_proto_types(runtime, decl)
    tif = _parse_prototype_decl(runtime, decl)
    if tif is None:
        if unknown_types:
            rendered = ", ".join(unknown_types)
            raise IdaOperationError(f"failed to apply prototype at {hex(ea)}; unknown type(s): {rendered}")
        current_prototype = runtime.ida_typeinf.print_type(ea, runtime.ida_typeinf.PRTYPE_1LINE) or ""
        raise IdaOperationError(
            f"failed to apply prototype at {hex(ea)}; current prototype: {current_prototype or '<unknown>'}; "
            "check declaration syntax, parser limitations, missing support types, "
            "and retry after `function prototype show`"
        )
    if not runtime.ida_typeinf.apply_tinfo(ea, tif, runtime.ida_typeinf.TINFO_DEFINITE):
        current_prototype = runtime.ida_typeinf.print_type(ea, runtime.ida_typeinf.PRTYPE_1LINE) or ""
        raise IdaOperationError(
            f"failed to apply prototype at {hex(ea)}; current prototype: {current_prototype or '<unknown>'}; "
            "parsed declaration successfully but apply_tinfo failed"
        )
    callers_considered = 0
    callers_updated = 0
    callers_failed = 0
    if request.propagate_callers:
        callers_considered, callers_updated, callers_failed = _propagate_callee_tinfo(runtime, ea, tif)
    normalized_decl = decl if decl.endswith(";") else f"{decl};"
    if original_name and _decl_looks_like_destructor(normalized_decl):
        current_name = runtime.ida_name.get_name(ea) or ""
        if current_name and current_name != original_name:
            with suppress_recoverable_ida_errors():
                runtime.ida_name.set_name(ea, original_name, runtime.ida_name.SN_CHECK)
    return {
        "address": hex(ea),
        "prototype": runtime.ida_typeinf.print_type(ea, runtime.ida_typeinf.PRTYPE_1LINE) or "",
        "changed": True,
        "callers_considered": callers_considered,
        "callers_updated": callers_updated,
        "callers_failed": callers_failed,
    }


def _run_proto_get(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _proto_get(runtime, _parse_proto_get(params))


def _run_proto_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _proto_set(runtime, _parse_proto_set(params))


def _capture_proto_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _prototype_view(runtime, _parse_proto_set(params))


PROTOTYPE_OPS: dict[str, Op] = {
    "proto_get": Op(run=_run_proto_get),
    "proto_set": Op(
        run=_run_proto_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_proto_set,
            capture_after=_capture_proto_set,
            use_undo=True,
        ),
    ),
}


__all__ = [
    "PROTOTYPE_OPS",
    "PrototypeGetRequest",
    "PrototypeSetRequest",
]
