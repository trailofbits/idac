from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.params import optional_param_int, optional_str, require_str
from ..runtime import (
    IdaOperationError,
    IdaRuntime,
    is_recoverable_ida_error,
)
from ..symbols import classify_symbol_kind, is_rtti_symbol_name, is_vtable_symbol_name


@dataclass(frozen=True)
class ClassListRequest:
    query: str | None
    pattern: str | None
    glob: bool
    regex: bool
    ignore_case: bool


@dataclass(frozen=True)
class ClassCandidatesRequest:
    query: str
    kinds: tuple[str, ...]
    glob: bool
    regex: bool
    ignore_case: bool


@dataclass(frozen=True)
class ClassNameRequest:
    name: str


@dataclass(frozen=True)
class ClassFieldsRequest:
    name: str
    derived_only: bool


@dataclass(frozen=True)
class ClassVtableRequest:
    name: str
    runtime: bool


@dataclass(frozen=True)
class VtableDumpRequest:
    identifier: str
    slot_limit: int


def _parse_list(params: Mapping[str, Any]) -> ClassListRequest:
    query = optional_str(params.get("query"))
    pattern = optional_str(params.get("pattern"))
    return ClassListRequest(
        query=query,
        pattern=pattern,
        glob=bool(params.get("glob")),
        regex=bool(params.get("regex")),
        ignore_case=bool(params.get("ignore_case")),
    )


def _parse_candidates(params: Mapping[str, Any]) -> ClassCandidatesRequest:
    query = str(params.get("pattern") or params.get("query") or "")
    kinds = tuple(str(item) for item in (params.get("kinds") or []) if str(item))
    return ClassCandidatesRequest(
        query=query,
        kinds=kinds,
        glob=bool(params.get("glob")),
        regex=bool(params.get("regex")),
        ignore_case=bool(params.get("ignore_case")) or params.get("query") not in (None, ""),
    )


def _parse_name(params: Mapping[str, Any]) -> ClassNameRequest:
    return ClassNameRequest(name=require_str(params.get("name"), field="class name"))


def _parse_fields(params: Mapping[str, Any]) -> ClassFieldsRequest:
    return ClassFieldsRequest(
        name=require_str(params.get("name"), field="class name"),
        derived_only=bool(params.get("derived_only")),
    )


def _parse_class_vtable(params: Mapping[str, Any]) -> ClassVtableRequest:
    return ClassVtableRequest(
        name=require_str(params.get("name"), field="class name"),
        runtime=bool(params.get("runtime")),
    )


def _parse_vtable_dump(params: Mapping[str, Any]) -> VtableDumpRequest:
    identifier = require_str(params.get("identifier"), field="vtable identifier")
    slot_limit = optional_param_int(params, "slot_limit", label="vtable slot limit", minimum=1) or 64
    return VtableDumpRequest(identifier=identifier, slot_limit=slot_limit)


def _class_graph(runtime: IdaRuntime) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    rows = runtime.list_named_classes()
    classes = {row["name"]: row for row in rows}
    children: dict[str, list[str]] = {name: [] for name in classes}
    for name, row in classes.items():
        for base_name in row.get("bases") or []:
            if base_name in children:
                children[base_name].append(name)
    for names in children.values():
        names.sort(key=str.lower)
    return classes, children


def _member_size_bytes(member) -> int | None:
    size_bits = member.size
    return size_bits // 8 if size_bits else None


def _base_tif(runtime: IdaRuntime, member):
    base_name = member.type.get_type_name() or member.type.dstr()
    return runtime.find_named_type(base_name or "")


def _iter_udt_members(runtime: IdaRuntime, tif, *, expand_bases: bool, base_offset_bits: int = 0):
    for member in runtime.udt_members(tif):
        offset_bits = base_offset_bits + int(member.offset)
        if runtime.member_has(member, "is_baseclass"):
            if expand_bases:
                base_tif = _base_tif(runtime, member)
                if base_tif is not None:
                    yield from _iter_udt_members(
                        runtime,
                        base_tif,
                        expand_bases=True,
                        base_offset_bits=offset_bits,
                    )
            continue
        yield offset_bits, member


def _walk_graph(start: list[str], edges: dict[str, list[str]], *, known: set[str]) -> list[str]:
    queue = deque(start)
    seen: set[str] = set()
    rows: list[str] = []
    while queue:
        current = queue.popleft()
        if current in seen or current not in known:
            continue
        seen.add(current)
        rows.append(current)
        queue.extend(edges.get(current, []))
    return rows


def _vtable_header(runtime: IdaRuntime, table_ea: int, symbol_name: str, *, ptr_size: int):
    ida_name = runtime.mod("ida_name")
    if _looks_like_itanium_vtable(runtime, table_ea, symbol_name):
        typeinfo_ea = runtime.read_pointer(table_ea + ptr_size)
        return (
            "itanium",
            table_ea + (ptr_size * 2),
            [
                {
                    "index": 0,
                    "address": hex(table_ea),
                    "value": hex(runtime.read_pointer(table_ea)),
                    "name": "offset_to_top",
                },
                {
                    "index": 1,
                    "address": hex(table_ea + ptr_size),
                    "value": hex(typeinfo_ea),
                    "name": "typeinfo",
                    "symbol": ida_name.get_name(typeinfo_ea) or "",
                    "demangled": runtime.demangle_name(ida_name.get_name(typeinfo_ea) or ""),
                },
            ],
        )
    if symbol_name.startswith("??_7"):
        return "msvc", table_ea, []
    return "unknown", table_ea, []


def _flatten_class_fields(runtime: IdaRuntime, tif, *, derived_only: bool) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for offset_bits, member in _iter_udt_members(runtime, tif, expand_bases=not derived_only):
        if runtime.member_has(member, "is_method"):
            continue
        fields.append(
            {
                "name": member.name or "",
                "offset_bits": offset_bits,
                "offset": offset_bits // 8,
                "size_bits": member.size,
                "size": _member_size_bytes(member),
                "type": member.type.dstr() or runtime.tinfo_decl(member.type, multi=False),
                "is_vftable": runtime.member_has(member, "is_vftable"),
            }
        )
    fields.sort(key=lambda item: (item["offset"], item["name"]))
    return fields


def _vtable_members(runtime: IdaRuntime, vtable_tif) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, (offset_bits, member) in enumerate(_iter_udt_members(runtime, vtable_tif, expand_bases=True)):
        rows.append(
            {
                "index": index,
                "offset_bits": offset_bits,
                "offset": offset_bits // 8,
                "slot": runtime.vtable_slot(offset_bits),
                "name": member.name or "",
                "type": member.type.dstr() or runtime.tinfo_decl(member.type, multi=False),
                "comment": member.cmt or "",
            }
        )
    rows.sort(key=lambda item: (item["slot"], item["name"]))
    return rows


def _looks_like_itanium_vtable(runtime: IdaRuntime, ea: int, symbol_name: str) -> bool:
    if is_vtable_symbol_name(symbol_name) and not symbol_name.startswith("??_7"):
        return True
    ida_name = runtime.mod("ida_name")
    ptr_size = runtime.pointer_size()
    first = runtime.read_pointer(ea)
    second = runtime.read_pointer(ea + ptr_size)
    second_name = ida_name.get_name(second) or ""
    return first == 0 and str(second_name).startswith(("__ZTI", "_ZTI"))


def _resolve_vtable(runtime: IdaRuntime, identifier: str) -> tuple[int, str, str | None]:
    ida_name = runtime.mod("ida_name")
    table_ea = runtime.resolve_address(identifier)
    symbol_name = ida_name.get_name(table_ea) or str(identifier)
    return table_ea, symbol_name, runtime.demangle_name(symbol_name)


def _runtime_vtable_member(runtime: IdaRuntime, entry_ea: int, slot: int) -> tuple[dict[str, Any] | None, str | None]:
    ida_name = runtime.mod("ida_name")
    ida_bytes = runtime.mod("ida_bytes")
    ida_funcs = runtime.mod("ida_funcs")
    target = runtime.read_pointer(entry_ea)
    if target == 0:
        return None, "null_target"
    name = ida_name.get_name(target) or ""
    if is_rtti_symbol_name(name):
        return None, "rtti_boundary"
    flags = ida_bytes.get_flags(target)
    is_code = bool(ida_bytes.is_code(flags)) or ida_funcs.get_func(target) is not None
    if not is_code:
        return None, "non_function_target"
    return (
        {
            "slot": slot,
            "entry_address": hex(entry_ea),
            "target": hex(target),
            "name": name,
            "demangled": runtime.demangle_name(name),
            "is_code": is_code,
        },
        None,
    )


def _runtime_vtable_members(runtime: IdaRuntime, slot_ea: int, *, slot_limit: int, ptr_size: int):
    rows: list[dict[str, Any]] = []
    for slot in range(max(1, slot_limit)):
        entry_ea = slot_ea + slot * ptr_size
        member, stop_reason = _runtime_vtable_member(runtime, entry_ea, slot)
        if member is None:
            return rows, stop_reason
        rows.append(member)
    return rows, "slot_limit"


def _raw_vtable_dump(runtime: IdaRuntime, identifier: str, *, slot_limit: int = 64) -> dict[str, Any]:
    table_ea, symbol_name, demangled = _resolve_vtable(runtime, identifier)
    ptr_size = runtime.pointer_size()
    abi, slot_ea, header = _vtable_header(runtime, table_ea, symbol_name, ptr_size=ptr_size)
    members, stop_reason = _runtime_vtable_members(runtime, slot_ea, slot_limit=slot_limit, ptr_size=ptr_size)
    return {
        "identifier": identifier,
        "kind": "raw_vtable",
        "abi": abi,
        "table_address": hex(table_ea),
        "slot_address": hex(slot_ea),
        "symbol": symbol_name,
        "demangled_symbol": demangled,
        "header": header,
        "slot_count": len(members),
        "members": members,
        "stop_reason": stop_reason,
    }


def _raise_non_materialized_class_error(runtime: IdaRuntime, name: str, tif) -> None:
    kind = runtime.classify_tinfo(tif)
    if kind in {"struct", "union"}:
        raise IdaOperationError(
            f"type `{name}` exists as a {kind}, but is not class-materialized in local types; "
            + _class_materialization_hint(runtime, name)
        )
    raise IdaOperationError(f"type `{name}` exists as `{kind}`, but is not class-materialized in local types")


def _class_materialization_hint(runtime: IdaRuntime, name: str) -> str:
    hints = [
        f"try `type show {name}`",
        f"`type class candidates --query {name}`",
        "then import a concrete class layout with `type declare --replace`",
    ]
    evidence = _symbol_evidence(runtime, name)
    if evidence:
        hints.append("symbol evidence: " + ", ".join(evidence))
    return "; ".join(hints)


def _symbol_evidence(runtime: IdaRuntime, name: str) -> list[str]:
    try:
        symbols = runtime.find_symbols(query=name)
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise
        return []
    if not isinstance(symbols, list):
        return []

    vtable_count = 0
    typeinfo_count = 0
    function_count = 0
    for item in symbols:
        if not isinstance(item, dict):
            continue
        symbol_name = str(item.get("name") or "")
        kind = classify_symbol_kind(symbol_name, is_function=bool(item.get("is_function")))
        if kind == "vtable_symbol":
            vtable_count += 1
        elif kind in {"typeinfo_symbol", "typeinfo_name_symbol"}:
            typeinfo_count += 1
        elif kind == "function_symbol":
            function_count += 1

    evidence: list[str] = []
    if vtable_count:
        evidence.append(f"{vtable_count} vtable symbol(s)")
    if typeinfo_count:
        evidence.append(f"{typeinfo_count} RTTI symbol(s)")
    if function_count:
        evidence.append(f"{function_count} function symbol(s)")
    return evidence


def _local_type_candidate_rows(
    runtime: IdaRuntime,
    query: str,
    kind_filter: set[str],
    seen: set[tuple[str, str, str]],
    *,
    glob: bool,
    regex: bool,
    ignore_case: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in runtime.list_named_types(pattern=query or None, glob=glob, regex=regex, ignore_case=ignore_case):
        key = ("local_type", str(item.get("name") or ""), "")
        if key in seen or (kind_filter and "local_type" not in kind_filter):
            continue
        seen.add(key)
        rows.append(
            {
                "kind": "local_type",
                "name": item.get("name"),
                "decl": item.get("decl"),
                "type_kind": item.get("kind"),
            }
        )
    return rows


def _symbol_candidate_rows(
    runtime: IdaRuntime,
    query: str,
    kind_filter: set[str],
    seen: set[tuple[str, str, str]],
    *,
    glob: bool,
    regex: bool,
    ignore_case: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in runtime.find_symbols(pattern=query or None, glob=glob, regex=regex, ignore_case=ignore_case):
        name = str(item.get("name") or "")
        kind = classify_symbol_kind(name, is_function=bool(item.get("is_function")))
        if kind_filter and kind not in kind_filter:
            continue
        key = (kind, name, str(item.get("address") or ""))
        if key in seen:
            continue
        seen.add(key)
        rows.append({"kind": kind, "name": name, "address": item.get("address"), "demangled": item.get("demangled")})
    return rows


def _runtime_class_vtable(runtime: IdaRuntime, name: str, tif) -> dict[str, Any] | None:
    identifier = runtime.class_runtime_vtable_identifier(tif, name=name)
    if identifier is None:
        return None
    return _raw_vtable_dump(runtime, identifier)


def _require_class_tinfo(runtime: IdaRuntime, name: str):
    tif = runtime.find_named_type(name)
    if tif is None:
        raise IdaOperationError(f"class not found: {name}")
    if not runtime.is_class_tinfo(tif):
        _raise_non_materialized_class_error(runtime, name, tif)
    return tif


def _class_list(runtime: IdaRuntime, request: ClassListRequest) -> list[dict[str, Any]]:
    return runtime.list_named_classes(
        query=request.query,
        pattern=request.pattern,
        glob=request.glob,
        regex=request.regex,
        ignore_case=request.ignore_case,
    )


def _class_candidates(runtime: IdaRuntime, request: ClassCandidatesRequest) -> list[dict[str, Any]]:
    kind_filter = set(request.kinds)
    seen: set[tuple[str, str, str]] = set()
    rows = _local_type_candidate_rows(
        runtime,
        request.query,
        kind_filter,
        seen,
        glob=request.glob,
        regex=request.regex,
        ignore_case=request.ignore_case,
    )
    rows.extend(
        _symbol_candidate_rows(
            runtime,
            request.query,
            kind_filter,
            seen,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
        )
    )
    rows.sort(key=lambda item: (str(item.get("kind") or ""), str(item.get("name") or "").lower()))
    return rows


def _class_show(runtime: IdaRuntime, request: ClassNameRequest) -> dict[str, Any]:
    tif = _require_class_tinfo(runtime, request.name)
    payload = dict(runtime.class_summary(tif, name=request.name, decl_multi=True))
    payload["members"] = _flatten_class_fields(runtime, tif, derived_only=False)
    return payload


def _class_hierarchy(runtime: IdaRuntime, request: ClassNameRequest) -> dict[str, Any]:
    name = request.name
    classes, children = _class_graph(runtime)
    if name not in classes:
        tif = runtime.find_named_type(name)
        if tif is not None and not runtime.is_class_tinfo(tif):
            _raise_non_materialized_class_error(runtime, name, tif)
        raise IdaOperationError(f"class not found: {name}")
    base_edges = {class_name: row.get("bases") or [] for class_name, row in classes.items()}
    known = set(classes)
    ancestors = _walk_graph(list(classes[name].get("bases") or []), base_edges, known=known)
    descendants = _walk_graph(list(children.get(name, [])), children, known=known)
    return {
        "name": name,
        "bases": classes[name].get("bases") or [],
        "derived": children.get(name, []),
        "ancestors": ancestors,
        "descendants": descendants,
    }


def _class_fields(runtime: IdaRuntime, request: ClassFieldsRequest) -> dict[str, Any]:
    tif = _require_class_tinfo(runtime, request.name)
    return {
        "name": request.name,
        "kind": "class_fields",
        "derived_only": request.derived_only,
        "fields": _flatten_class_fields(runtime, tif, derived_only=request.derived_only),
    }


def _class_vtable(runtime: IdaRuntime, request: ClassVtableRequest) -> dict[str, Any]:
    tif = _require_class_tinfo(runtime, request.name)
    vtable_name = runtime.class_vtable_type_name(tif)
    if not vtable_name:
        raise IdaOperationError(f"class has no vtable type: {request.name}")
    vtable_tif = runtime.get_named_type(vtable_name)
    payload = {
        "name": request.name,
        "kind": "class_vtable",
        "vtable_type": vtable_name,
        "decl": runtime.tinfo_decl(vtable_tif, name=vtable_name, multi=True),
        "members": _vtable_members(runtime, vtable_tif),
    }
    if request.runtime:
        runtime_vtable = _runtime_class_vtable(runtime, request.name, tif)
        if runtime_vtable is not None:
            payload["runtime_vtable"] = runtime_vtable
    return payload


def _vtable_dump(runtime: IdaRuntime, request: VtableDumpRequest) -> dict[str, Any]:
    return _raw_vtable_dump(runtime, request.identifier, slot_limit=request.slot_limit)


def _run_class_list(runtime: IdaRuntime, params: Mapping[str, Any]) -> list[dict[str, Any]]:
    return _class_list(runtime, _parse_list(params))


def _run_class_candidates(runtime: IdaRuntime, params: Mapping[str, Any]) -> list[dict[str, Any]]:
    return _class_candidates(runtime, _parse_candidates(params))


def _run_class_show(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, Any]:
    return _class_show(runtime, _parse_name(params))


def _run_class_hierarchy(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, Any]:
    return _class_hierarchy(runtime, _parse_name(params))


def _run_class_fields(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, Any]:
    return _class_fields(runtime, _parse_fields(params))


def _run_class_vtable(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, Any]:
    return _class_vtable(runtime, _parse_class_vtable(params))


def _run_vtable_dump(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, Any]:
    return _vtable_dump(runtime, _parse_vtable_dump(params))


CLASS_OPS: dict[str, Op] = {
    "class_list": Op(run=_run_class_list),
    "class_candidates": Op(run=_run_class_candidates),
    "class_show": Op(run=_run_class_show),
    "class_hierarchy": Op(run=_run_class_hierarchy),
    "class_fields": Op(run=_run_class_fields),
    "class_vtable": Op(run=_run_class_vtable),
    "vtable_dump": Op(run=_run_vtable_dump),
}


__all__ = [
    "CLASS_OPS",
    "_flatten_class_fields",
    "_raw_vtable_dump",
    "_require_class_tinfo",
    "_symbol_evidence",
    "_vtable_members",
]
