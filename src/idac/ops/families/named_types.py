from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.params import optional_param_int, param_int
from ..preview import PreviewSpec
from ..runtime import IdaOperationError, IdaRuntime


@dataclass(frozen=True)
class NamedTypeListRequest:
    query: str | None
    pattern: str | None
    glob: bool
    regex: bool
    ignore_case: bool


@dataclass(frozen=True)
class NamedTypeShowRequest:
    name: str


@dataclass(frozen=True)
class StructFieldSetRequest:
    struct_name: str
    field_name: str
    decl: str
    offset: int


@dataclass(frozen=True)
class StructFieldRenameRequest:
    struct_name: str
    field_name: str
    new_name: str


@dataclass(frozen=True)
class StructFieldDeleteRequest:
    struct_name: str
    field_name: str


@dataclass(frozen=True)
class EnumMemberSetRequest:
    enum_name: str
    member_name: str
    value: int
    mask: int | None


@dataclass(frozen=True)
class EnumMemberRenameRequest:
    enum_name: str
    member_name: str
    new_name: str


@dataclass(frozen=True)
class EnumMemberDeleteRequest:
    enum_name: str
    member_name: str


_UNKNOWN_TINFO_SIZE_THRESHOLD = 1 << 63


def _require_name(params: Mapping[str, Any], *, key: str = "name", message: str = "type name is required") -> str:
    value = str(params.get(key) or "").strip()
    if not value:
        raise IdaOperationError(message)
    return value


def _parse_list(params: Mapping[str, Any]) -> NamedTypeListRequest:
    query = str(params.get("query") or "").strip() or None
    pattern = str(params.get("pattern") or "").strip() or None
    return NamedTypeListRequest(
        query=query,
        pattern=pattern,
        glob=bool(params.get("glob")),
        regex=bool(params.get("regex")),
        ignore_case=bool(params.get("ignore_case")),
    )


def _parse_show(params: Mapping[str, Any]) -> NamedTypeShowRequest:
    return NamedTypeShowRequest(name=_require_name(params))


def _parse_struct_show(params: Mapping[str, Any]) -> NamedTypeShowRequest:
    return NamedTypeShowRequest(name=_require_name(params, message="struct name is required"))


def _parse_enum_show(params: Mapping[str, Any]) -> NamedTypeShowRequest:
    return NamedTypeShowRequest(name=_require_name(params, message="enum name is required"))


def _parse_struct_field_set(params: Mapping[str, Any]) -> StructFieldSetRequest:
    struct_name = _require_name(params, key="struct_name", message="struct name is required")
    field_name = _require_name(params, key="field_name", message="field name is required")
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("struct field declaration is required")
    offset = param_int(params, "offset", label="struct field offset", minimum=0)
    return StructFieldSetRequest(struct_name=struct_name, field_name=field_name, decl=decl, offset=offset)


def _parse_struct_field_rename(params: Mapping[str, Any]) -> StructFieldRenameRequest:
    return StructFieldRenameRequest(
        struct_name=_require_name(params, key="struct_name", message="struct name is required"),
        field_name=_require_name(params, key="field_name", message="field name is required"),
        new_name=_require_name(params, key="new_name", message="new field name is required"),
    )


def _parse_struct_field_delete(params: Mapping[str, Any]) -> StructFieldDeleteRequest:
    return StructFieldDeleteRequest(
        struct_name=_require_name(params, key="struct_name", message="struct name is required"),
        field_name=_require_name(params, key="field_name", message="field name is required"),
    )


def _parse_enum_member_set(params: Mapping[str, Any]) -> EnumMemberSetRequest:
    return EnumMemberSetRequest(
        enum_name=_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_require_name(params, key="member_name", message="enum member name is required"),
        value=param_int(params, "value", label="enum member value"),
        mask=None if params.get("mask") in (None, "") else optional_param_int(params, "mask", label="enum member mask"),
    )


def _parse_enum_member_rename(params: Mapping[str, Any]) -> EnumMemberRenameRequest:
    return EnumMemberRenameRequest(
        enum_name=_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_require_name(params, key="member_name", message="enum member name is required"),
        new_name=_require_name(params, key="new_name", message="new enum member name is required"),
    )


def _parse_enum_member_delete(params: Mapping[str, Any]) -> EnumMemberDeleteRequest:
    return EnumMemberDeleteRequest(
        enum_name=_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_require_name(params, key="member_name", message="enum member name is required"),
    )


def _normalize_tinfo_size(value: object) -> int | None:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return None
    if size < 0 or size >= _UNKNOWN_TINFO_SIZE_THRESHOLD:
        return None
    return size


def _named_type_entry_rows(rows: list[dict[str, Any]]) -> list[dict[str, object]]:
    return [
        {
            "name": str(item.get("name") or ""),
            "kind": str(item.get("kind") or ""),
            "decl": str(item.get("decl") or ""),
        }
        for item in rows
    ]


def _struct_member_rows(rows: list[dict[str, Any]]) -> list[dict[str, object]]:
    return [
        {
            "index": int(item.get("index") or 0),
            "name": None if item.get("name") is None else str(item.get("name")),
            "offset_bits": int(item.get("offset_bits") or 0),
            "offset": int(item.get("offset") or 0),
            "size_bits": int(item.get("size_bits") or 0),
            "size": None if item.get("size") is None else int(item.get("size")),
            "type": str(item.get("type") or ""),
            "comment": str(item.get("comment") or ""),
        }
        for item in rows
    ]


def _enum_member_rows(rows: list[dict[str, Any]]) -> list[dict[str, object]]:
    return [
        {
            "index": int(item.get("index") or 0),
            "name": None if item.get("name") is None else str(item.get("name")),
            "value": int(item.get("value") or 0),
            "value_hex": str(item.get("value_hex") or hex(int(item.get("value") or 0))),
            "comment": str(item.get("comment") or ""),
        }
        for item in rows
    ]


def _ensure_terr_ok(runtime: IdaRuntime, code: int, action: str) -> None:
    ida_typeinf = runtime.mod("ida_typeinf")
    if code != ida_typeinf.TERR_OK:
        raise IdaOperationError(f"{action}: {ida_typeinf.tinfo_errstr(code)}")


def _persist_named_type(runtime: IdaRuntime, tif, name: str) -> None:
    ida_typeinf = runtime.mod("ida_typeinf")
    code = tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
    if code != ida_typeinf.TERR_OK:
        raise IdaOperationError(f"failed to persist type `{name}`: {ida_typeinf.tinfo_errstr(code)}")


def _struct_member_index(tif, struct_name: str, field_name: str) -> int:
    idx, _udm = tif.get_udm(field_name)
    if idx < 0:
        raise IdaOperationError(f"struct field not found: {struct_name}.{field_name}")
    return idx


def _enum_type(runtime: IdaRuntime, name: str):
    return runtime.get_named_type(name, kind="enum")


def _enum_member_index(tif, enum_name: str, member_name: str) -> int:
    idx, _edm = tif.get_edm(member_name)
    if idx < 0:
        raise IdaOperationError(f"enum member not found: {enum_name}.{member_name}")
    return idx


def _parse_member_type(runtime: IdaRuntime, decl: str, field_name: str):
    ida_typeinf = runtime.mod("ida_typeinf")
    tif = ida_typeinf.tinfo_t()
    parse_flags = ida_typeinf.PT_VAR | ida_typeinf.PT_SIL | ida_typeinf.PT_SEMICOLON
    raw_decl = decl.strip()
    normalized_decl = f"{raw_decl.rstrip(';')};"
    candidates: list[str] = []
    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(field_name)}(?![A-Za-z0-9_])", raw_decl):
        candidates.append(normalized_decl)
    candidates.append(f"{raw_decl.rstrip(';')} {field_name};")
    for parse_text in dict.fromkeys(candidates):
        if ida_typeinf.parse_decl(tif, None, parse_text, parse_flags):
            return tif
    raise IdaOperationError(f"failed to parse member type: {decl}")


def _type_list(runtime: IdaRuntime, request: NamedTypeListRequest) -> list[dict[str, object]]:
    return _named_type_entry_rows(
        runtime.list_named_types(
            query=request.query,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
        )
    )


def _type_show(runtime: IdaRuntime, request: NamedTypeShowRequest) -> dict[str, object]:
    tif = runtime.get_named_type(request.name)
    kind = runtime.classify_tinfo(tif)
    size = _normalize_tinfo_size(tif.get_size())
    decl = runtime.tinfo_decl(tif, name=request.name, multi=True)
    if kind in {"struct", "union"}:
        return {
            "name": request.name,
            "kind": kind,
            "size": size,
            "size_known": size is not None,
            "decl": decl,
            "layout": decl,
            "members": _struct_member_rows(runtime.tinfo_members(tif)),
        }
    if kind == "enum":
        return {
            "name": request.name,
            "kind": kind,
            "size": size,
            "size_known": size is not None,
            "decl": decl,
            "members": _enum_member_rows(runtime.enum_members(tif)),
        }
    return {
        "name": request.name,
        "kind": kind,
        "size": size,
        "size_known": size is not None,
        "decl": decl,
    }


def _struct_list(runtime: IdaRuntime, request: NamedTypeListRequest) -> list[dict[str, object]]:
    return _named_type_entry_rows(
        runtime.list_named_types(
            query=request.query,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
            kinds={"struct", "union"},
        )
    )


def _struct_view(runtime: IdaRuntime, request: NamedTypeShowRequest) -> dict[str, object]:
    tif = runtime.get_struct_or_union(request.name)
    return {
        "name": request.name,
        "kind": runtime.classify_tinfo(tif),
        "layout": runtime.tinfo_decl(tif, name=request.name, multi=True),
        "members": _struct_member_rows(runtime.tinfo_members(tif)),
    }


def _persist_and_show_struct(runtime: IdaRuntime, tif, *, name: str) -> dict[str, object]:
    _persist_named_type(runtime, tif, name)
    try:
        shown = _struct_view(runtime, NamedTypeShowRequest(name=name))
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"persisted named type `{name}` but failed to read it back: {detail}") from exc
    return {**shown, "changed": True}


def _struct_field_set(runtime: IdaRuntime, request: StructFieldSetRequest) -> dict[str, object]:
    tif = runtime.get_struct_or_union(request.struct_name)
    offset_bits = request.offset * 8
    member_tif = _parse_member_type(runtime, request.decl, request.field_name)
    idx, udm = tif.get_udm_by_offset(offset_bits)
    if idx >= 0 and udm is not None and udm.offset == offset_bits:
        _ensure_terr_ok(runtime, tif.set_udm_type(idx, member_tif), "failed to set field type")
        if udm.name != request.field_name:
            _ensure_terr_ok(runtime, tif.rename_udm(idx, request.field_name), "failed to rename field")
    else:
        _ensure_terr_ok(runtime, tif.add_udm(request.field_name, member_tif, offset_bits), "failed to add field")
    return _persist_and_show_struct(runtime, tif, name=request.struct_name)


def _struct_field_rename(runtime: IdaRuntime, request: StructFieldRenameRequest) -> dict[str, object]:
    tif = runtime.get_struct_or_union(request.struct_name)
    idx = _struct_member_index(tif, request.struct_name, request.field_name)
    _ensure_terr_ok(runtime, tif.rename_udm(idx, request.new_name), "failed to rename field")
    return _persist_and_show_struct(runtime, tif, name=request.struct_name)


def _struct_field_delete(runtime: IdaRuntime, request: StructFieldDeleteRequest) -> dict[str, object]:
    tif = runtime.get_struct_or_union(request.struct_name)
    idx = _struct_member_index(tif, request.struct_name, request.field_name)
    _ensure_terr_ok(runtime, tif.del_udm(idx), "failed to delete field")
    return _persist_and_show_struct(runtime, tif, name=request.struct_name)


def _enum_list(runtime: IdaRuntime, request: NamedTypeListRequest) -> list[dict[str, object]]:
    return _named_type_entry_rows(
        runtime.list_named_types(
            query=request.query,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
            kinds={"enum"},
        )
    )


def _enum_view(runtime: IdaRuntime, request: NamedTypeShowRequest) -> dict[str, object]:
    tif = _enum_type(runtime, request.name)
    return {
        "name": request.name,
        "kind": "enum",
        "decl": runtime.tinfo_decl(tif, name=request.name, multi=True),
        "members": _enum_member_rows(runtime.enum_members(tif)),
    }


def _persist_and_show_enum(runtime: IdaRuntime, tif, *, name: str) -> dict[str, object]:
    _persist_named_type(runtime, tif, name)
    try:
        shown = _enum_view(runtime, NamedTypeShowRequest(name=name))
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"persisted named type `{name}` but failed to read it back: {detail}") from exc
    return {**shown, "changed": True}


def _enum_member_set(runtime: IdaRuntime, request: EnumMemberSetRequest) -> dict[str, object]:
    tif = _enum_type(runtime, request.enum_name)
    ida_typeinf = runtime.mod("ida_typeinf")
    mask = ida_typeinf.DEFMASK64 if request.mask is None else request.mask
    idx, _edm = tif.get_edm(request.member_name)
    if idx >= 0:
        _ensure_terr_ok(runtime, tif.edit_edm(idx, request.value, mask), "failed to edit enum member")
    else:
        _ensure_terr_ok(runtime, tif.add_edm(request.member_name, request.value, mask), "failed to add enum member")
    return _persist_and_show_enum(runtime, tif, name=request.enum_name)


def _enum_member_rename(runtime: IdaRuntime, request: EnumMemberRenameRequest) -> dict[str, object]:
    tif = _enum_type(runtime, request.enum_name)
    idx = _enum_member_index(tif, request.enum_name, request.member_name)
    _ensure_terr_ok(runtime, tif.rename_edm(idx, request.new_name), "failed to rename enum member")
    return _persist_and_show_enum(runtime, tif, name=request.enum_name)


def _enum_member_delete(runtime: IdaRuntime, request: EnumMemberDeleteRequest) -> dict[str, object]:
    tif = _enum_type(runtime, request.enum_name)
    _ensure_terr_ok(runtime, tif.del_edm(request.member_name), "failed to delete enum member")
    return _persist_and_show_enum(runtime, tif, name=request.enum_name)


def _run_type_list(runtime: IdaRuntime, params: Mapping[str, Any]) -> list[dict[str, object]]:
    return _type_list(runtime, _parse_list(params))


def _run_type_show(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _type_show(runtime, _parse_show(params))


def _run_struct_list(runtime: IdaRuntime, params: Mapping[str, Any]) -> list[dict[str, object]]:
    return _struct_list(runtime, _parse_list(params))


def _run_struct_show(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _struct_view(runtime, _parse_struct_show(params))


def _run_struct_field_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _struct_field_set(runtime, _parse_struct_field_set(params))


def _run_struct_field_rename(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _struct_field_rename(runtime, _parse_struct_field_rename(params))


def _run_struct_field_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _struct_field_delete(runtime, _parse_struct_field_delete(params))


def _capture_struct_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_struct_field_set(params)
    return _struct_view(runtime, NamedTypeShowRequest(name=request.struct_name))


def _capture_struct_rename(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_struct_field_rename(params)
    return _struct_view(runtime, NamedTypeShowRequest(name=request.struct_name))


def _capture_struct_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_struct_field_delete(params)
    return _struct_view(runtime, NamedTypeShowRequest(name=request.struct_name))


def _run_enum_list(runtime: IdaRuntime, params: Mapping[str, Any]) -> list[dict[str, object]]:
    return _enum_list(runtime, _parse_list(params))


def _run_enum_show(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _enum_view(runtime, _parse_enum_show(params))


def _run_enum_member_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _enum_member_set(runtime, _parse_enum_member_set(params))


def _run_enum_member_rename(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _enum_member_rename(runtime, _parse_enum_member_rename(params))


def _run_enum_member_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _enum_member_delete(runtime, _parse_enum_member_delete(params))


def _capture_enum_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_enum_member_set(params)
    return _enum_view(runtime, NamedTypeShowRequest(name=request.enum_name))


def _capture_enum_rename(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_enum_member_rename(params)
    return _enum_view(runtime, NamedTypeShowRequest(name=request.enum_name))


def _capture_enum_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    request = _parse_enum_member_delete(params)
    return _enum_view(runtime, NamedTypeShowRequest(name=request.enum_name))


NAMED_TYPE_OPS: dict[str, Op] = {
    "type_list": Op(run=_run_type_list),
    "type_show": Op(run=_run_type_show),
    "struct_list": Op(run=_run_struct_list),
    "struct_show": Op(run=_run_struct_show),
    "struct_field_set": Op(
        run=_run_struct_field_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_struct_set,
            capture_after=_capture_struct_set,
            use_undo=True,
        ),
    ),
    "struct_field_rename": Op(
        run=_run_struct_field_rename,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_struct_rename,
            capture_after=_capture_struct_rename,
            use_undo=True,
        ),
    ),
    "struct_field_delete": Op(
        run=_run_struct_field_delete,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_struct_delete,
            capture_after=_capture_struct_delete,
            use_undo=True,
        ),
    ),
    "enum_list": Op(run=_run_enum_list),
    "enum_show": Op(run=_run_enum_show),
    "enum_member_set": Op(
        run=_run_enum_member_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_enum_set,
            capture_after=_capture_enum_set,
            use_undo=True,
        ),
    ),
    "enum_member_rename": Op(
        run=_run_enum_member_rename,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_enum_rename,
            capture_after=_capture_enum_rename,
            use_undo=True,
        ),
    ),
    "enum_member_delete": Op(
        run=_run_enum_member_delete,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_enum_delete,
            capture_after=_capture_enum_delete,
            use_undo=True,
        ),
    ),
}


__all__ = [
    "NAMED_TYPE_OPS",
    "EnumMemberDeleteRequest",
    "EnumMemberRenameRequest",
    "EnumMemberSetRequest",
    "NamedTypeListRequest",
    "NamedTypeShowRequest",
    "StructFieldDeleteRequest",
    "StructFieldRenameRequest",
    "StructFieldSetRequest",
    "_parse_member_type",
]
