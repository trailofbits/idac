from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..base import OperationContext, OperationSpec
from ..helpers.params import optional_param_int, param_int
from ..models import payload_from_model
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


@dataclass(frozen=True)
class NamedTypeEntry:
    name: str
    kind: str
    decl: str


@dataclass(frozen=True)
class StructMember:
    index: int
    name: str | None
    offset_bits: int
    offset: int
    size_bits: int
    size: int | None
    type: str
    comment: str


@dataclass(frozen=True)
class EnumMember:
    index: int
    name: str | None
    value: int
    value_hex: str
    comment: str


@dataclass(frozen=True)
class NamedTypeView:
    name: str
    kind: str
    size: int | None
    size_known: bool
    decl: str


@dataclass(frozen=True)
class StructuredTypeView:
    name: str
    kind: str
    size: int | None
    size_known: bool
    decl: str
    layout: str
    members: tuple[StructMember, ...]


@dataclass(frozen=True)
class EnumTypeView:
    name: str
    kind: str
    size: int | None
    size_known: bool
    decl: str
    members: tuple[EnumMember, ...]


@dataclass(frozen=True)
class StructView:
    name: str
    kind: str
    layout: str
    members: tuple[StructMember, ...]


@dataclass(frozen=True)
class StructMutationResult:
    name: str
    kind: str
    layout: str
    members: tuple[StructMember, ...]
    changed: bool


@dataclass(frozen=True)
class EnumView:
    name: str
    kind: str
    decl: str
    members: tuple[EnumMember, ...]


@dataclass(frozen=True)
class EnumMutationResult:
    name: str
    kind: str
    decl: str
    members: tuple[EnumMember, ...]
    changed: bool


_UNKNOWN_TINFO_SIZE_THRESHOLD = 1 << 63


def _require_name(params: dict[str, object], *, key: str = "name", message: str = "type name is required") -> str:
    value = str(params.get(key) or "").strip()
    if not value:
        raise IdaOperationError(message)
    return value


def _parse_list(params: dict[str, object]) -> NamedTypeListRequest:
    query = str(params.get("query") or "").strip() or None
    pattern = str(params.get("pattern") or "").strip() or None
    return NamedTypeListRequest(
        query=query,
        pattern=pattern,
        glob=bool(params.get("glob")),
        regex=bool(params.get("regex")),
        ignore_case=bool(params.get("ignore_case")),
    )


def _parse_show(params: dict[str, object]) -> NamedTypeShowRequest:
    return NamedTypeShowRequest(name=_require_name(params))


def _parse_struct_show(params: dict[str, object]) -> NamedTypeShowRequest:
    return NamedTypeShowRequest(name=_require_name(params, message="struct name is required"))


def _parse_enum_show(params: dict[str, object]) -> NamedTypeShowRequest:
    return NamedTypeShowRequest(name=_require_name(params, message="enum name is required"))


def _parse_struct_field_set(params: dict[str, object]) -> StructFieldSetRequest:
    struct_name = _require_name(params, key="struct_name", message="struct name is required")
    field_name = _require_name(params, key="field_name", message="field name is required")
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("struct field declaration is required")
    offset = param_int(params, "offset", label="struct field offset", minimum=0)
    return StructFieldSetRequest(struct_name=struct_name, field_name=field_name, decl=decl, offset=offset)


def _parse_struct_field_rename(params: dict[str, object]) -> StructFieldRenameRequest:
    return StructFieldRenameRequest(
        struct_name=_require_name(params, key="struct_name", message="struct name is required"),
        field_name=_require_name(params, key="field_name", message="field name is required"),
        new_name=_require_name(params, key="new_name", message="new field name is required"),
    )


def _parse_struct_field_delete(params: dict[str, object]) -> StructFieldDeleteRequest:
    return StructFieldDeleteRequest(
        struct_name=_require_name(params, key="struct_name", message="struct name is required"),
        field_name=_require_name(params, key="field_name", message="field name is required"),
    )


def _parse_enum_member_set(params: dict[str, object]) -> EnumMemberSetRequest:
    return EnumMemberSetRequest(
        enum_name=_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_require_name(params, key="member_name", message="enum member name is required"),
        value=param_int(params, "value", label="enum member value"),
        mask=None if params.get("mask") in (None, "") else optional_param_int(params, "mask", label="enum member mask"),
    )


def _parse_enum_member_rename(params: dict[str, object]) -> EnumMemberRenameRequest:
    return EnumMemberRenameRequest(
        enum_name=_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_require_name(params, key="member_name", message="enum member name is required"),
        new_name=_require_name(params, key="new_name", message="new enum member name is required"),
    )


def _parse_enum_member_delete(params: dict[str, object]) -> EnumMemberDeleteRequest:
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


def _coerce_named_type_entries(rows: list[dict[str, object]]) -> tuple[NamedTypeEntry, ...]:
    return tuple(
        NamedTypeEntry(
            name=str(item.get("name") or ""),
            kind=str(item.get("kind") or ""),
            decl=str(item.get("decl") or ""),
        )
        for item in rows
    )


def _coerce_struct_members(rows: list[dict[str, object]]) -> tuple[StructMember, ...]:
    return tuple(
        StructMember(
            index=int(item.get("index") or 0),
            name=None if item.get("name") is None else str(item.get("name")),
            offset_bits=int(item.get("offset_bits") or 0),
            offset=int(item.get("offset") or 0),
            size_bits=int(item.get("size_bits") or 0),
            size=None if item.get("size") is None else int(item.get("size")),
            type=str(item.get("type") or ""),
            comment=str(item.get("comment") or ""),
        )
        for item in rows
    )


def _coerce_enum_members(rows: list[dict[str, object]]) -> tuple[EnumMember, ...]:
    return tuple(
        EnumMember(
            index=int(item.get("index") or 0),
            name=None if item.get("name") is None else str(item.get("name")),
            value=int(item.get("value") or 0),
            value_hex=str(item.get("value_hex") or hex(int(item.get("value") or 0))),
            comment=str(item.get("comment") or ""),
        )
        for item in rows
    )


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


def _type_list(context: OperationContext, request: NamedTypeListRequest) -> tuple[NamedTypeEntry, ...]:
    runtime = context.runtime
    return _coerce_named_type_entries(
        runtime.list_named_types(
            query=request.query,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
        )
    )


def op_type_list(runtime: IdaRuntime, params: dict[str, Any]) -> tuple[NamedTypeEntry, ...]:
    return _type_list(OperationContext(runtime=runtime), _parse_list(params))


def _type_show(
    context: OperationContext,
    request: NamedTypeShowRequest,
) -> NamedTypeView | StructuredTypeView | EnumTypeView:
    runtime = context.runtime
    tif = runtime.get_named_type(request.name)
    kind = runtime.classify_tinfo(tif)
    size = _normalize_tinfo_size(tif.get_size())
    decl = runtime.tinfo_decl(tif, name=request.name, multi=True)
    if kind in {"struct", "union"}:
        members = _coerce_struct_members(runtime.tinfo_members(tif))
        return StructuredTypeView(
            name=request.name,
            kind=kind,
            size=size,
            size_known=size is not None,
            decl=decl,
            layout=decl,
            members=members,
        )
    if kind == "enum":
        return EnumTypeView(
            name=request.name,
            kind=kind,
            size=size,
            size_known=size is not None,
            decl=decl,
            members=_coerce_enum_members(runtime.enum_members(tif)),
        )
    return NamedTypeView(
        name=request.name,
        kind=kind,
        size=size,
        size_known=size is not None,
        decl=decl,
    )


def op_type_show(runtime: IdaRuntime, params: dict[str, Any]) -> dict[str, object]:
    return payload_from_model(_type_show(OperationContext(runtime=runtime), _parse_show(params)))


def _struct_list(context: OperationContext, request: NamedTypeListRequest) -> tuple[NamedTypeEntry, ...]:
    runtime = context.runtime
    return _coerce_named_type_entries(
        runtime.list_named_types(
            query=request.query,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
            kinds={"struct", "union"},
        )
    )


def op_struct_list(runtime: IdaRuntime, params: dict[str, Any]) -> tuple[NamedTypeEntry, ...]:
    return _struct_list(OperationContext(runtime=runtime), _parse_list(params))


def _struct_view(context: OperationContext, request: NamedTypeShowRequest) -> StructView:
    runtime = context.runtime
    tif = runtime.get_struct_or_union(request.name)
    return StructView(
        name=request.name,
        kind=runtime.classify_tinfo(tif),
        layout=runtime.tinfo_decl(tif, name=request.name, multi=True),
        members=_coerce_struct_members(runtime.tinfo_members(tif)),
    )


def op_struct_show(runtime: IdaRuntime, params: dict[str, Any]) -> StructView:
    return _struct_view(OperationContext(runtime=runtime), _parse_struct_show(params))


def _persist_and_show_struct(runtime: IdaRuntime, tif, *, name: str) -> StructMutationResult:
    _persist_named_type(runtime, tif, name)
    try:
        shown = _struct_view(OperationContext(runtime=runtime), NamedTypeShowRequest(name=name))
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"persisted named type `{name}` but failed to read it back: {detail}") from exc
    return StructMutationResult(
        name=shown.name,
        kind=shown.kind,
        layout=shown.layout,
        members=shown.members,
        changed=True,
    )


def _struct_field_set(context: OperationContext, request: StructFieldSetRequest) -> StructMutationResult:
    runtime = context.runtime
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


def op_struct_field_set(runtime: IdaRuntime, params: dict[str, Any]) -> StructMutationResult:
    return _struct_field_set(OperationContext(runtime=runtime), _parse_struct_field_set(params))


def _struct_field_rename(context: OperationContext, request: StructFieldRenameRequest) -> StructMutationResult:
    runtime = context.runtime
    tif = runtime.get_struct_or_union(request.struct_name)
    idx = _struct_member_index(tif, request.struct_name, request.field_name)
    _ensure_terr_ok(runtime, tif.rename_udm(idx, request.new_name), "failed to rename field")
    return _persist_and_show_struct(runtime, tif, name=request.struct_name)


def op_struct_field_rename(runtime: IdaRuntime, params: dict[str, Any]) -> StructMutationResult:
    return _struct_field_rename(OperationContext(runtime=runtime), _parse_struct_field_rename(params))


def _struct_field_delete(context: OperationContext, request: StructFieldDeleteRequest) -> StructMutationResult:
    runtime = context.runtime
    tif = runtime.get_struct_or_union(request.struct_name)
    idx = _struct_member_index(tif, request.struct_name, request.field_name)
    _ensure_terr_ok(runtime, tif.del_udm(idx), "failed to delete field")
    return _persist_and_show_struct(runtime, tif, name=request.struct_name)


def op_struct_field_delete(runtime: IdaRuntime, params: dict[str, Any]) -> StructMutationResult:
    return _struct_field_delete(OperationContext(runtime=runtime), _parse_struct_field_delete(params))


def _struct_view_for_set(context: OperationContext, request: StructFieldSetRequest) -> StructView:
    return _struct_view(context, NamedTypeShowRequest(name=request.struct_name))


def _struct_view_for_rename(context: OperationContext, request: StructFieldRenameRequest) -> StructView:
    return _struct_view(context, NamedTypeShowRequest(name=request.struct_name))


def _struct_view_for_delete(context: OperationContext, request: StructFieldDeleteRequest) -> StructView:
    return _struct_view(context, NamedTypeShowRequest(name=request.struct_name))


def _enum_list(context: OperationContext, request: NamedTypeListRequest) -> tuple[NamedTypeEntry, ...]:
    runtime = context.runtime
    return _coerce_named_type_entries(
        runtime.list_named_types(
            query=request.query,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
            kinds={"enum"},
        )
    )


def op_enum_list(runtime: IdaRuntime, params: dict[str, Any]) -> tuple[NamedTypeEntry, ...]:
    return _enum_list(OperationContext(runtime=runtime), _parse_list(params))


def _enum_view(context: OperationContext, request: NamedTypeShowRequest) -> EnumView:
    runtime = context.runtime
    tif = _enum_type(runtime, request.name)
    return EnumView(
        name=request.name,
        kind="enum",
        decl=runtime.tinfo_decl(tif, name=request.name, multi=True),
        members=_coerce_enum_members(runtime.enum_members(tif)),
    )


def op_enum_show(runtime: IdaRuntime, params: dict[str, Any]) -> EnumView:
    return _enum_view(OperationContext(runtime=runtime), _parse_enum_show(params))


def _persist_and_show_enum(runtime: IdaRuntime, tif, *, name: str) -> EnumMutationResult:
    _persist_named_type(runtime, tif, name)
    try:
        shown = _enum_view(OperationContext(runtime=runtime), NamedTypeShowRequest(name=name))
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"persisted named type `{name}` but failed to read it back: {detail}") from exc
    return EnumMutationResult(
        name=shown.name,
        kind=shown.kind,
        decl=shown.decl,
        members=shown.members,
        changed=True,
    )


def _enum_member_set(context: OperationContext, request: EnumMemberSetRequest) -> EnumMutationResult:
    runtime = context.runtime
    tif = _enum_type(runtime, request.enum_name)
    ida_typeinf = runtime.mod("ida_typeinf")
    mask = ida_typeinf.DEFMASK64 if request.mask is None else request.mask
    idx, _edm = tif.get_edm(request.member_name)
    if idx >= 0:
        _ensure_terr_ok(runtime, tif.edit_edm(idx, request.value, mask), "failed to edit enum member")
    else:
        _ensure_terr_ok(runtime, tif.add_edm(request.member_name, request.value, mask), "failed to add enum member")
    return _persist_and_show_enum(runtime, tif, name=request.enum_name)


def op_enum_member_set(runtime: IdaRuntime, params: dict[str, Any]) -> EnumMutationResult:
    return _enum_member_set(OperationContext(runtime=runtime), _parse_enum_member_set(params))


def _enum_member_rename(context: OperationContext, request: EnumMemberRenameRequest) -> EnumMutationResult:
    runtime = context.runtime
    tif = _enum_type(runtime, request.enum_name)
    idx = _enum_member_index(tif, request.enum_name, request.member_name)
    _ensure_terr_ok(runtime, tif.rename_edm(idx, request.new_name), "failed to rename enum member")
    return _persist_and_show_enum(runtime, tif, name=request.enum_name)


def op_enum_member_rename(runtime: IdaRuntime, params: dict[str, Any]) -> EnumMutationResult:
    return _enum_member_rename(OperationContext(runtime=runtime), _parse_enum_member_rename(params))


def _enum_member_delete(context: OperationContext, request: EnumMemberDeleteRequest) -> EnumMutationResult:
    runtime = context.runtime
    tif = _enum_type(runtime, request.enum_name)
    _ensure_terr_ok(runtime, tif.del_edm(request.member_name), "failed to delete enum member")
    return _persist_and_show_enum(runtime, tif, name=request.enum_name)


def op_enum_member_delete(runtime: IdaRuntime, params: dict[str, Any]) -> EnumMutationResult:
    return _enum_member_delete(OperationContext(runtime=runtime), _parse_enum_member_delete(params))


def _enum_view_for_set(context: OperationContext, request: EnumMemberSetRequest) -> EnumView:
    return _enum_view(context, NamedTypeShowRequest(name=request.enum_name))


def _enum_view_for_rename(context: OperationContext, request: EnumMemberRenameRequest) -> EnumView:
    return _enum_view(context, NamedTypeShowRequest(name=request.enum_name))


def _enum_view_for_delete(context: OperationContext, request: EnumMemberDeleteRequest) -> EnumView:
    return _enum_view(context, NamedTypeShowRequest(name=request.enum_name))


def named_type_operations() -> tuple[OperationSpec[object, object], ...]:
    return (
        OperationSpec(name="type_list", parse=_parse_list, run=_type_list),
        OperationSpec(name="type_show", parse=_parse_show, run=_type_show),
        OperationSpec(name="struct_list", parse=_parse_list, run=_struct_list),
        OperationSpec(name="struct_show", parse=_parse_struct_show, run=_struct_view),
        OperationSpec(
            name="struct_field_set",
            parse=_parse_struct_field_set,
            run=_struct_field_set,
            mutating=True,
            preview=PreviewSpec(
                capture_before=_struct_view_for_set,
                capture_after=_struct_view_for_set,
                use_undo=True,
            ),
        ),
        OperationSpec(
            name="struct_field_rename",
            parse=_parse_struct_field_rename,
            run=_struct_field_rename,
            mutating=True,
            preview=PreviewSpec(
                capture_before=_struct_view_for_rename,
                capture_after=_struct_view_for_rename,
                use_undo=True,
            ),
        ),
        OperationSpec(
            name="struct_field_delete",
            parse=_parse_struct_field_delete,
            run=_struct_field_delete,
            mutating=True,
            preview=PreviewSpec(
                capture_before=_struct_view_for_delete,
                capture_after=_struct_view_for_delete,
                use_undo=True,
            ),
        ),
        OperationSpec(name="enum_list", parse=_parse_list, run=_enum_list),
        OperationSpec(name="enum_show", parse=_parse_enum_show, run=_enum_view),
        OperationSpec(
            name="enum_member_set",
            parse=_parse_enum_member_set,
            run=_enum_member_set,
            mutating=True,
            preview=PreviewSpec(
                capture_before=_enum_view_for_set,
                capture_after=_enum_view_for_set,
                use_undo=True,
            ),
        ),
        OperationSpec(
            name="enum_member_rename",
            parse=_parse_enum_member_rename,
            run=_enum_member_rename,
            mutating=True,
            preview=PreviewSpec(
                capture_before=_enum_view_for_rename,
                capture_after=_enum_view_for_rename,
                use_undo=True,
            ),
        ),
        OperationSpec(
            name="enum_member_delete",
            parse=_parse_enum_member_delete,
            run=_enum_member_delete,
            mutating=True,
            preview=PreviewSpec(
                capture_before=_enum_view_for_delete,
                capture_after=_enum_view_for_delete,
                use_undo=True,
            ),
        ),
    )


__all__ = [
    "EnumMember",
    "EnumMemberDeleteRequest",
    "EnumMemberRenameRequest",
    "EnumMemberSetRequest",
    "EnumMutationResult",
    "EnumTypeView",
    "EnumView",
    "NamedTypeEntry",
    "NamedTypeListRequest",
    "NamedTypeShowRequest",
    "NamedTypeView",
    "StructFieldDeleteRequest",
    "StructFieldRenameRequest",
    "StructFieldSetRequest",
    "StructMember",
    "StructMutationResult",
    "StructView",
    "StructuredTypeView",
    "_parse_member_type",
    "named_type_operations",
    "op_enum_list",
    "op_enum_member_delete",
    "op_enum_member_rename",
    "op_enum_member_set",
    "op_enum_show",
    "op_struct_field_delete",
    "op_struct_field_rename",
    "op_struct_field_set",
    "op_struct_list",
    "op_struct_show",
    "op_type_list",
    "op_type_show",
]
