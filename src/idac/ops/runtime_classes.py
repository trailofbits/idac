from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .helpers.matching import text_matches
from .symbols import is_vtable_symbol_name

if TYPE_CHECKING:
    from .runtime import IdaRuntime


def looks_like_vtable_type(runtime: IdaRuntime, tif) -> bool:
    try:
        if tif.is_vftable():
            return True
    except Exception as exc:
        if not runtime.is_recoverable_error(exc):
            raise
    name = tif.get_type_name() or ""
    if name.endswith("_vtbl"):
        return True
    decl = runtime.tinfo_decl(tif, name=name or None, multi=False)
    return decl.lstrip().startswith("struct /*VFT*/")


def is_class_tinfo(runtime: IdaRuntime, tif) -> bool:
    if not tif.is_struct() or runtime._looks_like_vtable_type(tif):
        return False
    try:
        if tif.has_vftable():
            return True
    except Exception as exc:
        if not runtime.is_recoverable_error(exc):
            raise
    try:
        if tif.is_cpp_struct():
            return True
    except Exception as exc:
        if not runtime.is_recoverable_error(exc):
            raise
    decl = runtime.tinfo_decl(tif, name=tif.get_type_name() or None, multi=False)
    if "__cppobj" in decl:
        return True
    for member in runtime.udt_members(tif):
        member_name = runtime.member_name(member)
        if runtime.member_has(member, "is_baseclass") or runtime.member_has(member, "is_vftable"):
            return True
        if member_name.startswith("_vptr$") or member_name == "__vftable":
            return True
    class_name = tif.get_type_name() or ""
    return bool(class_name and runtime.find_named_type(f"{class_name}_vtbl"))


def class_base_names(runtime: IdaRuntime, tif) -> list[str]:
    bases: list[str] = []
    for member in runtime.udt_members(tif):
        if not runtime.member_has(member, "is_baseclass"):
            continue
        base_name = member.type.get_type_name() or member.type.dstr() or runtime.tinfo_decl(member.type, multi=False)
        if base_name:
            bases.append(base_name)
    return bases


def _class_vtable_member_type_name(runtime: IdaRuntime, tif) -> str | None:
    for member in runtime.udt_members(tif):
        member_name = runtime.member_name(member)
        if not (
            runtime.member_has(member, "is_vftable") or member_name.startswith("_vptr$") or member_name == "__vftable"
        ):
            continue
        name = runtime._member_pointed_name(member)
        if name:
            return name
    return None


def class_vtable_type_name(runtime: IdaRuntime, tif) -> str | None:
    class_name = tif.get_type_name() or ""
    if vtable_name := _class_vtable_member_type_name(runtime, tif):
        return vtable_name
    guessed = f"{class_name}_vtbl" if class_name else ""
    if guessed and runtime.find_named_type(guessed):
        return guessed
    for base_name in runtime.class_base_names(tif):
        base_tif = runtime.find_named_type(base_name)
        if base_tif is None:
            continue
        if vtable_name := runtime.class_vtable_type_name(base_tif):
            return vtable_name
    return None


def vtable_ea(runtime: IdaRuntime, tif) -> int | None:
    ida_typeinf = runtime.mod("ida_typeinf")
    idaapi = runtime.mod("idaapi")

    seen: set[int] = set()
    for ordinal in (tif.get_ordinal(), tif.get_final_ordinal()):
        if ordinal <= 0 or ordinal in seen:
            continue
        seen.add(ordinal)
        try:
            ea = ida_typeinf.get_vftable_ea(ordinal)
        except Exception as exc:
            if not runtime.is_recoverable_error(exc):
                raise
            continue
        if ea not in (0, idaapi.BADADDR):
            return ea
    return None


def class_vtable_ea(runtime: IdaRuntime, tif) -> int | None:
    direct = runtime.vtable_ea(tif)
    if direct is not None:
        return direct
    vtable_name = runtime.class_vtable_type_name(tif)
    if not vtable_name:
        return None
    vtable_tif = runtime.find_named_type(vtable_name)
    if vtable_tif is None:
        return None
    return runtime.vtable_ea(vtable_tif)


def class_runtime_vtable_identifier(runtime: IdaRuntime, tif, *, name: str | None = None) -> str | None:
    if (table_ea := runtime.class_vtable_ea(tif)) is not None:
        return hex(table_ea)
    class_name = name or tif.get_type_name() or ""
    if not class_name:
        return None
    symbol = runtime.find_vtable_symbol(class_name)
    return None if symbol is None else str(symbol["address"])


def class_summary(
    runtime: IdaRuntime,
    tif,
    *,
    name: str | None = None,
    decl_multi: bool = False,
) -> dict[str, Any]:
    display_name = name or tif.get_type_name() or ""
    return {
        "name": display_name,
        "kind": "class",
        "size": tif.get_size(),
        "bases": runtime.class_base_names(tif),
        "vtable_type": runtime.class_vtable_type_name(tif),
        "decl": runtime.tinfo_decl(tif, name=display_name or None, multi=decl_multi),
    }


def _class_matches_pattern(row: dict[str, Any], pattern: str, *, glob: bool, regex: bool, ignore_case: bool) -> bool:
    haystack = "\n".join(
        part
        for part in (
            str(row["name"]),
            str(row["decl"]),
            " ".join(str(base) for base in row["bases"]),
            str(row["vtable_type"] or ""),
        )
        if part
    )
    return text_matches(haystack, pattern=pattern, glob=glob, regex=regex, ignore_case=ignore_case)


def list_named_classes(
    runtime: IdaRuntime,
    *,
    query: str | None = None,
    pattern: str | None = None,
    glob: bool = False,
    regex: bool = False,
    ignore_case: bool = False,
) -> list[dict[str, Any]]:
    pattern_text = str(pattern if pattern is not None else query or "")
    rows: list[dict[str, Any]] = []
    for tif in runtime.iter_named_types():
        if not runtime.is_class_tinfo(tif):
            continue
        row = runtime.class_summary(tif, decl_multi=False)
        if pattern_text and not _class_matches_pattern(
            row,
            pattern_text,
            glob=glob,
            regex=regex,
            ignore_case=ignore_case or query is not None,
        ):
            continue
        rows.append(row)
    rows.sort(key=lambda item: item["name"].lower())
    return rows


def _candidate_class_names(class_name: str) -> set[str]:
    candidates = {class_name}
    if "__" in class_name:
        candidates.add(class_name.replace("__", "::"))
    if "::" in class_name:
        candidates.add(class_name.replace("::", "__"))
    return {item for item in candidates if item}


def _demangled_text_contains_class_name(text: str, class_name: str) -> bool:
    exact_pattern = rf"(?<![A-Za-z0-9_:]){re.escape(class_name)}(?![A-Za-z0-9_:])"
    if re.search(exact_pattern, text) is not None:
        return True
    msvc_vftable_pattern = rf"(?<![A-Za-z0-9_:]){re.escape(class_name)}(?=::`vftable')"
    return re.search(msvc_vftable_pattern, text) is not None


def find_vtable_symbol(runtime: IdaRuntime, class_name: str) -> dict[str, Any] | None:
    targets = _candidate_class_names(class_name)
    for ea, name, demangled in runtime.iter_names():
        if not is_vtable_symbol_name(name):
            continue
        demangled_text = demangled or ""
        if any(_demangled_text_contains_class_name(demangled_text, target) for target in targets):
            return {
                "address": hex(ea),
                "name": name,
                "demangled": demangled,
            }
    return None
