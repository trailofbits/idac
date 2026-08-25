"""Self-contained IDA-side operations executed through ida-nexus.

This module is uploaded as one content-addressed RemoteModule source file.
It must not import the local idac package: an IDA process is not expected to
have idac installed. Request-specific state belongs to dispatch() and its
IdaRuntime instance; module globals contain immutable operation definitions.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import re
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from types import MappingProxyType
from typing import Any, Generic, Literal, TypedDict, TypeVar, cast

# ---- Matching ----


def pattern_from_params(params: Mapping[str, Any]) -> tuple[str, bool, bool]:
    pattern = str(params.get("pattern") or "")
    return (pattern, bool(params.get("regex")), bool(params.get("ignore_case")))


def text_matches(text: str, *, pattern: str, regex: bool = False, ignore_case: bool = False) -> bool:
    if not pattern:
        return True
    haystack = text
    needle = pattern
    if regex:
        flags = re.IGNORECASE if ignore_case else 0
        try:
            return re.search(needle, haystack, flags=flags) is not None
        except re.error as exc:
            raise ValueError(f"invalid regex pattern: {pattern}") from exc
    if ignore_case:
        haystack = haystack.lower()
        needle = needle.lower()
    return needle in haystack


# ---- Symbol classification ----


VTABLE_SYMBOL_PREFIXES = ("__ZTV", "_ZTV", "??_7")
RTTI_TYPEINFO_PREFIXES = ("__ZTI", "_ZTI")
RTTI_NAME_PREFIXES = ("__ZTS", "_ZTS")
RTTI_SYMBOL_PREFIXES = RTTI_TYPEINFO_PREFIXES + RTTI_NAME_PREFIXES


def is_vtable_symbol_name(name: str) -> bool:
    return (name or "").startswith(VTABLE_SYMBOL_PREFIXES)


def classify_symbol_kind(name: str, *, is_function: bool) -> str:
    if is_vtable_symbol_name(name):
        return "vtable_symbol"
    if (name or "").startswith(RTTI_TYPEINFO_PREFIXES):
        return "typeinfo_symbol"
    if (name or "").startswith(RTTI_NAME_PREFIXES):
        return "typeinfo_name_symbol"
    if is_function:
        return "function_symbol"
    return "symbol"


# ---- Class recognition ----


def _class_vtable_member_type_name(runtime: IdaRuntime, tif) -> str | None:
    for member in runtime.udt_members(tif):
        member_name = member.name or ""
        if not (member.is_vftable() or member_name.startswith("_vptr$") or member_name == "__vftable"):
            continue
        name = runtime._member_pointed_name(member)
        if name:
            return name
    return None


def _class_matches_pattern(row: dict[str, Any], pattern: str, *, regex: bool, ignore_case: bool) -> bool:
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
    return text_matches(haystack, pattern=pattern, regex=regex, ignore_case=ignore_case)


def _candidate_class_names(class_name: str) -> set[str]:
    candidates = {class_name}
    if "__" in class_name:
        candidates.add(class_name.replace("__", "::"))
    if "::" in class_name:
        candidates.add(class_name.replace("::", "__"))
    return {item for item in candidates if item}


def _demangled_text_contains_class_name(text: str, class_name: str) -> bool:
    exact_pattern = f"(?<![A-Za-z0-9_:]){re.escape(class_name)}(?![A-Za-z0-9_:])"
    if re.search(exact_pattern, text) is not None:
        return True
    msvc_vftable_pattern = f"(?<![A-Za-z0-9_:]){re.escape(class_name)}(?=::`vftable')"
    return re.search(msvc_vftable_pattern, text) is not None


# ---- IDA runtime facade ----


class IdaOperationError(RuntimeError):
    """Raised for expected user-facing IDA lookup and operation failures."""


@dataclass(frozen=True)
class XrefRecord:
    from_ea: int
    to_ea: int
    type: str
    kind: str
    user: bool


@dataclass(frozen=True)
class SegmentRange:
    name: str
    start_ea: int
    end_ea: int


RECOVERABLE_IDA_ERRORS = (AttributeError, RuntimeError, OSError)
_CACHED_IDA_MODULE_ATTRS = frozenset(
    {
        "idaapi",
        "idautils",
        "ida_bytes",
        "ida_frame",
        "ida_funcs",
        "ida_ida",
        "ida_idp",
        "ida_kernwin",
        "ida_name",
        "ida_nalt",
        "ida_range",
        "ida_segment",
        "ida_strlist",
        "ida_typeinf",
        "ida_ua",
        "ida_xref",
    }
)


def is_recoverable_ida_error(exc: BaseException) -> bool:
    """Return whether an IDA exception should degrade gracefully."""
    return isinstance(exc, RECOVERABLE_IDA_ERRORS) and (not isinstance(exc, IdaOperationError))


@contextlib.contextmanager
def suppress_recoverable_ida_errors():
    """Suppress IDA API errors that are safe to treat as missing metadata."""
    try:
        yield
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise


@contextlib.contextmanager
def ida_undo_restore_point(
    runtime: IdaRuntime,
    *,
    action_name: str,
    label: str,
    unavailable_message: str,
    restore_error_message: str,
    restore_failure_message: str | None = None,
):
    """Create an IDA undo point and always restore it on exit."""
    ida_undo = runtime.mod("ida_undo")
    if not ida_undo.create_undo_point(action_name=action_name, label=label):
        raise IdaOperationError(unavailable_message)
    try:
        yield
    except BaseException as exc:
        if not ida_undo.perform_undo():
            raise IdaOperationError(restore_failure_message or restore_error_message) from exc
        raise
    else:
        if not ida_undo.perform_undo():
            raise IdaOperationError(restore_error_message)


class IdaRuntime:
    """Small facade over imported IDA modules plus convenience helpers."""

    def __init__(self) -> None:
        self._module_cache: dict[str, Any] = {}

    def __getattr__(self, name: str):
        """Resolve selected IDA modules as cached runtime attributes."""
        if name not in _CACHED_IDA_MODULE_ATTRS:
            raise AttributeError(f"{type(self).__name__!s} has no attribute {name!r}")
        module = self.mod(name)
        self._module_cache.setdefault(name, module)
        setattr(self, name, module)
        return module

    def mod(self, name: str):
        """Import an IDA module by name."""
        cached = self._module_cache.get(name)
        if cached is not None:
            return cached
        module = importlib.import_module(name)
        self._module_cache[name] = module
        return module

    def udt_members(self, tif):
        """Return UDT members for ``tif`` or an empty iterable when unavailable."""
        udt = self.ida_typeinf.udt_type_data_t()
        return udt if tif.get_udt_details(udt) else ()

    def _member_pointed_name(self, member) -> str | None:
        pointed = member.type.get_pointed_object()
        if pointed is None:
            return None
        name = pointed.get_type_name() or self.tinfo_decl(pointed, multi=False)
        if name == "<unknown>":
            return None
        return name or None

    def resolve_address(self, identifier: str) -> int:
        """Resolve a user-supplied address or symbol to an effective address."""
        text = str(identifier).strip()
        if not text:
            raise IdaOperationError("address or identifier is required")
        ea = self.ida_kernwin.str2ea_ex(text, self.idaapi.BADADDR, self.ida_kernwin.S2EAOPT_NOCALC)
        if ea not in (None, self.idaapi.BADADDR):
            return ea
        raise IdaOperationError(f"symbol not found: {identifier}")

    @staticmethod
    def _lookup_text_variants(text: str) -> list[str]:
        rendered = str(text or "").strip()
        if not rendered:
            return []
        variants = [rendered]
        if "(" in rendered:
            short_name = rendered.split("(", 1)[0].strip()
            if short_name and short_name != rendered:
                variants.append(short_name)
        return variants

    def _demangled_lookup_texts(self, ea: int) -> list[str]:
        texts: list[str] = []
        short_flags = self.ida_name.GN_VISIBLE | self.ida_name.GN_DEMANGLED | self.ida_name.GN_SHORT
        long_flags = self.ida_name.GN_VISIBLE | self.ida_name.GN_DEMANGLED | self.ida_name.GN_LONG
        with suppress_recoverable_ida_errors():
            texts.extend(self._lookup_text_variants(self.ida_name.get_ea_name(ea, short_flags) or ""))
        with suppress_recoverable_ida_errors():
            texts.extend(self._lookup_text_variants(self.ida_name.get_ea_name(ea, long_flags) or ""))
        raw_name = ""
        with suppress_recoverable_ida_errors():
            raw_name = str(self.ida_name.get_name(ea) or "").strip()
        demangled_name = self.demangle_name(raw_name)
        texts.extend(self._lookup_text_variants(demangled_name or ""))
        return texts

    def _resolve_demangled_function_address(self, identifier: str) -> int | None:
        if not any(marker in str(identifier).strip() for marker in ("::", "(", "~", "operator")):
            return None
        query = str(identifier).strip()
        match_ea: int | None = None
        for ea in self.idautils.Functions():
            if query not in self._demangled_lookup_texts(ea):
                continue
            if match_ea is None:
                match_ea = ea
                continue
            if ea != match_ea:
                raise IdaOperationError(
                    f"multiple functions matched demangled name: {identifier}; "
                    "use a mangled name, full signature, or address"
                )
        return match_ea

    def resolve_function(self, identifier: str):
        """Resolve a function identifier and require that it names a function."""
        address_error: IdaOperationError | None = None
        try:
            ea = self.resolve_address(identifier)
        except IdaOperationError as exc:
            address_error = exc
            ea = None
        func = None if ea is None else self.ida_funcs.get_func(ea)
        if func is not None:
            return func
        demangled_ea = self._resolve_demangled_function_address(str(identifier))
        func = None if demangled_ea is None else self.ida_funcs.get_func(demangled_ea)
        if func is not None:
            return func
        if address_error is not None:
            raise address_error
        raise IdaOperationError(f"function not found: {identifier}")

    def function_name(self, ea: int) -> str:
        return self.ida_funcs.get_func_name(ea) or hex(ea)

    def display_function_name(self, ea: int, *, demangle: bool = False) -> str:
        name = self.function_name(ea)
        if not demangle:
            return name
        flags = self.ida_name.GN_VISIBLE | self.ida_name.GN_DEMANGLED | self.ida_name.GN_SHORT
        return self.ida_name.get_short_name(ea, flags) or name

    def function_identity(self, func) -> tuple[str, str]:
        ea = int(func.start_ea)
        return (self.function_name(ea), hex(ea))

    def function_ea(self, identifier: str) -> int:
        return self.resolve_function(identifier).start_ea

    def database_bounds(self) -> tuple[int, int]:
        return (self.ida_ida.inf_get_min_ea(), self.ida_ida.inf_get_max_ea())

    def iter_segments(self) -> tuple[SegmentRange, ...]:
        ida_segment = self.ida_segment
        rows: list[SegmentRange] = []
        segment_ea = ida_segment.get_first_segment_ea()
        while segment_ea != self.idaapi.BADADDR:
            info = ida_segment.segment_info_t()
            if not ida_segment.get_segment_info(info, segment_ea):
                raise IdaOperationError(f"failed to read segment information at {hex(segment_ea)}")
            start_ea = int(info.start_ea)
            end_ea = int(info.end_ea)
            name = ida_segment.get_segment_name(segment_ea, self.ida_name.GN_VISIBLE)
            rows.append(SegmentRange(name=name, start_ea=start_ea, end_ea=end_ea))
            next_ea = ida_segment.get_next_segment_ea(segment_ea)
            if next_ea == self.idaapi.BADADDR:
                break
            if next_ea <= segment_ea:
                raise IdaOperationError("segment enumeration did not advance")
            segment_ea = next_ea
        return tuple(rows)

    @staticmethod
    def _segment_selector_matches(name: str, selector: str) -> bool:
        normalized_name = str(name).strip()
        normalized_selector = str(selector).strip()
        if not normalized_name or not normalized_selector:
            return False
        if normalized_name == normalized_selector:
            return True
        if ":" not in normalized_selector and normalized_name.startswith(f"{normalized_selector}:"):
            return True
        if ":" in normalized_name:
            _prefix, suffix = normalized_name.split(":", 1)
            if normalized_selector == suffix:
                return True
        return False

    @staticmethod
    def ea_in_ranges(ea: int, ranges: tuple[SegmentRange, ...]) -> bool:
        return any(item.start_ea <= ea < item.end_ea for item in ranges)

    @staticmethod
    def _validate_range_endpoint(*, label: str, value: int | None, bounds_start: int, bounds_end: int) -> None:
        if value is None or bounds_start <= value <= bounds_end:
            return
        raise IdaOperationError(
            f"range {label} {hex(value)} is outside database bounds {hex(bounds_start)}-{hex(bounds_end)}"
        )

    def resolve_segment_ranges(
        self,
        selector: str,
        *,
        start: str | None = None,
        end: str | None = None,
        require_bounds: bool = False,
        missing_message: str = "range requires both start and end addresses",
    ) -> tuple[SegmentRange, ...]:
        selector_text = str(selector).strip()
        if not selector_text:
            raise IdaOperationError("segment selector is required")
        all_segments = self.iter_segments()
        segments = tuple(item for item in all_segments if self._segment_selector_matches(item.name, selector_text))
        if not segments:
            prefixes = sorted({item.name.split(":", 1)[0] for item in all_segments})
            detail = ""
            if prefixes:
                shown = ", ".join(prefixes[:10])
                if len(prefixes) > 10:
                    shown += ", ..."
                detail = f"; available segments: {shown}"
            raise IdaOperationError(f"segment not found: {selector_text}{detail}")
        range_start, range_end = self.resolve_range(
            start=start,
            end=end,
            require_bounds=require_bounds,
            missing_message=missing_message,
        )
        clipped = tuple(
            SegmentRange(name=item.name, start_ea=max(item.start_ea, range_start), end_ea=min(item.end_ea, range_end))
            for item in segments
            if min(item.end_ea, range_end) > max(item.start_ea, range_start)
        )
        if not clipped:
            raise IdaOperationError(f"range does not overlap segment: {selector_text}")
        return clipped

    def _normalize_xref(self, xref) -> XrefRecord:
        type_code = int(xref.type)
        type_name, kind = {
            self.ida_xref.fl_U: ("Data_Unknown", "unknown"),
            self.ida_xref.dr_O: ("Data_Offset", "offset"),
            self.ida_xref.dr_W: ("Data_Write", "write"),
            self.ida_xref.dr_R: ("Data_Read", "read"),
            self.ida_xref.dr_T: ("Data_Text", "text"),
            self.ida_xref.dr_I: ("Data_Informational", "informational"),
            self.ida_xref.fl_CF: ("Code_Far_Call", "call"),
            self.ida_xref.fl_CN: ("Code_Near_Call", "call"),
            self.ida_xref.fl_JF: ("Code_Far_Jump", "jump"),
            self.ida_xref.fl_JN: ("Code_Near_Jump", "jump"),
            self.ida_xref.fl_F: ("Ordinary_Flow", "flow"),
        }.get(type_code, (f"xref_{type_code}", "code" if bool(xref.iscode) else "data"))
        return XrefRecord(
            from_ea=int(xref.frm),
            to_ea=int(xref.to),
            type=type_name,
            kind=kind,
            user=bool(xref.user),
        )

    def xrefs_to(self, ea: int, *, flags: int | None = None) -> tuple[XrefRecord, ...]:
        block = self.ida_xref.xrefblk_t()
        resolved_flags = self.ida_xref.XREF_FLOW if flags is None else flags
        return tuple(self._normalize_xref(xref) for xref in block.refs_to(ea, resolved_flags))

    def xrefs_from(self, ea: int, *, flags: int | None = None) -> tuple[XrefRecord, ...]:
        block = self.ida_xref.xrefblk_t()
        resolved_flags = self.ida_xref.XREF_FLOW if flags is None else flags
        return tuple(self._normalize_xref(xref) for xref in block.refs_from(ea, resolved_flags))

    def resolve_range(
        self,
        *,
        start: str | None = None,
        end: str | None = None,
        require_bounds: bool = False,
        missing_message: str = "range requires both start and end addresses",
    ) -> tuple[int, int]:
        bounds_start, bounds_end = self.database_bounds()
        range_start, range_end = (bounds_start, bounds_end)
        if require_bounds and (start is None or end is None):
            raise IdaOperationError(missing_message)
        if start is not None:
            range_start = self.resolve_address(start)
        if end is not None:
            range_end = self.resolve_address(end)
        self._validate_range_endpoint(
            label="start",
            value=range_start if start is not None else None,
            bounds_start=bounds_start,
            bounds_end=bounds_end,
        )
        self._validate_range_endpoint(
            label="end", value=range_end if end is not None else None, bounds_start=bounds_start, bounds_end=bounds_end
        )
        if range_end <= range_start:
            raise IdaOperationError("range end must be greater than the start")
        return (range_start, range_end)

    def compile_binpat(self, pattern: str, *, ea: int | None = None, radix: int = 16, strlit_encoding: int = -1):
        """Compile an IDA byte-pattern string without going through ``find_bytes``."""
        text = str(pattern or "").strip()
        if not text:
            raise IdaOperationError("byte pattern is required")
        compile_ea = self.database_bounds()[0] if ea is None else ea
        try:
            compiled = self.ida_bytes.compiled_binpat_vec_t.parse(compile_ea, text, radix, strlit_encoding)
        except Exception as exc:
            detail = str(exc).strip() or "unknown error"
            prefix = "Could not parse pattern: "
            if detail.startswith(prefix):
                detail = detail[len(prefix) :].strip() or "unknown error"
            raise IdaOperationError(f"invalid byte pattern: {detail}") from exc
        if len(compiled) == 0:
            raise IdaOperationError("invalid byte pattern")
        return compiled

    def require_hexrays(self):
        """Require a working Hex-Rays decompiler session."""
        ida_hexrays = self.mod("ida_hexrays")
        if not ida_hexrays.init_hexrays_plugin():
            raise IdaOperationError("Hex-Rays decompiler is unavailable")
        return ida_hexrays

    def get_named_type(self, name: str, *, kind: str | None = None):
        """Resolve a named type, optionally constraining the expected kind."""
        tif = self.ida_typeinf.tinfo_t()
        kind_code = {
            "struct": self.ida_typeinf.BTF_STRUCT,
            "union": self.ida_typeinf.BTF_UNION,
            "enum": self.ida_typeinf.BTF_ENUM,
        }.get(kind or "")
        if kind_code is None:
            ok = tif.get_named_type(None, name)
        else:
            ok = tif.get_named_type(self.ida_typeinf.get_idati(), name, kind_code, True, False)
        if not ok:
            raise IdaOperationError(f"type not found: {name}")
        return tif

    def find_named_type(self, name: str, *, kind: str | None = None):
        """Best-effort named type lookup that returns ``None`` on failure."""
        try:
            return self.get_named_type(name, kind=kind)
        except IdaOperationError:
            return None

    def get_struct_or_union(self, name: str):
        """Resolve a struct first, then fall back to a union of the same name."""
        tif = self.find_named_type(name, kind="struct")
        return tif if tif is not None else self.get_named_type(name, kind="union")

    def classify_tinfo(self, tif) -> str:
        """Classify a ``tinfo_t`` into the coarse kinds used by the CLI."""
        if tif.is_struct():
            return "struct"
        if tif.is_union():
            return "union"
        if tif.is_enum():
            return "enum"
        if tif.is_func():
            return "function"
        if tif.is_typedef():
            return "typedef"
        if tif.is_ptr():
            return "pointer"
        if tif.is_array():
            return "array"
        return "type"

    def demangle_name(self, name: str) -> str | None:
        """Best-effort demangling that hides expected IDA failures."""
        text = (name or "").strip()
        if not text:
            return None
        try:
            if demangled := self.ida_name.demangle_name(text, 0):
                return demangled
        except Exception as exc:
            if not is_recoverable_ida_error(exc):
                raise
        return None

    def tinfo_decl(self, tif, *, name: str | None = None, multi: bool = True) -> str:
        """Render a stable declaration string for a ``tinfo_t``."""
        type_name = name or tif.get_type_name() or ""
        try:
            flags = self.ida_typeinf.PRTYPE_TYPE | self.ida_typeinf.PRTYPE_DEF
            flags |= self.ida_typeinf.PRTYPE_MULTI if multi else self.ida_typeinf.PRTYPE_1LINE
            text = tif._print(type_name, flags)
            if text:
                return text
        except Exception as exc:
            if not is_recoverable_ida_error(exc):
                raise
        with suppress_recoverable_ida_errors():
            text = tif.dstr()
            if text:
                return text
        return type_name or "<unknown>"

    def tinfo_members(self, tif) -> list[dict[str, Any]]:
        """Return a normalized list of UDT member metadata."""
        members: list[dict[str, Any]] = []
        for index, udm in enumerate(self.udt_members(tif)):
            size_bits = udm.size
            members.append(
                {
                    "index": index,
                    "name": udm.name,
                    "offset_bits": udm.offset,
                    "offset": udm.offset // 8,
                    "size_bits": size_bits,
                    "size": size_bits // 8 if size_bits else None,
                    "type": self.tinfo_decl(udm.type, multi=False),
                    "comment": udm.cmt or "",
                }
            )
        return members

    def enum_members(self, tif) -> list[dict[str, Any]]:
        """Return a normalized list of enum member metadata."""
        members: list[dict[str, Any]] = []
        for index, edm in enumerate(tif.iter_enum()):
            members.append(
                {
                    "index": index,
                    "name": edm.name,
                    "value": edm.value,
                    "value_hex": hex(edm.value),
                    "comment": edm.cmt or "",
                }
            )
        return members

    def list_named_types(
        self,
        *,
        pattern: str | None = None,
        regex: bool = False,
        ignore_case: bool = False,
        kinds: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List named local types, optionally filtered by substring and kind."""
        pattern_text = str(pattern or "")
        rows: list[dict[str, Any]] = []
        for tif in self.ida_typeinf.get_idati().named_types():
            name = tif.get_type_name() or ""
            kind = self.classify_tinfo(tif)
            if pattern_text and not text_matches(name, pattern=pattern_text, regex=regex, ignore_case=ignore_case):
                continue
            if kinds is not None and kind not in kinds:
                continue
            rows.append({"name": name, "kind": kind, "decl": self.tinfo_decl(tif, name=name, multi=False)})
        rows.sort(key=lambda item: (item["kind"], item["name"].lower()))
        return rows

    def _looks_like_vtable_type(self, tif) -> bool:
        try:
            if tif.is_vftable():
                return True
        except Exception as exc:
            if not is_recoverable_ida_error(exc):
                raise
        name = tif.get_type_name() or ""
        if name.endswith("_vtbl"):
            return True
        decl = self.tinfo_decl(tif, name=name or None, multi=False)
        return decl.lstrip().startswith("struct /*VFT*/")

    def is_class_tinfo(self, tif) -> bool:
        if not tif.is_struct() or self._looks_like_vtable_type(tif):
            return False
        with suppress_recoverable_ida_errors():
            if tif.has_vftable():
                return True
        with suppress_recoverable_ida_errors():
            if tif.is_cpp_struct():
                return True
        decl = self.tinfo_decl(tif, name=tif.get_type_name() or None, multi=False)
        if "__cppobj" in decl:
            return True
        for member in self.udt_members(tif):
            member_name = member.name or ""
            if member.is_baseclass() or member.is_vftable():
                return True
            if member_name.startswith("_vptr$") or member_name == "__vftable":
                return True
        class_name = tif.get_type_name() or ""
        return bool(class_name and self.find_named_type(f"{class_name}_vtbl"))

    def class_base_names(self, tif) -> list[str]:
        bases: list[str] = []
        for member in self.udt_members(tif):
            if not member.is_baseclass():
                continue
            base_name = member.type.get_type_name() or member.type.dstr() or self.tinfo_decl(member.type, multi=False)
            if base_name:
                bases.append(base_name)
        return bases

    def class_vtable_type_name(self, tif) -> str | None:
        class_name = tif.get_type_name() or ""
        if vtable_name := _class_vtable_member_type_name(self, tif):
            return vtable_name
        guessed = f"{class_name}_vtbl" if class_name else ""
        if guessed and self.find_named_type(guessed):
            return guessed
        for base_name in self.class_base_names(tif):
            base_tif = self.find_named_type(base_name)
            if base_tif is None:
                continue
            if vtable_name := self.class_vtable_type_name(base_tif):
                return vtable_name
        return None

    def vtable_ea(self, tif) -> int | None:
        ida_typeinf = self.mod("ida_typeinf")
        idaapi = self.mod("idaapi")
        seen: set[int] = set()
        for ordinal in (tif.get_ordinal(), tif.get_final_ordinal()):
            if ordinal <= 0 or ordinal in seen:
                continue
            seen.add(ordinal)
            try:
                ea = ida_typeinf.get_vftable_ea(ordinal)
            except Exception as exc:
                if not is_recoverable_ida_error(exc):
                    raise
                continue
            if ea not in (0, idaapi.BADADDR):
                return ea
        return None

    def class_vtable_ea(self, tif) -> int | None:
        direct = self.vtable_ea(tif)
        if direct is not None:
            return direct
        vtable_name = self.class_vtable_type_name(tif)
        if not vtable_name:
            return None
        vtable_tif = self.find_named_type(vtable_name)
        if vtable_tif is None:
            return None
        return self.vtable_ea(vtable_tif)

    def class_runtime_vtable_identifier(self, tif, *, name: str | None = None) -> str | None:
        if (table_ea := self.class_vtable_ea(tif)) is not None:
            return hex(table_ea)
        class_name = name or tif.get_type_name() or ""
        if not class_name:
            return None
        symbol = self.find_vtable_symbol(class_name)
        return None if symbol is None else str(symbol["address"])

    def class_summary(self, tif, *, name: str | None = None, decl_multi: bool = False) -> dict[str, Any]:
        display_name = name or tif.get_type_name() or ""
        return {
            "name": display_name,
            "kind": "class",
            "size": tif.get_size(),
            "bases": self.class_base_names(tif),
            "vtable_type": self.class_vtable_type_name(tif),
            "decl": self.tinfo_decl(tif, name=display_name or None, multi=decl_multi),
        }

    def list_named_classes(
        self,
        *,
        pattern: str | None = None,
        regex: bool = False,
        ignore_case: bool = False,
    ) -> list[dict[str, Any]]:
        pattern_text = str(pattern or "")
        rows: list[dict[str, Any]] = []
        for tif in self.ida_typeinf.get_idati().named_types():
            if not self.is_class_tinfo(tif):
                continue
            row = self.class_summary(tif, decl_multi=False)
            if pattern_text and (
                not _class_matches_pattern(
                    row,
                    pattern_text,
                    regex=regex,
                    ignore_case=ignore_case,
                )
            ):
                continue
            rows.append(row)
        rows.sort(key=lambda item: item["name"].lower())
        return rows

    def iter_names(self):
        for ea, name in self.idautils.Names():
            yield (ea, name, self.demangle_name(name))

    def find_symbols(
        self,
        *,
        pattern: str | None = None,
        regex: bool = False,
        ignore_case: bool = False,
    ) -> list[dict[str, Any]]:
        pattern_text = str(pattern or "")
        rows: list[dict[str, Any]] = []
        for ea, name, demangled in self.iter_names():
            haystack = "\n".join(part for part in (name, demangled or "") if part)
            if pattern_text and not text_matches(haystack, pattern=pattern_text, regex=regex, ignore_case=ignore_case):
                continue
            rows.append(
                {
                    "address": hex(ea),
                    "name": name,
                    "demangled": demangled,
                    "is_function": self.ida_funcs.get_func(ea) is not None,
                }
            )
        return rows

    def find_vtable_symbol(self, class_name: str) -> dict[str, Any] | None:
        targets = _candidate_class_names(class_name)
        for ea, name, demangled in self.iter_names():
            if not is_vtable_symbol_name(name):
                continue
            demangled_text = demangled or ""
            if any(_demangled_text_contains_class_name(demangled_text, target) for target in targets):
                return {"address": hex(ea), "name": name, "demangled": demangled}
        return None

    def pointer_size(self) -> int:
        if self.ida_ida.inf_is_64bit():
            return 8
        if self.ida_ida.inf_is_32bit_exactly():
            return 4
        return 2

    def read_pointer(self, ea: int) -> int:
        width = self.pointer_size()
        if width == 8:
            return self.ida_bytes.get_qword(ea)
        if width == 4:
            return self.ida_bytes.get_wide_dword(ea)
        return self.ida_bytes.get_wide_word(ea)

    def vtable_slot(self, offset_bits: int) -> int:
        return offset_bits // (self.pointer_size() * 8)

    def pseudocode_text(self, cfunc) -> str:
        """Render Hex-Rays pseudocode as plain text."""
        lines: list[str] = []
        for item in cfunc.get_pseudocode():
            lines.append(_strip_tags(self, item.line).rstrip())
        return "\n".join(lines)


def _strip_tags(runtime: IdaRuntime, text: Any) -> str:
    ida_lines = runtime.mod("ida_lines")
    return ida_lines.tag_remove(str(text or ""))


def _ea_text(runtime: IdaRuntime, ea: Any) -> str | None:
    idaapi = runtime.mod("idaapi")
    try:
        value = int(ea)
    except (TypeError, ValueError):
        return None
    if value == idaapi.BADADDR:
        return None
    return hex(value)


# ---- Parameter parsing ----


def parse_int_text(value: Any, *, label: str, minimum: int | None = None) -> int:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{label} is required")
    try:
        parsed = int(text, 0)
    except ValueError as exc:
        raise ValueError(f"{label} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{label} must be greater than or equal to {minimum}")
    return parsed


def param_int(params: Mapping[str, Any], key: str, *, label: str | None = None, minimum: int | None = None) -> int:
    name = key if label is None else label
    try:
        return parse_int_text(params.get(key), label=name, minimum=minimum)
    except ValueError as exc:
        raise IdaOperationError(str(exc)) from exc


def optional_param_int(
    params: Mapping[str, Any], key: str, *, label: str | None = None, minimum: int | None = None
) -> int | None:
    value = params.get(key)
    if value in (None, ""):
        return None
    return param_int(params, key, label=label, minimum=minimum)


def require_str(value: Any, *, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise IdaOperationError(f"{field} is required")
    return text


def optional_str(value: Any) -> str | None:
    return str(value or "").strip() or None


def parse_aliases(raw_aliases: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in raw_aliases or []:
        if isinstance(item, dict):
            src = str(item.get("from") or "").strip()
            dst = str(item.get("to") or "").strip()
            raw = f"{src}={dst}" if src or dst else ""
        else:
            raw = str(item).strip()
            src = dst = ""
            if "=" in raw:
                src, dst = (part.strip() for part in raw.split("=", 1))
        if not src or not dst:
            text = raw or str(item)
            raise ValueError(f"invalid alias `{text}`; expected OLD=NEW")
        rows.append({"from": src, "to": dst})
    return rows


# ---- Operation definitions ----


RequestT = TypeVar("RequestT")
ResultT = TypeVar("ResultT")
Params = Mapping[str, Any]
ParseParams = Callable[[Params], RequestT]
RunOperation = Callable[["OperationContext", RequestT], ResultT]


@dataclass(frozen=True)
class OperationContext:
    runtime: IdaRuntime
    preview: bool = False


@dataclass(frozen=True)
class OperationSpec(Generic[RequestT, ResultT]):
    name: str
    run: RunOperation[RequestT, ResultT]
    parse: ParseParams[RequestT] | None = None
    mutating: bool = False
    preview: PreviewSpec[RequestT, ResultT] | None = None


# ---- Preview execution ----


PreviewPrepare = Callable[[OperationContext, RequestT], RequestT]
PreviewCapture = Callable[[OperationContext, RequestT], Any]
PreviewRollback = Callable[[OperationContext, RequestT, Any], None]
PreviewCleanup = Callable[[OperationContext, RequestT], None]


@dataclass(frozen=True)
class PreviewOutcome(Generic[ResultT]):
    result: ResultT
    before: Any
    after: Any
    persisted: bool = False
    preview: bool = True
    preview_mode: str = "rollback"


@dataclass(frozen=True)
class PreviewSpec(Generic[RequestT, ResultT]):
    capture_before: PreviewCapture
    capture_after: PreviewCapture
    rollback: PreviewRollback[RequestT] | None = None
    prepare: PreviewPrepare[RequestT] | None = None
    cleanup: PreviewCleanup[RequestT] | None = None
    use_undo: bool = False


def run_preview(
    context: OperationContext,
    name: str,
    request: RequestT,
    runner: RunOperation[RequestT, ResultT],
    spec: PreviewSpec[RequestT, ResultT] | None,
) -> PreviewOutcome[ResultT]:
    if spec is None:
        raise IdaOperationError("preview is not supported for this operation")
    prepared = request if spec.prepare is None else spec.prepare(context, request)
    if spec.use_undo:
        cleanup_error: BaseException | None = None
        try:
            with ida_undo_restore_point(
                context.runtime,
                action_name=f"idac_preview_{name}",
                label=f"idac preview {name}",
                unavailable_message="preview is unavailable because IDA undo is disabled",
                restore_error_message=f"preview failed to restore changes via undo for {name}",
                restore_failure_message=f"preview failed and IDA could not restore changes via undo for {name}",
            ):
                before = spec.capture_before(context, prepared)
                result = runner(context, prepared)
                after = spec.capture_after(context, prepared)
        finally:
            if spec.cleanup is not None:
                try:
                    spec.cleanup(context, prepared)
                except BaseException as exc:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise cleanup_error
        return PreviewOutcome(result=result, before=before, after=after, preview_mode="undo")
    if spec.rollback is None:
        raise IdaOperationError(f"preview is not supported for this operation: {name}")
    result: Any = None
    after: Any = None
    runner_started = False
    primary_error: BaseException | None = None
    rollback_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        before = spec.capture_before(context, prepared)
        try:
            runner_started = True
            result = runner(context, prepared)
            after = spec.capture_after(context, prepared)
        except BaseException as exc:
            primary_error = exc
        finally:
            if runner_started:
                try:
                    spec.rollback(context, prepared, before)
                except BaseException as exc:
                    rollback_error = exc
    finally:
        if spec.cleanup is not None:
            try:
                spec.cleanup(context, prepared)
            except BaseException as exc:
                cleanup_error = exc
    if rollback_error is not None:
        if primary_error is not None:
            raise rollback_error from primary_error
        raise rollback_error
    if primary_error is not None:
        raise primary_error
    if cleanup_error is not None:
        raise cleanup_error
    return PreviewOutcome(result=result, before=before, after=after)


# ---- Shared wire models ----


JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


def payload_from_model(value: Any) -> JsonValue:
    if is_dataclass(value) and (not isinstance(value, type)):
        return {
            field.name[:-1] if field.name.endswith("_") else field.name: payload_from_model(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, (list, tuple)):
        return [payload_from_model(item) for item in value]
    if isinstance(value, dict):
        return {str(key): payload_from_model(item) for key, item in value.items()}
    return value


# ---- Database operations ----


@dataclass(frozen=True)
class _database_DatabaseInfoResult:
    path: str
    database_path: str
    module: str
    processor: str
    bits: int
    base: str
    min_ea: str
    max_ea: str
    main_ea: str | None
    start_ea: str | None
    entry_ea: str | None


def _database_database_info(context: OperationContext, request: None) -> _database_DatabaseInfoResult:
    del request
    runtime = context.runtime
    ida_entry = runtime.mod("ida_entry")
    ida_ida = runtime.mod("ida_ida")
    ida_loader = runtime.mod("ida_loader")
    ida_nalt = runtime.mod("ida_nalt")
    idaapi = runtime.mod("idaapi")
    entry_ord = ida_entry.get_entry_ordinal(0)
    entry_ea = ida_entry.get_entry(entry_ord) if entry_ord != idaapi.BADADDR else idaapi.BADADDR
    main_ea = ida_ida.inf_get_main()
    start_ea = ida_ida.inf_get_start_ea()
    return _database_DatabaseInfoResult(
        path=ida_nalt.get_input_file_path() or "",
        database_path=ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
        module=ida_nalt.get_root_filename() or "",
        processor=ida_ida.inf_get_procname(),
        bits=runtime.pointer_size() * 8,
        base=hex(ida_nalt.get_imagebase()),
        min_ea=hex(ida_ida.inf_get_min_ea()),
        max_ea=hex(ida_ida.inf_get_max_ea()),
        main_ea=None if main_ea == idaapi.BADADDR else hex(main_ea),
        start_ea=None if start_ea == idaapi.BADADDR else hex(start_ea),
        entry_ea=None if entry_ea == idaapi.BADADDR else hex(entry_ea),
    )


# ---- Segment operations ----


@dataclass(frozen=True)
class _segments_SegmentListRequest:
    pattern: str
    regex: bool
    ignore_case: bool


@dataclass(frozen=True)
class _segments_SegmentListEntry:
    name: str
    start: str
    end: str
    size: int


def _segments_parse_segment_list(params: Mapping[str, Any]) -> _segments_SegmentListRequest:
    pattern, regex, ignore_case = pattern_from_params(params)
    if regex and pattern:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise IdaOperationError(f"invalid segment regex: {exc}") from exc
    return _segments_SegmentListRequest(pattern=pattern, regex=regex, ignore_case=ignore_case)


def _segments_segment_list(
    context: OperationContext, request: _segments_SegmentListRequest
) -> tuple[_segments_SegmentListEntry, ...]:
    rows: list[_segments_SegmentListEntry] = []
    for segment in context.runtime.iter_segments():
        if request.pattern and (
            not text_matches(
                segment.name,
                pattern=request.pattern,
                regex=request.regex,
                ignore_case=request.ignore_case,
            )
        ):
            continue
        rows.append(
            _segments_SegmentListEntry(
                name=segment.name,
                start=hex(segment.start_ea),
                end=hex(segment.end_ea),
                size=segment.end_ea - segment.start_ea,
            )
        )
    return tuple(rows)


# ---- Function operations ----


@dataclass(frozen=True)
class _functions_FunctionListRequest:
    pattern: str
    regex: bool
    ignore_case: bool
    segment: str | None
    limit: int | None
    demangle: bool


@dataclass(frozen=True)
class _functions_FunctionIdentifierRequest:
    identifier: str


@dataclass(frozen=True)
class _functions_DisasmRangeRequest:
    start: str
    end: str


@dataclass(frozen=True)
class _functions_DecompileRequest:
    identifier: str
    no_cache: bool


@dataclass(frozen=True)
class _functions_CtreeRequest:
    identifier: str
    level: str
    maturity: str


@dataclass(frozen=True)
class _functions_FunctionListEntry:
    name: str
    display_name: str
    render_name: str
    address: str
    section: str
    size: int


@dataclass(frozen=True)
class _functions_FunctionShowResult:
    name: str
    display_name: str
    address: str
    size: int
    prototype: str
    flags: str


@dataclass(frozen=True)
class _functions_FrameXref:
    address: str
    operand: int
    type: int
    access: str


@dataclass(frozen=True)
class _functions_FrameMember:
    index: int
    name: str
    offset: int
    end_offset: int
    size: int
    type: str
    kind: str
    is_special: bool
    is_arg: bool
    fp_offset: int | None = None
    xrefs: tuple[_functions_FrameXref, ...] = ()
    xref_count: int | None = None


@dataclass(frozen=True)
class _functions_FunctionFrameResult:
    function: str
    address: str
    frame_size: int
    local_size: int
    saved_registers_size: int
    argument_size: int
    members: tuple[_functions_FrameMember, ...]


@dataclass(frozen=True)
class _functions_FunctionStackvarsResult:
    function: str
    address: str
    stackvars: tuple[_functions_FrameMember, ...]


@dataclass(frozen=True)
class _functions_CallerEdge:
    call_site: str
    caller: str
    caller_address: str


@dataclass(frozen=True)
class _functions_CalleeEdge:
    call_site: str
    callee: str
    callee_address: str


@dataclass(frozen=True)
class _functions_IncomingEdgesResult:
    function: str
    address: str
    edges: tuple[_functions_CallerEdge, ...]


@dataclass(frozen=True)
class _functions_OutgoingEdgesResult:
    function: str
    address: str
    edges: tuple[_functions_CalleeEdge, ...]


@dataclass(frozen=True)
class _functions_TextResult:
    text: str


@dataclass(frozen=True)
class _functions_CtreeNode:
    kind: str
    depth: int
    op: str
    ea: str | None
    text: str


@dataclass(frozen=True)
class _functions_CtreeResult:
    function: str
    address: str
    level: str
    nodes: tuple[_functions_CtreeNode, ...]
    text: str


@dataclass(frozen=True)
class _functions_MicrocodeResult:
    function: str
    address: str
    level: str
    maturity: str
    lines: tuple[str, ...]
    text: str


def _functions_parse_function_list(params: Mapping[str, Any]) -> _functions_FunctionListRequest:
    pattern, regex, ignore_case = pattern_from_params(params)
    return _functions_FunctionListRequest(
        pattern=pattern,
        regex=regex,
        ignore_case=ignore_case,
        segment=optional_str(params.get("segment")),
        limit=optional_param_int(params, "limit", label="function list limit", minimum=1),
        demangle=bool(params.get("demangle")),
    )


def _functions_function_list(
    context: OperationContext, request: _functions_FunctionListRequest
) -> tuple[_functions_FunctionListEntry, ...]:
    runtime = context.runtime
    ranges = () if request.segment is None else runtime.resolve_segment_ranges(request.segment)
    rows: list[_functions_FunctionListEntry] = []
    for ea in runtime.idautils.Functions():
        if ranges and (not runtime.ea_in_ranges(ea, ranges)):
            continue
        name = runtime.function_name(ea)
        display_name = runtime.display_function_name(ea, demangle=True)
        match_name = display_name if request.demangle else name
        if request.pattern and (
            not text_matches(
                match_name,
                pattern=request.pattern,
                regex=request.regex,
                ignore_case=request.ignore_case,
            )
        ):
            continue
        func = runtime.ida_funcs.get_func(ea)
        rows.append(
            _functions_FunctionListEntry(
                name=name,
                display_name=display_name,
                render_name=display_name if request.demangle else name,
                address=hex(ea),
                section=runtime.ida_segment.get_segment_name(ea, runtime.ida_name.GN_VISIBLE),
                size=0 if func is None else func.end_ea - func.start_ea,
            )
        )
        if request.limit is not None and len(rows) >= request.limit:
            break
    return tuple(rows)


def _functions_parse_identifier(params: Mapping[str, Any]) -> _functions_FunctionIdentifierRequest:
    return _functions_FunctionIdentifierRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier")
    )


def _functions_parse_disasm_range(params: Mapping[str, Any]) -> _functions_DisasmRangeRequest:
    return _functions_DisasmRangeRequest(
        start=require_str(params.get("start"), field="range start"),
        end=require_str(params.get("end"), field="range end"),
    )


def _functions_function_show(
    context: OperationContext, request: _functions_FunctionIdentifierRequest
) -> _functions_FunctionShowResult:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    ida_typeinf = runtime.ida_typeinf
    name, address = runtime.function_identity(func)
    ea = func.start_ea
    return _functions_FunctionShowResult(
        name=name,
        display_name=runtime.display_function_name(ea, demangle=True),
        address=address,
        size=func.end_ea - func.start_ea,
        prototype=ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) or "",
        flags=hex(func.flags),
    )


def _functions_frame_members(
    runtime: IdaRuntime, func, *, include_special: bool, include_xrefs: bool, query: str | None = None
) -> tuple[_functions_FrameMember, ...]:
    frame_tif = runtime.ida_typeinf.tinfo_t()
    if not frame_tif.get_func_frame(func):
        raise IdaOperationError(f"function has no frame: {hex(func.start_ea)}")
    xref_names = {runtime.ida_xref.dr_R: "read", runtime.ida_xref.dr_W: "write"}
    members: list[_functions_FrameMember] = []
    for index, frame_udm in enumerate(frame_tif.iter_struct()):
        offset = frame_udm.begin() // 8
        end_offset = frame_udm.end() // 8
        tid = frame_tif.get_udm_tid(index)
        local_size = func.frsize
        saved_regs_size = func.frregs
        special_from_layout = local_size <= offset < local_size + saved_regs_size
        is_special = bool(runtime.ida_frame.is_special_frame_member(tid)) or special_from_layout
        if is_special and (not include_special):
            continue
        name = str(frame_udm.name or f"<unnamed_{index}>")
        if query and (not text_matches(name, pattern=query, ignore_case=True)):
            continue
        is_arg = False if is_special else bool(runtime.ida_frame.is_funcarg_off(func, offset))
        xrefs: tuple[_functions_FrameXref, ...] = ()
        xref_count: int | None = None
        if include_xrefs:
            xreflist = runtime.ida_frame.xreflist_t()
            runtime.ida_frame.build_stkvar_xrefs(xreflist, func, offset, end_offset)
            xref_rows: list[_functions_FrameXref] = []
            for item_index in range(xreflist.size()):
                item = xreflist[item_index]
                xref_rows.append(
                    _functions_FrameXref(
                        address=hex(item.ea),
                        operand=item.opnum,
                        type=item.type,
                        access=xref_names.get(item.type, "unknown"),
                    )
                )
            xrefs = tuple(xref_rows)
            xref_count = len(xref_rows)
        members.append(
            _functions_FrameMember(
                index=index,
                name=name,
                offset=offset,
                end_offset=end_offset,
                size=max(0, end_offset - offset),
                type=runtime.tinfo_decl(frame_udm.type, multi=False),
                kind="special" if is_special else "arg" if is_arg else "local",
                is_special=is_special,
                is_arg=is_arg,
                fp_offset=None if is_special else runtime.ida_frame.soff_to_fpoff(func, offset),
                xrefs=xrefs,
                xref_count=xref_count,
            )
        )
    members.sort(key=lambda item: (item.offset, item.name.lower()))
    return tuple(members)


def _functions_function_frame(
    context: OperationContext, request: _functions_FunctionIdentifierRequest
) -> _functions_FunctionFrameResult:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = runtime.function_identity(func)
    frame_tif = runtime.ida_typeinf.tinfo_t()
    if not frame_tif.get_func_frame(func):
        raise IdaOperationError(f"function has no frame: {address}")
    return _functions_FunctionFrameResult(
        function=name,
        address=address,
        frame_size=frame_tif.get_size(),
        local_size=func.frsize,
        saved_registers_size=func.frregs,
        argument_size=func.argsize,
        members=_functions_frame_members(runtime, func, include_special=True, include_xrefs=False),
    )


def _functions_function_stackvars(
    context: OperationContext, request: _functions_FunctionIdentifierRequest
) -> _functions_FunctionStackvarsResult:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = runtime.function_identity(func)
    return _functions_FunctionStackvarsResult(
        function=name,
        address=address,
        stackvars=_functions_frame_members(runtime, func, include_special=False, include_xrefs=True),
    )


def _functions_incoming_edges(runtime: IdaRuntime, func) -> tuple[_functions_CallerEdge, ...]:
    rows: list[_functions_CallerEdge] = []
    seen: set[tuple[int, int]] = set()
    target_ea = func.start_ea
    flags = runtime.ida_xref.XREF_CODE | runtime.ida_xref.XREF_NOFLOW
    for ref in runtime.xrefs_to(target_ea, flags=flags):
        if ref.kind != "call":
            continue
        caller = runtime.ida_funcs.get_func(ref.from_ea)
        if caller is None:
            continue
        caller_ea = caller.start_ea
        key = (caller_ea, ref.from_ea)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            _functions_CallerEdge(
                call_site=hex(ref.from_ea), caller=runtime.function_name(caller_ea), caller_address=hex(caller_ea)
            )
        )
    rows.sort(key=lambda item: (item.caller.lower(), item.call_site))
    return tuple(rows)


def _functions_outgoing_edges(runtime: IdaRuntime, func) -> tuple[_functions_CalleeEdge, ...]:
    rows: list[_functions_CalleeEdge] = []
    seen: set[tuple[int, int]] = set()
    flags = runtime.ida_xref.XREF_CODE | runtime.ida_xref.XREF_NOFLOW
    for item in runtime.ida_funcs.func_item_iterator_t(func).code_items():
        for ref in runtime.xrefs_from(item, flags=flags):
            if ref.kind != "call":
                continue
            callee = runtime.ida_funcs.get_func(ref.to_ea)
            if callee is None:
                continue
            callee_ea = callee.start_ea
            key = (item, callee_ea)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                _functions_CalleeEdge(
                    call_site=hex(item), callee=runtime.function_name(callee_ea), callee_address=hex(callee_ea)
                )
            )
    rows.sort(key=lambda item: (item.callee.lower(), item.call_site))
    return tuple(rows)


def _functions_function_callers(
    context: OperationContext, request: _functions_FunctionIdentifierRequest
) -> _functions_IncomingEdgesResult:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = runtime.function_identity(func)
    return _functions_IncomingEdgesResult(
        function=name, address=address, edges=_functions_incoming_edges(runtime, func)
    )


def _functions_function_callees(
    context: OperationContext, request: _functions_FunctionIdentifierRequest
) -> _functions_OutgoingEdgesResult:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = runtime.function_identity(func)
    return _functions_OutgoingEdgesResult(
        function=name, address=address, edges=_functions_outgoing_edges(runtime, func)
    )


def _functions_disasm(
    context: OperationContext, request: _functions_FunctionIdentifierRequest
) -> _functions_TextResult:
    runtime = context.runtime
    func_ea = runtime.function_ea(request.identifier)
    ida_lines = runtime.mod("ida_lines")
    lines = [
        f"{hex(ea)}: {_strip_tags(runtime, ida_lines.generate_disasm_line(ea, 0) or '')}"
        for ea in runtime.idautils.FuncItems(func_ea)
    ]
    return _functions_TextResult(text="\n".join(lines))


def _functions_disasm_range(context: OperationContext, request: _functions_DisasmRangeRequest) -> _functions_TextResult:
    runtime = context.runtime
    start_ea, end_ea = runtime.resolve_range(start=request.start, end=request.end, require_bounds=True)
    ida_lines = runtime.mod("ida_lines")
    flags = ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS
    lines: list[str] = []
    for ea in runtime.idautils.Heads(start_ea, end_ea):
        text = _strip_tags(runtime, ida_lines.generate_disasm_line(ea, flags) or "")
        if text:
            lines.append(f"{hex(ea)}: {text}")
    return _functions_TextResult(text="\n".join(lines))


def _functions_parse_decompile(params: Mapping[str, Any]) -> _functions_DecompileRequest:
    return _functions_DecompileRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        no_cache=bool(params.get("no_cache")),
    )


def _functions_decompile(context: OperationContext, request: _functions_DecompileRequest) -> _functions_TextResult:
    runtime = context.runtime
    ida_hexrays = runtime.require_hexrays()
    ea = runtime.function_ea(request.identifier)
    flags = ida_hexrays.DECOMP_NO_CACHE if request.no_cache else 0
    cfunc = ida_hexrays.decompile(ea, None, flags) if flags else ida_hexrays.decompile(ea)
    if cfunc is None:
        raise IdaOperationError(f"failed to decompile function at {hex(ea)}")
    return _functions_TextResult(text=runtime.pseudocode_text(cfunc))


def _functions_parse_ctree(params: Mapping[str, Any]) -> _functions_CtreeRequest:
    return _functions_CtreeRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        level=str(params.get("level") or "ctree").lower(),
        maturity=str(params.get("maturity") or "generated").lower(),
    )


def _functions_ctree_rows(runtime: IdaRuntime, cfunc) -> tuple[_functions_CtreeNode, ...]:
    ida_hexrays = runtime.require_hexrays()
    rows: list[_functions_CtreeNode] = []

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST | ida_hexrays.CV_PARENTS)

        def _append(self, kind: str, node) -> int:
            rows.append(
                _functions_CtreeNode(
                    kind=kind,
                    depth=max(0, len(self.parents) - 1),
                    op=node.opname,
                    ea=_ea_text(runtime, node.ea),
                    text=_strip_tags(runtime, node.print1(cfunc)),
                )
            )
            return 0

        def visit_insn(self, insn):
            return self._append("insn", insn)

        def visit_expr(self, expr):
            return self._append("expr", expr)

    visitor = Visitor()
    visitor.apply_to(cfunc.body, None)
    return tuple(rows)


def _functions_render_ctree_text(nodes: tuple[_functions_CtreeNode, ...]) -> str:
    return "\n".join(
        f"{'  ' * int(node.depth)}{node.kind}:{node.op}"
        + (f" @{node.ea}" if node.ea else "")
        + (f"  {node.text}" if node.text else "")
        for node in nodes
    )


def _functions_maturity_value(runtime: IdaRuntime, name: str) -> int:
    ida_hexrays = runtime.require_hexrays()
    maturities = {
        "generated": ida_hexrays.MMAT_GENERATED,
        "preoptimized": ida_hexrays.MMAT_PREOPTIMIZED,
        "locopt": ida_hexrays.MMAT_LOCOPT,
        "calls": ida_hexrays.MMAT_CALLS,
        "glbopt1": ida_hexrays.MMAT_GLBOPT1,
        "glbopt2": ida_hexrays.MMAT_GLBOPT2,
        "glbopt3": ida_hexrays.MMAT_GLBOPT3,
        "lvars": ida_hexrays.MMAT_LVARS,
    }
    try:
        return maturities[name]
    except KeyError as exc:
        raise IdaOperationError(f"unsupported microcode maturity: {name}") from exc


def _functions_microcode_lines(runtime: IdaRuntime, func, maturity: str) -> tuple[str, ...]:
    ida_hexrays = runtime.require_hexrays()
    maturity_value = _functions_maturity_value(runtime, maturity)

    class Printer(ida_hexrays.vd_printer_t):
        def __init__(self) -> None:
            super().__init__()
            self.lines: list[str] = []

        def _print(self, indent, line):
            prefix = " " * int(indent or 0)
            rendered = _strip_tags(runtime, line).rstrip()
            self.lines.append(f"{prefix}{rendered}".rstrip())
            return 0

    mbr = ida_hexrays.mba_ranges_t()
    mbr.ranges.push_back(runtime.ida_range.range_t(func.start_ea, func.end_ea))
    hf = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_WARNINGS | ida_hexrays.DECOMP_NO_CACHE, maturity_value
    )
    if mba is None:
        raise IdaOperationError(f"failed to generate microcode: {hf.desc()}")
    printer = Printer()
    mba._print(printer)
    return tuple(line for line in printer.lines if line)


def _functions_ctree(
    context: OperationContext, request: _functions_CtreeRequest
) -> _functions_CtreeResult | _functions_MicrocodeResult:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = runtime.function_identity(func)
    if request.level == "ctree":
        cfunc = runtime.require_hexrays().decompile(func.start_ea)
        if cfunc is None:
            raise IdaOperationError(f"failed to decompile function at {address}")
        nodes = _functions_ctree_rows(runtime, cfunc)
        return _functions_CtreeResult(
            function=name, address=address, level=request.level, nodes=nodes, text=_functions_render_ctree_text(nodes)
        )
    if request.level == "micro":
        lines = _functions_microcode_lines(runtime, func, request.maturity)
        return _functions_MicrocodeResult(
            function=name,
            address=address,
            level=request.level,
            maturity=request.maturity,
            lines=lines,
            text="\n".join(lines),
        )
    raise IdaOperationError(f"unsupported ctree level: {request.level}")


# ---- Search operations ----


_search_MEBIBYTE = 1024 * 1024
_search_MAX_DSC_STRING_SCAN_BYTES = 16 * _search_MEBIBYTE


@dataclass(frozen=True)
class _search_SearchBytesRequest:
    pattern: str
    segment: str
    start: str | None
    end: str | None
    limit: int


@dataclass(frozen=True)
class _search_SearchMatch:
    address: str


@dataclass(frozen=True)
class _search_SearchMatchInFunction:
    address: str
    function: str


@dataclass(frozen=True)
class _search_SearchBytesResult:
    pattern: str
    segment: str
    start: str
    end: str
    limit: int
    truncated: bool
    ranges: tuple[_search_SearchScopeRange, ...]
    results: tuple[_search_SearchMatch | _search_SearchMatchInFunction, ...]


@dataclass(frozen=True)
class _search_XrefsRequest:
    identifier: str


@dataclass(frozen=True)
class _search_XrefRow:
    from_: str
    to: str
    type: str
    kind: str
    user: bool
    function: str | None = None


@dataclass(frozen=True)
class _search_StringsRequest:
    pattern: str
    regex: bool
    ignore_case: bool
    scan: bool
    segment: str
    start: str | None
    end: str | None


@dataclass(frozen=True)
class _search_StringRow:
    address: str
    text: str


@dataclass(frozen=True)
class _search_SearchScopeRange:
    name: str
    start: str
    end: str


@dataclass(frozen=True)
class _search_ImportEntry:
    address: str
    name: str
    ordinal: int


@dataclass(frozen=True)
class _search_ImportModule:
    module: str
    entries: tuple[_search_ImportEntry, ...]


def _search_parse_search_bytes(params: Mapping[str, Any]) -> _search_SearchBytesRequest:
    pattern = require_str(params.get("pattern"), field="byte pattern")
    segment = require_str(params.get("segment"), field="segment selector")
    start = optional_str(params.get("start"))
    end = optional_str(params.get("end"))
    limit = optional_param_int(params, "limit", label="search result limit", minimum=1) or 100
    return _search_SearchBytesRequest(pattern=pattern, segment=segment, start=start, end=end, limit=limit)


def _search_search_bytes_from_cursor(runtime: IdaRuntime, start: int, end: int, compiled_pattern, flags: int) -> int:
    result = runtime.mod("ida_bytes").bin_search(start, end, compiled_pattern, flags)
    return int(result[0]) if isinstance(result, tuple) else int(result)


def _search_has_more_search_bytes_matches(
    runtime: IdaRuntime,
    *,
    ranges: tuple[SegmentRange, ...],
    start_index: int,
    cursor: int,
    compiled_pattern,
    flags: int,
    badaddr: int,
) -> bool:
    for index in range(start_index, len(ranges)):
        scope = ranges[index]
        scope_cursor = cursor if index == start_index else scope.start_ea
        if scope_cursor >= scope.end_ea:
            continue
        match_ea = _search_search_bytes_from_cursor(runtime, scope_cursor, scope.end_ea, compiled_pattern, flags)
        if match_ea != badaddr:
            return True
    return False


def _search_search_bytes(context: OperationContext, request: _search_SearchBytesRequest) -> _search_SearchBytesResult:
    runtime = context.runtime
    ida_bytes = runtime.mod("ida_bytes")
    idaapi = runtime.mod("idaapi")
    ranges = runtime.resolve_segment_ranges(request.segment, start=request.start, end=request.end, require_bounds=False)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW
    compiled_pattern = runtime.compile_binpat(request.pattern, ea=ranges[0].start_ea)
    rows: list[_search_SearchMatch | _search_SearchMatchInFunction] = []
    truncated = False
    for index, scope in enumerate(ranges):
        cursor = scope.start_ea
        while cursor < scope.end_ea and len(rows) < request.limit:
            match_ea = _search_search_bytes_from_cursor(runtime, cursor, scope.end_ea, compiled_pattern, flags)
            if match_ea == idaapi.BADADDR:
                break
            func = runtime.ida_funcs.get_func(match_ea)
            function_name = None if func is None else runtime.function_name(func.start_ea)
            if function_name:
                rows.append(_search_SearchMatchInFunction(address=hex(match_ea), function=function_name))
            else:
                rows.append(_search_SearchMatch(address=hex(match_ea)))
            cursor = match_ea + 1
        if len(rows) == request.limit:
            truncated = _search_has_more_search_bytes_matches(
                runtime,
                ranges=ranges,
                start_index=index,
                cursor=cursor,
                compiled_pattern=compiled_pattern,
                flags=flags,
                badaddr=idaapi.BADADDR,
            )
            break
    return _search_SearchBytesResult(
        pattern=request.pattern,
        segment=request.segment,
        start=hex(ranges[0].start_ea),
        end=hex(ranges[-1].end_ea),
        limit=request.limit,
        truncated=truncated,
        ranges=tuple(
            _search_SearchScopeRange(name=item.name, start=hex(item.start_ea), end=hex(item.end_ea)) for item in ranges
        ),
        results=tuple(rows),
    )


def _search_parse_xrefs(params: Mapping[str, Any]) -> _search_XrefsRequest:
    return _search_XrefsRequest(identifier=require_str(params.get("identifier"), field="address or identifier"))


def _search_xrefs(context: OperationContext, request: _search_XrefsRequest) -> tuple[_search_XrefRow, ...]:
    runtime = context.runtime
    ea = runtime.resolve_address(request.identifier)
    rows: list[_search_XrefRow] = []
    seen: set[tuple[str, str, str, str, bool, str | None]] = set()
    for flags in (runtime.ida_xref.XREF_FLOW, runtime.ida_xref.XREF_CODE, runtime.ida_xref.XREF_DATA):
        for ref in runtime.xrefs_to(ea, flags=flags):
            func = runtime.ida_funcs.get_func(ref.from_ea)
            row = _search_XrefRow(
                from_=hex(ref.from_ea),
                to=hex(ref.to_ea),
                type=ref.type,
                kind=ref.kind,
                user=ref.user,
                function=None if func is None else runtime.function_name(func.start_ea),
            )
            key = (row.from_, row.to, row.type, row.kind, row.user, row.function)
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    rows.sort(key=lambda item: (item.kind, item.from_))
    return tuple(rows)


def _search_parse_strings(params: Mapping[str, Any]) -> _search_StringsRequest:
    pattern, regex, ignore_case = pattern_from_params(params)
    segment = require_str(params.get("segment"), field="segment selector")
    start = optional_str(params.get("start"))
    end = optional_str(params.get("end"))
    return _search_StringsRequest(
        pattern=pattern,
        regex=regex,
        ignore_case=ignore_case,
        scan=bool(params.get("scan")),
        segment=segment,
        start=start,
        end=end,
    )


def _search_string_text(runtime: IdaRuntime, ea: int, length: int, strtype: int) -> str:
    value = runtime.ida_bytes.get_strlit_contents(ea, length, strtype)
    if value is None:
        return ""
    return value.decode("UTF-8", "replace")


def _search_defined_string_rows(
    runtime: IdaRuntime, *, ranges: tuple[SegmentRange, ...], pattern: str, regex: bool, ignore_case: bool
) -> tuple[_search_StringRow, ...]:
    ida_strlist = runtime.ida_strlist
    string_types = list(
        dict.fromkeys(
            (
                runtime.ida_nalt.STRTYPE_TERMCHR,
                runtime.ida_nalt.STRTYPE_C,
                runtime.ida_nalt.STRTYPE_C_16,
                runtime.ida_nalt.STRTYPE_C_32,
                runtime.ida_nalt.STRTYPE_PASCAL,
                runtime.ida_nalt.STRTYPE_PASCAL_16,
                runtime.ida_nalt.STRTYPE_PASCAL_32,
                runtime.ida_nalt.STRTYPE_LEN2,
                runtime.ida_nalt.STRTYPE_LEN2_16,
                runtime.ida_nalt.STRTYPE_LEN2_32,
                runtime.ida_nalt.STRTYPE_LEN4,
                runtime.ida_nalt.STRTYPE_LEN4_16,
                runtime.ida_nalt.STRTYPE_LEN4_32,
            )
        )
    )
    options = ida_strlist.get_strlist_options()
    saved_strtypes = list(options.strtypes)
    saved_minlen = int(options.minlen)
    saved_display_only_existing_strings = bool(options.display_only_existing_strings)
    saved_only_7bit = bool(options.only_7bit)
    saved_ignore_heads = bool(options.ignore_heads)
    rows: list[_search_StringRow] = []
    try:
        options.strtypes = string_types
        options.minlen = 1
        options.display_only_existing_strings = True
        options.only_7bit = False
        options.ignore_heads = False
        ida_strlist.build_strlist()
        item = ida_strlist.string_info_t()
        for index in range(int(ida_strlist.get_strlist_qty())):
            if not ida_strlist.get_strlist_item(item, index):
                continue
            ea = int(item.ea)
            if not runtime.ea_in_ranges(ea, ranges):
                continue
            text = _search_string_text(runtime, ea, int(item.length), int(item.type))
            if text_matches(text, pattern=pattern, regex=regex, ignore_case=ignore_case):
                rows.append(_search_StringRow(address=hex(ea), text=text))
    finally:
        options.strtypes = saved_strtypes
        options.minlen = saved_minlen
        options.display_only_existing_strings = saved_display_only_existing_strings
        options.only_7bit = saved_only_7bit
        options.ignore_heads = saved_ignore_heads
        ida_strlist.build_strlist()
    return tuple(rows)


def _search_scan_string_rows(
    runtime: IdaRuntime, *, ranges: tuple[SegmentRange, ...], pattern: str, regex: bool, ignore_case: bool
) -> tuple[_search_StringRow, ...]:
    rows: list[_search_StringRow] = []
    for scope in ranges:
        cursor = scope.start_ea
        while cursor < scope.end_ea:
            length = runtime.ida_bytes.get_max_strlit_length(
                cursor, runtime.ida_nalt.STRTYPE_C, runtime.ida_bytes.ALOPT_IGNHEADS
            )
            if length < 5 or cursor + length > scope.end_ea:
                cursor += 1
                continue
            text = _search_string_text(runtime, cursor, length, runtime.ida_nalt.STRTYPE_C)
            if not text:
                cursor += 1
                continue
            if not text_matches(text, pattern=pattern, regex=regex, ignore_case=ignore_case):
                cursor += max(length, 1)
                continue
            rows.append(_search_StringRow(address=hex(cursor), text=text))
            cursor += max(length, 1)
    return tuple(rows)


def _search_validate_dsc_string_scan_ranges(ranges: tuple[SegmentRange, ...]) -> None:
    requested = sum(max(0, item.end_ea - item.start_ea) for item in ranges)
    if requested <= _search_MAX_DSC_STRING_SCAN_BYTES:
        return
    raise IdaOperationError(
        "dyld shared cache string scans are limited to "
        f"{_search_MAX_DSC_STRING_SCAN_BYTES // _search_MEBIBYTE} MiB; "
        f"requested {requested // _search_MEBIBYTE} MiB"
    )


def _search_strings(context: OperationContext, request: _search_StringsRequest) -> tuple[_search_StringRow, ...]:
    runtime = context.runtime
    input_basename = os.path.basename(str(runtime.ida_nalt.get_input_file_path() or "").strip()).lower()
    is_dsc = input_basename == "dyld_shared_cache" or input_basename.startswith("dyld_shared_cache_")
    ranges = runtime.resolve_segment_ranges(
        request.segment,
        start=request.start,
        end=request.end,
        require_bounds=is_dsc and request.scan,
        missing_message="dyld shared cache string scan requires both start and end addresses",
    )
    if request.scan:
        if is_dsc:
            _search_validate_dsc_string_scan_ranges(ranges)
        return _search_scan_string_rows(
            runtime,
            ranges=ranges,
            pattern=request.pattern,
            regex=request.regex,
            ignore_case=request.ignore_case,
        )
    if is_dsc:
        raise IdaOperationError(
            "defined string listing is disabled for dyld shared caches; use "
            "`search strings --scan --segment ... --start ... --end ...` with a range of at most "
            f"{_search_MAX_DSC_STRING_SCAN_BYTES // _search_MEBIBYTE} MiB"
        )
    return _search_defined_string_rows(
        runtime,
        ranges=ranges,
        pattern=request.pattern,
        regex=request.regex,
        ignore_case=request.ignore_case,
    )


def _search_imports(context: OperationContext, request: None) -> tuple[_search_ImportModule, ...]:
    del request
    runtime = context.runtime
    modules: list[_search_ImportModule] = []
    for index in range(runtime.ida_nalt.get_import_module_qty()):
        module_name = runtime.ida_nalt.get_import_module_name(index) or "<unnamed>"
        entries: list[_search_ImportEntry] = []

        def imp_cb(ea: int, name: str | None, ordinal: int, entries: list[_search_ImportEntry] = entries) -> bool:
            entries.append(_search_ImportEntry(address=hex(ea), name=name or f"ordinal_{ordinal}", ordinal=ordinal))
            return True

        runtime.ida_nalt.enum_import_names(index, imp_cb)
        modules.append(_search_ImportModule(module=module_name, entries=tuple(entries)))
    return tuple(modules)


# ---- Bookmark operations ----


@dataclass(frozen=True)
class _bookmarks_BookmarkGetRequest:
    slot: int | None = None


@dataclass(frozen=True)
class _bookmarks_BookmarkSetRequest:
    slot: int
    identifier: str
    comment: str = ""


@dataclass(frozen=True)
class _bookmarks_BookmarkAddRequest:
    identifier: str
    comment: str = ""
    slot: int | None = None


@dataclass(frozen=True)
class _bookmarks_BookmarkDeleteRequest:
    slot: int


@dataclass(frozen=True)
class _bookmarks_BookmarkState:
    slot: int
    present: bool
    address: str | None
    comment: str | None


@dataclass(frozen=True)
class _bookmarks_BookmarkList:
    bookmarks: list[_bookmarks_BookmarkState]
    count: int


@dataclass(frozen=True)
class _bookmarks_BookmarkMutationResult:
    slot: int
    present: bool
    address: str | None
    comment: str | None
    changed: bool


def _bookmarks_parse_slot(value: object) -> int:
    text = str("" if value is None else value).strip()
    if not text:
        raise IdaOperationError("bookmark slot is required")
    try:
        slot = int(text, 0)
    except ValueError as exc:
        raise IdaOperationError("bookmark slot must be an integer") from exc
    if slot < 0:
        raise IdaOperationError("bookmark slot must be greater than or equal to 0")
    return slot


def _bookmarks_validate_slot(runtime: IdaRuntime, slot: int) -> int:
    ida_moves = runtime.mod("ida_moves")
    if slot > ida_moves.MAX_MARK_SLOT:
        raise IdaOperationError(f"bookmark slot must be less than or equal to {ida_moves.MAX_MARK_SLOT}")
    return slot


def _bookmarks_bookmark_template(runtime: IdaRuntime):
    ida_kernwin = runtime.mod("ida_kernwin")
    ida_moves = runtime.mod("ida_moves")
    place_id = ida_kernwin.get_place_class_id("idaplace_t")
    if place_id < 0:
        raise IdaOperationError("failed to resolve IDA bookmark place class")
    place = ida_kernwin.get_place_class_template(place_id)
    if place is None:
        raise IdaOperationError("failed to build an idaplace_t template for bookmarks")
    loc = ida_moves.lochist_entry_t()
    loc.set_place(place)
    return loc


def _bookmarks_bookmark_state(runtime: IdaRuntime, slot: int) -> _bookmarks_BookmarkState:
    ida_kernwin = runtime.mod("ida_kernwin")
    ida_moves = runtime.mod("ida_moves")
    loc = _bookmarks_bookmark_template(runtime)
    desc, found_slot = ida_moves.bookmarks_t.get(loc, slot, None)
    if desc is None or found_slot is None:
        return _bookmarks_BookmarkState(slot=slot, present=False, address=None, comment=None)
    place = loc.place()
    idaplace = ida_kernwin.place_t.as_idaplace_t(place)
    if idaplace is None:
        raise IdaOperationError(f"failed to decode bookmark slot {slot}")
    address = hex(idaplace.ea)
    return _bookmarks_BookmarkState(slot=slot, present=True, address=address, comment=desc)


def _bookmarks_bookmark_list(runtime: IdaRuntime) -> _bookmarks_BookmarkList:
    ida_moves = runtime.mod("ida_moves")
    bookmarks: list[_bookmarks_BookmarkState] = []
    for slot in range(ida_moves.MAX_MARK_SLOT + 1):
        state = _bookmarks_bookmark_state(runtime, slot)
        if state.present:
            bookmarks.append(state)
    return _bookmarks_BookmarkList(bookmarks=bookmarks, count=len(bookmarks))


def _bookmarks_first_free_slot(runtime: IdaRuntime) -> int:
    ida_moves = runtime.mod("ida_moves")
    for slot in range(ida_moves.MAX_MARK_SLOT + 1):
        if not _bookmarks_bookmark_state(runtime, slot).present:
            return slot
    raise IdaOperationError(f"no free bookmark slots remain (0..{ida_moves.MAX_MARK_SLOT})")


def _bookmarks_erase_bookmark_raw(runtime: IdaRuntime, slot: int) -> bool:
    ida_moves = runtime.mod("ida_moves")
    loc = _bookmarks_bookmark_template(runtime)
    return bool(ida_moves.bookmarks_t.erase(loc, slot, None))


def _bookmarks_write_bookmark_raw(runtime: IdaRuntime, *, slot: int, identifier: str, comment: str) -> int:
    ea = runtime.resolve_address(identifier)
    runtime.mod("ida_idc").mark_position(ea, 0, 0, 0, slot, comment)
    return ea


def _bookmarks_write_bookmark(
    runtime: IdaRuntime, *, slot: int, identifier: str, comment: str
) -> _bookmarks_BookmarkMutationResult:
    ea = _bookmarks_write_bookmark_raw(runtime, slot=slot, identifier=identifier, comment=comment)
    state = _bookmarks_bookmark_state(runtime, slot)
    if not state.present or state.address != hex(ea) or state.comment != comment:
        raise IdaOperationError(f"failed to set bookmark slot {slot}")
    return _bookmarks_BookmarkMutationResult(
        slot=state.slot, present=state.present, address=state.address, comment=state.comment, changed=True
    )


def _bookmarks_parse_get(params: Mapping[str, Any]) -> _bookmarks_BookmarkGetRequest:
    slot_value = params.get("slot")
    if slot_value in (None, ""):
        return _bookmarks_BookmarkGetRequest()
    return _bookmarks_BookmarkGetRequest(slot=_bookmarks_parse_slot(slot_value))


def _bookmarks_parse_set(params: Mapping[str, Any]) -> _bookmarks_BookmarkSetRequest:
    return _bookmarks_BookmarkSetRequest(
        slot=_bookmarks_parse_slot(params.get("slot")),
        identifier=require_str(params.get("address"), field="address"),
        comment=str(params.get("comment") or ""),
    )


def _bookmarks_parse_add(params: Mapping[str, Any]) -> _bookmarks_BookmarkAddRequest:
    return _bookmarks_BookmarkAddRequest(
        identifier=require_str(params.get("address"), field="address"),
        comment=str(params.get("comment") or ""),
    )


def _bookmarks_parse_delete(params: Mapping[str, Any]) -> _bookmarks_BookmarkDeleteRequest:
    return _bookmarks_BookmarkDeleteRequest(slot=_bookmarks_parse_slot(params.get("slot")))


def _bookmarks_get_bookmark(
    context: OperationContext, request: _bookmarks_BookmarkGetRequest
) -> _bookmarks_BookmarkState | _bookmarks_BookmarkList:
    runtime = context.runtime
    if request.slot is None:
        return _bookmarks_bookmark_list(runtime)
    return _bookmarks_bookmark_state(runtime, _bookmarks_validate_slot(runtime, request.slot))


def _bookmarks_set_bookmark(
    context: OperationContext, request: _bookmarks_BookmarkSetRequest
) -> _bookmarks_BookmarkMutationResult:
    runtime = context.runtime
    slot = _bookmarks_validate_slot(runtime, request.slot)
    before = _bookmarks_bookmark_state(runtime, slot)
    target_address = hex(runtime.resolve_address(request.identifier))
    if before.present and before.address == target_address and before.comment == request.comment:
        return _bookmarks_BookmarkMutationResult(
            slot=before.slot,
            present=before.present,
            address=before.address,
            comment=before.comment,
            changed=False,
        )
    try:
        return _bookmarks_write_bookmark(
            runtime,
            slot=slot,
            identifier=target_address,
            comment=request.comment,
        )
    except BaseException:
        _bookmarks_restore_bookmark_state(context, request, before)
        raise


def _bookmarks_add_bookmark(
    context: OperationContext, request: _bookmarks_BookmarkAddRequest
) -> _bookmarks_BookmarkMutationResult:
    runtime = context.runtime
    slot = (
        _bookmarks_first_free_slot(runtime) if request.slot is None else _bookmarks_validate_slot(runtime, request.slot)
    )
    resolved_request = _bookmarks_BookmarkAddRequest(
        identifier=request.identifier,
        comment=request.comment,
        slot=slot,
    )
    before = _bookmarks_BookmarkState(slot=slot, present=False, address=None, comment=None)
    try:
        return _bookmarks_write_bookmark(
            runtime,
            slot=slot,
            identifier=request.identifier,
            comment=request.comment,
        )
    except BaseException:
        _bookmarks_restore_bookmark_state(context, resolved_request, before)
        raise


def _bookmarks_prepare_add_bookmark(
    context: OperationContext, request: _bookmarks_BookmarkAddRequest
) -> _bookmarks_BookmarkAddRequest:
    return _bookmarks_BookmarkAddRequest(
        identifier=request.identifier,
        comment=request.comment,
        slot=_bookmarks_first_free_slot(context.runtime),
    )


def _bookmarks_delete_bookmark(
    context: OperationContext, request: _bookmarks_BookmarkDeleteRequest
) -> _bookmarks_BookmarkMutationResult:
    runtime = context.runtime
    slot = _bookmarks_validate_slot(runtime, request.slot)
    before = _bookmarks_bookmark_state(runtime, slot)
    if not before.present:
        return _bookmarks_BookmarkMutationResult(
            slot=before.slot, present=before.present, address=before.address, comment=before.comment, changed=False
        )
    try:
        if not _bookmarks_erase_bookmark_raw(runtime, slot):
            raise IdaOperationError(f"failed to delete bookmark slot {slot}")
        after = _bookmarks_bookmark_state(runtime, slot)
        if after.present:
            raise IdaOperationError(f"failed to delete bookmark slot {slot}")
    except BaseException:
        _bookmarks_restore_bookmark_state(context, request, before)
        raise
    return _bookmarks_BookmarkMutationResult(
        slot=after.slot, present=after.present, address=after.address, comment=after.comment, changed=True
    )


def _bookmarks_preview_single_slot(
    context: OperationContext,
    request: _bookmarks_BookmarkSetRequest | _bookmarks_BookmarkAddRequest | _bookmarks_BookmarkDeleteRequest,
) -> _bookmarks_BookmarkState:
    runtime = context.runtime
    if request.slot is None:
        raise IdaOperationError("bookmark preview did not resolve a slot")
    return _bookmarks_bookmark_state(runtime, _bookmarks_validate_slot(runtime, request.slot))


def _bookmarks_restore_bookmark_state(
    context: OperationContext,
    request: _bookmarks_BookmarkSetRequest | _bookmarks_BookmarkAddRequest | _bookmarks_BookmarkDeleteRequest,
    before: _bookmarks_BookmarkState,
) -> None:
    runtime = context.runtime
    if request.slot is None:
        raise IdaOperationError("bookmark preview did not resolve a slot")
    slot = _bookmarks_validate_slot(runtime, request.slot)
    if before.present:
        if before.address is None:
            raise IdaOperationError(f"bookmark slot {slot} is present but has no saved address")
        _bookmarks_write_bookmark_raw(runtime, slot=slot, identifier=before.address, comment=before.comment or "")
        return
    _bookmarks_erase_bookmark_raw(runtime, slot)


# ---- Comment operations ----


_comments_CommentScope = Literal["line", "function", "anterior", "posterior"]


@dataclass(frozen=True)
class _comments_CommentLookup:
    identifier: str
    scope: _comments_CommentScope
    repeatable: bool


@dataclass(frozen=True)
class _comments_CommentChange:
    identifier: str
    text: str
    scope: _comments_CommentScope
    repeatable: bool


@dataclass(frozen=True)
class _comments_CommentView:
    address: str
    scope: _comments_CommentScope
    repeatable: bool
    comment: str | None


@dataclass(frozen=True)
class _comments_CommentMutationResult:
    address: str
    scope: _comments_CommentScope
    repeatable: bool
    comment: str | None
    changed: bool


def _comments_normalize_comment_text(text: str | None) -> str | None:
    return None if text in (None, "") else str(text)


def _comments_parse_scope(params: Mapping[str, Any]) -> _comments_CommentScope:
    scope = str(params.get("scope") or "line").strip().lower()
    if scope not in {"line", "function", "anterior", "posterior"}:
        raise IdaOperationError(f"unsupported comment scope: {scope}")
    return scope


def _comments_parse_repeatable(params: Mapping[str, Any], *, scope: _comments_CommentScope) -> bool:
    repeatable = bool(params.get("repeatable"))
    if repeatable and scope in {"anterior", "posterior"}:
        raise IdaOperationError("repeatable comments are only supported for line or function scope")
    return repeatable


def _comments_function_for_comment(runtime: IdaRuntime, ea: int):
    func = runtime.ida_funcs.get_func(ea)
    if func is None:
        raise IdaOperationError(f"no function contains address {hex(ea)}")
    return func


def _comments_extra_anchor(runtime: IdaRuntime, scope: _comments_CommentScope) -> int:
    ida_lines = runtime.mod("ida_lines")
    if scope == "anterior":
        return ida_lines.E_PREV
    if scope == "posterior":
        return ida_lines.E_NEXT
    raise IdaOperationError(f"extra comments are unsupported for scope: {scope}")


def _comments_read_extra_comment(runtime: IdaRuntime, ea: int, *, scope: _comments_CommentScope) -> str | None:
    ida_lines = runtime.mod("ida_lines")
    index = _comments_extra_anchor(runtime, scope)
    lines: list[str] = []
    while True:
        line = ida_lines.get_extra_cmt(ea, index)
        if line is None:
            break
        lines.append(str(line))
        index += 1
    return _comments_normalize_comment_text(None if not lines else "\n".join(lines))


def _comments_extra_comment_lines(text: str | None) -> list[str]:
    rendered = "" if text is None else str(text)
    return [] if rendered == "" else rendered.split("\n")


def _comments_set_extra_comment_lines(
    runtime: IdaRuntime, ea: int, *, scope: _comments_CommentScope, lines: list[str]
) -> None:
    ida_lines = runtime.mod("ida_lines")
    anchor = _comments_extra_anchor(runtime, scope)
    ida_lines.delete_extra_cmts(ea, anchor)
    for index, line in enumerate(lines):
        if not ida_lines.update_extra_cmt(ea, anchor + index, line):
            raise IdaOperationError(f"failed to set {scope} comment at {hex(ea)}")


def _comments_write_extra_comment(
    runtime: IdaRuntime, ea: int, *, scope: _comments_CommentScope, text: str | None
) -> None:
    before = _comments_read_extra_comment(runtime, ea, scope=scope)
    before_lines = _comments_extra_comment_lines(before)
    new_lines = _comments_extra_comment_lines(text)
    try:
        _comments_set_extra_comment_lines(runtime, ea, scope=scope, lines=new_lines)
    except Exception as exc:
        try:
            _comments_set_extra_comment_lines(runtime, ea, scope=scope, lines=before_lines)
        except Exception as restore_exc:
            raise IdaOperationError(
                f"failed to restore {scope} comment at {hex(ea)} after update failure"
            ) from restore_exc
        raise IdaOperationError(f"failed to set {scope} comment at {hex(ea)}") from exc


def _comments_read_comment(
    runtime: IdaRuntime, request: _comments_CommentLookup | _comments_CommentChange
) -> _comments_CommentView:
    ida_bytes = runtime.mod("ida_bytes")
    ea = runtime.resolve_address(request.identifier)
    if request.scope == "line":
        comment = _comments_normalize_comment_text(ida_bytes.get_cmt(ea, request.repeatable))
        return _comments_CommentView(
            address=hex(ea), scope=request.scope, repeatable=request.repeatable, comment=comment
        )
    if request.scope == "function":
        func = _comments_function_for_comment(runtime, ea)
        comment = _comments_normalize_comment_text(runtime.ida_funcs.get_func_cmt(func, request.repeatable))
        return _comments_CommentView(
            address=hex(func.start_ea), scope=request.scope, repeatable=request.repeatable, comment=comment
        )
    return _comments_CommentView(
        address=hex(ea),
        scope=request.scope,
        repeatable=False,
        comment=_comments_read_extra_comment(runtime, ea, scope=request.scope),
    )


def _comments_write_comment(
    runtime: IdaRuntime, request: _comments_CommentChange, *, text: str
) -> _comments_CommentMutationResult:
    ida_bytes = runtime.mod("ida_bytes")
    ea = runtime.resolve_address(request.identifier)
    if request.scope == "line":
        if not ida_bytes.set_cmt(ea, text, request.repeatable):
            raise IdaOperationError(f"failed to set comment at {hex(ea)}")
        return _comments_CommentMutationResult(
            address=hex(ea),
            scope=request.scope,
            repeatable=request.repeatable,
            comment=_comments_normalize_comment_text(ida_bytes.get_cmt(ea, request.repeatable)),
            changed=True,
        )
    if request.scope == "function":
        func = _comments_function_for_comment(runtime, ea)
        if not runtime.ida_funcs.set_func_cmt(func, text, request.repeatable):
            raise IdaOperationError(f"failed to set function comment at {hex(func.start_ea)}")
        return _comments_CommentMutationResult(
            address=hex(func.start_ea),
            scope=request.scope,
            repeatable=request.repeatable,
            comment=_comments_normalize_comment_text(runtime.ida_funcs.get_func_cmt(func, request.repeatable)),
            changed=True,
        )
    _comments_write_extra_comment(runtime, ea, scope=request.scope, text=text)
    return _comments_CommentMutationResult(
        address=hex(ea),
        scope=request.scope,
        repeatable=False,
        comment=_comments_read_extra_comment(runtime, ea, scope=request.scope),
        changed=True,
    )


def _comments_comment_view(
    context: OperationContext, request: _comments_CommentLookup | _comments_CommentChange
) -> _comments_CommentView:
    return _comments_read_comment(context.runtime, request)


def _comments_parse_lookup(params: Mapping[str, Any]) -> _comments_CommentLookup:
    identifier = require_str(params.get("address"), field="address")
    scope = _comments_parse_scope(params)
    return _comments_CommentLookup(
        identifier=identifier, scope=scope, repeatable=_comments_parse_repeatable(params, scope=scope)
    )


def _comments_parse_change(params: Mapping[str, Any]) -> _comments_CommentChange:
    request = _comments_parse_lookup(params)
    return _comments_CommentChange(
        identifier=request.identifier,
        text=str(params.get("text") or ""),
        scope=request.scope,
        repeatable=request.repeatable,
    )


def _comments_change_comment(
    context: OperationContext, request: _comments_CommentLookup | _comments_CommentChange
) -> _comments_CommentMutationResult:
    change = (
        request
        if isinstance(request, _comments_CommentChange)
        else _comments_CommentChange(
            identifier=request.identifier, text="", scope=request.scope, repeatable=request.repeatable
        )
    )
    before = _comments_read_comment(context.runtime, change)
    desired = _comments_normalize_comment_text(change.text)
    if before.comment == desired:
        return _comments_CommentMutationResult(
            address=before.address,
            scope=before.scope,
            repeatable=before.repeatable,
            comment=before.comment,
            changed=False,
        )
    try:
        return _comments_write_comment(context.runtime, change, text=change.text)
    except BaseException:
        try:
            _comments_restore_comment(context, change, before)
        except BaseException as restore_exc:
            raise IdaOperationError(f"failed to restore {change.scope} comment after mutation failure") from restore_exc
        raise


def _comments_restore_comment(
    context: OperationContext,
    request: _comments_CommentLookup | _comments_CommentChange,
    before: _comments_CommentView,
) -> None:
    del request
    runtime = context.runtime
    ea = runtime.resolve_address(before.address)
    text = "" if before.comment is None else before.comment
    if before.scope == "line":
        if not runtime.mod("ida_bytes").set_cmt(ea, text, before.repeatable):
            raise IdaOperationError(f"failed to restore comment at {hex(ea)}")
        return
    if before.scope == "function":
        func = _comments_function_for_comment(runtime, ea)
        if not runtime.ida_funcs.set_func_cmt(func, text, before.repeatable):
            raise IdaOperationError(f"failed to restore function comment at {hex(func.start_ea)}")
        return
    _comments_set_extra_comment_lines(
        runtime,
        ea,
        scope=before.scope,
        lines=_comments_extra_comment_lines(before.comment),
    )


# ---- Name operations ----


@dataclass(frozen=True)
class _names_NameSetRequest:
    identifier: str
    new_name: str


@dataclass(frozen=True)
class _names_NameState:
    address: str
    name: str


@dataclass(frozen=True)
class _names_NameMutationResult:
    address: str
    name: str
    changed: bool


def _names_parse_name_set(params: Mapping[str, Any]) -> _names_NameSetRequest:
    identifier = require_str(params.get("identifier"), field="address or identifier")
    new_name = require_str(params.get("new_name"), field="new name")
    return _names_NameSetRequest(identifier=identifier, new_name=new_name)


def _names_prepare_name_set(context: OperationContext, request: _names_NameSetRequest) -> _names_NameSetRequest:
    runtime = context.runtime
    return _names_NameSetRequest(identifier=hex(runtime.resolve_address(request.identifier)), new_name=request.new_name)


def _names_name_state(context: OperationContext, request: _names_NameSetRequest) -> _names_NameState:
    runtime = context.runtime
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    return _names_NameState(address=hex(ea), name=ida_name.get_name(ea) or "")


def _names_set_name(context: OperationContext, request: _names_NameSetRequest) -> _names_NameMutationResult:
    runtime = context.runtime
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    before = _names_NameState(address=hex(ea), name=ida_name.get_name(ea) or "")
    if before.name == request.new_name:
        return _names_NameMutationResult(address=before.address, name=before.name, changed=False)
    try:
        if not ida_name.set_name(ea, request.new_name, ida_name.SN_CHECK):
            raise IdaOperationError(f"failed to set name at {hex(ea)}")
        after = ida_name.get_name(ea) or ""
        if after != request.new_name:
            raise IdaOperationError(f"failed to read back name at {hex(ea)}")
    except BaseException:
        _names_restore_name(context, request, before)
        raise
    return _names_NameMutationResult(address=hex(ea), name=after, changed=True)


def _names_restore_name(
    context: OperationContext,
    request: _names_NameSetRequest,
    before: _names_NameState,
) -> None:
    runtime = context.runtime
    ida_name = runtime.mod("ida_name")
    ea = runtime.resolve_address(request.identifier)
    if not ida_name.set_name(ea, before.name, ida_name.SN_CHECK):
        raise IdaOperationError(f"failed to restore name at {hex(ea)}")


# ---- Local-variable operations ----


@dataclass(frozen=True)
class _locals_LocalSelector:
    name: str | None = None
    local_id: str | None = None
    index: int | None = None

    def stable_selector(self) -> tuple[str, Any] | None:
        if self.local_id is not None:
            return ("local_id", self.local_id)
        if self.index is not None:
            return ("index", self.index)
        return None


@dataclass(frozen=True)
class _locals_LocalListRequest:
    identifier: str


@dataclass(frozen=True)
class _locals_LocalRenameRequest:
    identifier: str
    selector: _locals_LocalSelector
    new_name: str


@dataclass(frozen=True)
class _locals_LocalRetypeRequest:
    identifier: str
    selector: _locals_LocalSelector
    decl: str


@dataclass(frozen=True)
class _locals_LocalUpdateRequest:
    identifier: str
    selector: _locals_LocalSelector
    new_name: str | None = None
    decl: str | None = None


@dataclass(frozen=True)
class _locals_LocalPlanItem:
    selector: _locals_LocalSelector
    new_name: str | None = None
    decl: str | None = None
    type_text: str | None = None


@dataclass(frozen=True)
class _locals_LocalApplyPlanRequest:
    identifier: str
    items: tuple[_locals_LocalPlanItem, ...]


@dataclass(frozen=True)
class _locals_LocalRow:
    index: int
    local_id: str
    definition_address: str
    location: str
    name: str
    display_name: str
    type: str
    is_arg: bool
    is_stack: bool
    stack_offset: int | None
    size: int


@dataclass(frozen=True)
class _locals_LocalListResult:
    function: str
    address: str
    locals: tuple[_locals_LocalRow, ...]


@dataclass(frozen=True)
class _locals_LocalMutationResult:
    function: str
    address: str
    locals: tuple[_locals_LocalRow, ...]
    changed: bool


@dataclass(frozen=True)
class _locals_AppliedLocalPlanItem:
    index: int
    local_id: str
    old_name: str
    new_name: str | None
    decl: str | None


@dataclass(frozen=True)
class _locals_LocalApplyPlanResult:
    function: str
    address: str
    locals: tuple[_locals_LocalRow, ...]
    changed: bool
    applied: tuple[_locals_AppliedLocalPlanItem, ...]


@dataclass(frozen=True)
class _locals_SelectedLocal:
    name: str
    locator: Any
    display_name: str | None = None
    index: int | None = None
    local_id: str | None = None

    def label(self) -> str:
        return self.display_name or self.name or "<unnamed local>"


_locals_LOCAL_ID_NEW_RE = re.compile(
    "^(?P<kind>stack|reg|regpair)\\((?P<body>[^)]*)\\)@(?P<defea>0x[0-9a-fA-F]+|\\d+)$", re.IGNORECASE
)
_locals_LOCAL_SELECTOR_GUIDANCE = (
    "list locals again to confirm current names and prefer a stable selector such as local_id or index"
)


def _locals_parse_local_selector(params: Mapping[str, Any], *, name_key: str) -> _locals_LocalSelector:
    name = str(params.get(name_key) or "").strip() or None
    local_id = str(params.get("local_id") or "").strip() or None
    index = optional_param_int(params, "index", label="local index", minimum=0)
    stable_count = sum(value is not None for value in (local_id, index))
    if name is None and stable_count == 0:
        raise IdaOperationError(f"local selector is required via {name_key}, local_id, or index")
    if stable_count > 1:
        raise IdaOperationError("--local-id and --index are mutually exclusive; got: local_id, index")
    return _locals_LocalSelector(name=name, local_id=local_id, index=index)


def _locals_parse_local_list(params: Mapping[str, Any]) -> _locals_LocalListRequest:
    return _locals_LocalListRequest(identifier=require_str(params.get("identifier"), field="address or identifier"))


def _locals_parse_local_rename(params: Mapping[str, Any]) -> _locals_LocalRenameRequest:
    new_name = str(params.get("new_name") or "")
    if not new_name:
        raise IdaOperationError("new local variable name is required")
    return _locals_LocalRenameRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        selector=_locals_parse_local_selector(params, name_key="old_name"),
        new_name=new_name,
    )


def _locals_parse_local_retype(params: Mapping[str, Any]) -> _locals_LocalRetypeRequest:
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("local variable declaration is required")
    return _locals_LocalRetypeRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        selector=_locals_parse_local_selector(params, name_key="local_name"),
        decl=decl,
    )


def _locals_parse_local_update(params: Mapping[str, Any]) -> _locals_LocalUpdateRequest:
    new_name = str(params.get("new_name") or "").strip() or None
    decl = str(params.get("decl") or "").strip() or None
    if new_name is None and decl is None:
        raise IdaOperationError("at least one of new_name or decl is required")
    return _locals_LocalUpdateRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        selector=_locals_parse_local_selector(params, name_key="local_name"),
        new_name=new_name,
        decl=decl,
    )


def _locals_local_plan_selector(raw: Mapping[Any, Any], *, index: int) -> _locals_LocalSelector:
    name = str(raw.get("name") or "").strip() or None
    local_id = str(raw.get("local_id") or "").strip() or None
    raw_index = raw.get("index")
    try:
        local_index = None if raw_index in (None, "") else parse_int_text(raw_index, label="local index", minimum=0)
    except ValueError as exc:
        raise IdaOperationError(f"local apply item {index}: {exc}") from exc
    stable_count = sum(value is not None for value in (local_id, local_index))
    if name is None and stable_count == 0:
        raise IdaOperationError(f"local apply item {index}: selector is required via local_id, index, or name")
    if stable_count > 1:
        raise IdaOperationError(f"local apply item {index}: local_id and index are mutually exclusive")
    if name is not None and stable_count > 0:
        raise IdaOperationError(f"local apply item {index}: do not combine name with local_id or index")
    return _locals_LocalSelector(name=name, local_id=local_id, index=local_index)


def _locals_parse_local_apply_plan(params: Mapping[str, Any]) -> _locals_LocalApplyPlanRequest:
    raw_items = params.get("items")
    if not isinstance(raw_items, list):
        raise IdaOperationError("local apply requires a JSON list of item objects")
    if not raw_items:
        raise IdaOperationError("local apply requires at least one item")
    items: list[_locals_LocalPlanItem] = []
    for item_index, raw in enumerate(raw_items, start=1):
        if not isinstance(raw, dict):
            raise IdaOperationError(f"local apply item {item_index}: expected object")
        unsupported_fields = set(raw) - {"name", "local_id", "index", "rename", "decl", "type"}
        if unsupported_fields:
            fields_text = ", ".join(sorted(str(field) for field in unsupported_fields))
            raise IdaOperationError(f"local apply item {item_index}: unsupported field(s): {fields_text}")
        new_name = str(raw.get("rename") or "").strip() or None
        decl = str(raw.get("decl") or "").strip() or None
        type_text = str(raw.get("type") or "").strip() or None
        if decl is not None and type_text is not None:
            raise IdaOperationError(f"local apply item {item_index}: use either decl or type, not both")
        if new_name is None and decl is None and (type_text is None):
            raise IdaOperationError(f"local apply item {item_index}: at least one of rename, decl, or type is required")
        items.append(
            _locals_LocalPlanItem(
                selector=_locals_local_plan_selector(raw, index=item_index),
                new_name=new_name,
                decl=decl,
                type_text=type_text,
            )
        )
    return _locals_LocalApplyPlanRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        items=tuple(items),
    )


def _locals_vdloc_text(location) -> str:
    if location.is_stkoff():
        return f"stack({location.stkoff()})"
    if location.is_reg1():
        return f"reg({location.reg1()})"
    if location.is_reg2():
        return f"regpair({location.reg1()},{location.reg2()})"
    return "unknown"


def _locals_local_identity(lvar) -> tuple[str, str, str]:
    definition_address = hex(lvar.defea)
    location = _locals_vdloc_text(lvar.location)
    return (definition_address, location, f"{location}@{definition_address}")


def _locals_safe_local_id(lvar) -> str:
    try:
        return _locals_local_identity(lvar)[2]
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise
        return ""


def _locals_normalize_local_location_text(text: str) -> str:
    value = str(text).strip()
    match = re.fullmatch("(?P<kind>stack|reg|regpair)\\((?P<body>[^)]*)\\)", value, re.IGNORECASE)
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


def _locals_normalize_local_id_text(local_id: str) -> str:
    text = str(local_id).strip()
    match = _locals_LOCAL_ID_NEW_RE.match(text)
    if match:
        defea_text = match.group("defea")
        with contextlib.suppress(ValueError):
            defea_text = hex(int(defea_text, 0))
        location_text = _locals_normalize_local_location_text(f"{match.group('kind')}({match.group('body')})")
        return f"{location_text}@{defea_text}"
    return text


def _locals_parse_var_decl(runtime: IdaRuntime, decl: str, *, error_message: str):
    tif = runtime.ida_typeinf.tinfo_t()
    parse_text = decl.strip()
    if not parse_text.endswith(";"):
        parse_text += ";"
    parse_flags = runtime.ida_typeinf.PT_VAR | runtime.ida_typeinf.PT_SIL | runtime.ida_typeinf.PT_SEMICOLON
    if not runtime.ida_typeinf.parse_decl(tif, None, parse_text, parse_flags):
        raise IdaOperationError(error_message)
    return tif


def _locals_decompile_locals(runtime: IdaRuntime, func_ea: int, *, action: str):
    cfunc = runtime.require_hexrays().decompile(func_ea)
    if cfunc is None:
        raise IdaOperationError(f"failed to {action} for {hex(func_ea)}")
    return cfunc


def _locals_lvar_locator(runtime: IdaRuntime, lvar):
    locator = runtime.require_hexrays().lvar_locator_t()
    locator.defea = lvar.defea
    locator.location = lvar.location
    return locator


def _locals_local_row(runtime: IdaRuntime, index: int, lvar, saved) -> _locals_LocalRow:
    stack_offset = None
    if lvar.is_stk_var():
        with suppress_recoverable_ida_errors():
            stack_offset = lvar.get_stkoff()
    definition_address, location, local_id = _locals_local_identity(lvar)
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
    return _locals_LocalRow(
        index=index,
        local_id=local_id,
        definition_address=definition_address,
        location=location,
        name=name,
        display_name=name or f"<unnamed_{index}>",
        type=type_text,
        is_arg=lvar.is_arg_var,
        is_stack=lvar.is_stk_var(),
        stack_offset=stack_offset,
        size=lvar.width,
    )


def _locals_local_rows(runtime: IdaRuntime, func_ea: int) -> tuple[_locals_LocalRow, ...]:
    ida_hexrays = runtime.require_hexrays()
    cfunc = _locals_decompile_locals(runtime, func_ea, action="inspect locals")
    user_rows: dict[tuple[int, str], Any] = {}
    user_info = ida_hexrays.lvar_uservec_t()
    if ida_hexrays.restore_user_lvar_settings(user_info, func_ea):
        for saved in user_info.lvvec:
            user_rows[saved.ll.defea, _locals_vdloc_text(saved.ll.location)] = saved
    rows: list[_locals_LocalRow] = []
    for index, lvar in enumerate(cfunc.get_lvars()):
        saved = user_rows.get((lvar.defea, _locals_vdloc_text(lvar.location)))
        rows.append(_locals_local_row(runtime, index, lvar, saved))
    return tuple(rows)


def _locals_local_list_result(runtime: IdaRuntime, func_ea: int) -> _locals_LocalListResult:
    return _locals_LocalListResult(
        function=runtime.function_name(func_ea), address=hex(func_ea), locals=_locals_local_rows(runtime, func_ea)
    )


def _locals_stable_local_matches(
    lvars: list[Any], *, selector_name: str, selector_value: Any
) -> tuple[list[tuple[int, Any]], str]:
    if selector_name == "local_id":
        normalized_local_id = _locals_normalize_local_id_text(str(selector_value))
        matches = [
            (index, lvar)
            for index, lvar in enumerate(lvars)
            if _locals_normalize_local_id_text(_locals_local_identity(lvar)[2]) == normalized_local_id
        ]
        return (matches, f"local id `{selector_value}`")
    matches = [(index, lvar) for index, lvar in enumerate(lvars) if index == selector_value]
    return (matches, f"local index {selector_value}")


def _locals_resolve_lvar_by_name(runtime: IdaRuntime, func_ea: int, name: str):
    local_name = name.strip()
    if not local_name:
        raise IdaOperationError("local variable name is required")
    locator = runtime.require_hexrays().lvar_locator_t()
    if not runtime.require_hexrays().locate_lvar(locator, func_ea, local_name):
        raise IdaOperationError(
            f"local variable not found: {local_name}; {_locals_LOCAL_SELECTOR_GUIDANCE}"
            f"{_locals_available_locals_suffix(runtime, func_ea)}"
        )
    return locator


def _locals_select_local(runtime: IdaRuntime, func_ea: int, selector: _locals_LocalSelector) -> _locals_SelectedLocal:
    stable = selector.stable_selector()
    if stable is None:
        if selector.name is None:
            raise IdaOperationError("local selector name is required")
        resolved_name = selector.name.strip()
        return _locals_SelectedLocal(
            name=resolved_name,
            locator=_locals_resolve_lvar_by_name(runtime, func_ea, resolved_name),
            display_name=resolved_name,
        )
    selector_name, selector_value = stable
    cfunc = _locals_decompile_locals(runtime, func_ea, action="inspect locals")
    matches, label = _locals_stable_local_matches(
        list(cfunc.get_lvars()), selector_name=selector_name, selector_value=selector_value
    )
    if not matches:
        raise IdaOperationError(
            f"local variable not found for {label}; {_locals_LOCAL_SELECTOR_GUIDANCE}"
            f"{_locals_available_locals_suffix(runtime, func_ea)}"
        )
    if len(matches) > 1:
        raise IdaOperationError(f"multiple locals matched {label}; use local_id or index instead")
    index, lvar = matches[0]
    resolved_name = lvar.name or ""
    return _locals_SelectedLocal(
        name=resolved_name,
        locator=_locals_lvar_locator(runtime, lvar),
        display_name=resolved_name or f"<unnamed_{index}>",
        index=index,
        local_id=_locals_safe_local_id(lvar),
    )


def _locals_select_local_from_lvars(
    runtime: IdaRuntime, func_ea: int, lvars: list[Any], selector: _locals_LocalSelector
) -> _locals_SelectedLocal:
    stable = selector.stable_selector()
    if stable is None:
        if selector.name is None:
            raise IdaOperationError("local selector name is required")
        name = selector.name.strip()
        matches = [(index, lvar) for index, lvar in enumerate(lvars) if str(lvar.name or "") == name]
        label = f"local name `{name}`"
    else:
        selector_name, selector_value = stable
        matches, label = _locals_stable_local_matches(lvars, selector_name=selector_name, selector_value=selector_value)
    if not matches:
        raise IdaOperationError(
            f"local variable not found for {label}; {_locals_LOCAL_SELECTOR_GUIDANCE}"
            f"{_locals_available_locals_suffix(runtime, func_ea)}"
        )
    if len(matches) > 1:
        raise IdaOperationError(f"multiple locals matched {label}; use local_id or index instead")
    index, lvar = matches[0]
    name = str(lvar.name or "")
    return _locals_SelectedLocal(
        name=name,
        locator=_locals_lvar_locator(runtime, lvar),
        display_name=name or f"<unnamed_{index}>",
        index=index,
        local_id=_locals_safe_local_id(lvar),
    )


def _locals_available_locals_suffix(runtime: IdaRuntime, func_ea: int) -> str:
    try:
        rows = _locals_local_rows(runtime, func_ea)
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise
        return ""
    if not rows:
        return ""
    rendered: list[str] = []
    for row in rows[:12]:
        name = row.display_name or row.name or f"<unnamed_{row.index}>"
        rendered.append(f"#{row.index} {name} ({row.local_id})")
    suffix = "; available locals: " + ", ".join(rendered)
    if len(rows) > 12:
        suffix += f", ... {len(rows) - 12} more"
    return suffix


def _locals_local_saved_info(runtime: IdaRuntime, locator):
    info = runtime.require_hexrays().lvar_saved_info_t()
    info.ll = locator
    return info


def _locals_readback_local_change(
    runtime: IdaRuntime, func_ea: int, *, success_message: str
) -> _locals_LocalMutationResult:
    try:
        refreshed = _locals_local_list_result(runtime, func_ea)
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"{success_message} but failed to read back locals: {detail}") from exc
    return _locals_LocalMutationResult(
        function=refreshed.function, address=refreshed.address, locals=refreshed.locals, changed=True
    )


def _locals_dirty_local_cfunc(runtime: IdaRuntime, func_ea: int) -> None:
    ida_hexrays = runtime.require_hexrays()
    with suppress_recoverable_ida_errors():
        ida_hexrays.mark_cfunc_dirty(func_ea, False)
        ida_hexrays.clear_cached_cfuncs()


def _locals_apply_local_change(
    runtime: IdaRuntime, func_ea: int, info, *, modify_flag: int, failure_message: str, success_message: str
) -> _locals_LocalMutationResult:
    if not runtime.require_hexrays().modify_user_lvar_info(func_ea, modify_flag, info):
        raise IdaOperationError(failure_message)
    _locals_dirty_local_cfunc(runtime, func_ea)
    return _locals_readback_local_change(runtime, func_ea, success_message=success_message)


def _locals_cleanup_local_preview(
    context: OperationContext,
    request: _locals_LocalRenameRequest
    | _locals_LocalRetypeRequest
    | _locals_LocalUpdateRequest
    | _locals_LocalApplyPlanRequest,
) -> None:
    runtime = context.runtime
    try:
        func_ea = runtime.function_ea(request.identifier)
        _locals_dirty_local_cfunc(runtime, func_ea)
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise


def _locals_local_list(
    context: OperationContext,
    request: _locals_LocalListRequest
    | _locals_LocalRenameRequest
    | _locals_LocalRetypeRequest
    | _locals_LocalUpdateRequest
    | _locals_LocalApplyPlanRequest,
) -> _locals_LocalListResult:
    runtime = context.runtime
    func_ea = runtime.function_ea(request.identifier)
    return _locals_local_list_result(runtime, func_ea)


def _locals_local_rename(context: OperationContext, request: _locals_LocalRenameRequest) -> _locals_LocalMutationResult:
    runtime = context.runtime
    func_ea = runtime.function_ea(request.identifier)
    selected = _locals_select_local(runtime, func_ea, request.selector)
    failure_message = f"failed to rename local variable: {selected.label()}"
    success_message = f"renamed local variable `{selected.label()}` to `{request.new_name}`"
    info = _locals_local_saved_info(runtime, selected.locator)
    info.name = request.new_name
    return _locals_apply_local_change(
        runtime,
        func_ea,
        info,
        modify_flag=runtime.require_hexrays().MLI_NAME,
        failure_message=failure_message,
        success_message=success_message,
    )


def _locals_local_retype(context: OperationContext, request: _locals_LocalRetypeRequest) -> _locals_LocalMutationResult:
    runtime = context.runtime
    func_ea = runtime.function_ea(request.identifier)
    selected = _locals_select_local(runtime, func_ea, request.selector)
    info = _locals_local_saved_info(runtime, selected.locator)
    info.name = selected.name
    info.type = _locals_parse_var_decl(
        runtime, request.decl, error_message=f"failed to parse local variable declaration: {request.decl}"
    )
    return _locals_apply_local_change(
        runtime,
        func_ea,
        info,
        modify_flag=runtime.require_hexrays().MLI_TYPE,
        failure_message=f"failed to update local variable type: {selected.label()}",
        success_message=f"updated local variable type for `{selected.label()}`",
    )


def _locals_local_update(context: OperationContext, request: _locals_LocalUpdateRequest) -> _locals_LocalMutationResult:
    runtime = context.runtime
    func_ea = runtime.function_ea(request.identifier)
    selected = _locals_select_local(runtime, func_ea, request.selector)
    info = _locals_local_saved_info(runtime, selected.locator)
    modify_flag = 0
    if request.new_name is not None:
        info.name = request.new_name
        modify_flag |= runtime.require_hexrays().MLI_NAME
    if request.decl is not None:
        info.name = request.new_name or selected.name
        info.type = _locals_parse_var_decl(
            runtime, request.decl, error_message=f"failed to parse local variable declaration: {request.decl}"
        )
        modify_flag |= runtime.require_hexrays().MLI_TYPE
    success_message_parts: list[str] = []
    if request.new_name is not None:
        success_message_parts.append(f"renamed local variable `{selected.label()}` to `{request.new_name}`")
    if request.decl is not None:
        success_message_parts.append(f"updated local variable type for `{request.new_name or selected.label()}`")
    return _locals_apply_local_change(
        runtime,
        func_ea,
        info,
        modify_flag=modify_flag,
        failure_message=f"failed to update local variable: {selected.label()}",
        success_message=" and ".join(success_message_parts),
    )


def _locals_decl_for_plan_item(item: _locals_LocalPlanItem, selected: _locals_SelectedLocal) -> str | None:
    if item.decl is not None:
        return item.decl
    if item.type_text is None:
        return None
    name = item.new_name or selected.name
    if not name:
        raise IdaOperationError("local apply type entries for unnamed locals require a rename or full decl")
    return f"{item.type_text.rstrip(';')} {name};"


def _locals_local_apply_plan(
    context: OperationContext, request: _locals_LocalApplyPlanRequest
) -> _locals_LocalApplyPlanResult:
    runtime = context.runtime
    ida_hexrays = runtime.require_hexrays()
    func_ea = runtime.function_ea(request.identifier)
    cfunc = _locals_decompile_locals(runtime, func_ea, action="inspect locals")
    lvars = list(cfunc.get_lvars())
    prepared: list[tuple[_locals_SelectedLocal, Any, int, _locals_LocalPlanItem, str | None]] = []
    for item in request.items:
        selected = _locals_select_local_from_lvars(runtime, func_ea, lvars, item.selector)
        info = _locals_local_saved_info(runtime, selected.locator)
        modify_flag = 0
        if item.new_name is not None:
            info.name = item.new_name
            modify_flag |= ida_hexrays.MLI_NAME
        decl = _locals_decl_for_plan_item(item, selected)
        if decl is not None:
            info.name = item.new_name or selected.name
            info.type = _locals_parse_var_decl(
                runtime, decl, error_message=f"failed to parse local variable declaration: {decl}"
            )
            modify_flag |= ida_hexrays.MLI_TYPE
        prepared.append((selected, info, modify_flag, item, decl))
    applied: list[_locals_AppliedLocalPlanItem] = []
    for selected, info, modify_flag, item, decl in prepared:
        if not ida_hexrays.modify_user_lvar_info(func_ea, modify_flag, info):
            raise IdaOperationError(f"failed to apply local plan item for `{selected.label()}`")
        applied.append(
            _locals_AppliedLocalPlanItem(
                index=-1 if selected.index is None else selected.index,
                local_id=selected.local_id or "",
                old_name=selected.name,
                new_name=item.new_name,
                decl=decl,
            )
        )
    _locals_dirty_local_cfunc(runtime, func_ea)
    try:
        refreshed = _locals_local_list_result(runtime, func_ea)
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"applied local plan but failed to read back locals: {detail}") from exc
    return _locals_LocalApplyPlanResult(
        function=refreshed.function,
        address=refreshed.address,
        locals=refreshed.locals,
        changed=True,
        applied=tuple(applied),
    )


# ---- Prototype operations ----


_prototypes_PROTO_BUILTIN_TOKENS = frozenset(
    {
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
)


@dataclass(frozen=True)
class _prototypes_PrototypeGetRequest:
    identifier: str


@dataclass(frozen=True)
class _prototypes_PrototypeSetRequest:
    identifier: str
    decl: str
    preview_decompile: bool = False
    propagate_callers: bool = False


@dataclass(frozen=True)
class _prototypes_PrototypeCheckRequest:
    identifier: str
    decl: str


@dataclass(frozen=True)
class _prototypes_PrototypeView:
    address: str
    prototype: str


@dataclass(frozen=True)
class _prototypes_PrototypePreviewView:
    address: str
    prototype: str
    decompile: str


@dataclass(frozen=True)
class _prototypes_PrototypePreviewErrorView:
    address: str
    prototype: str
    decompile: None
    decompile_error: str


@dataclass(frozen=True)
class _prototypes_PrototypeMutationResult:
    address: str
    prototype: str
    changed: bool
    callers_considered: int = 0
    callers_updated: int = 0
    callers_failed: int = 0


@dataclass(frozen=True)
class _prototypes_PrototypeCheckResult:
    address: str
    success: bool
    parsed: bool
    is_function: bool
    arglocs_calculated: bool | None
    unknown_types: tuple[str, ...]
    diagnostics: tuple[str, ...]


def _prototypes_parse_proto_get(params: Mapping[str, Any]) -> _prototypes_PrototypeGetRequest:
    return _prototypes_PrototypeGetRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier")
    )


def _prototypes_parse_proto_set(params: Mapping[str, Any]) -> _prototypes_PrototypeSetRequest:
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("prototype declaration is required")
    return _prototypes_PrototypeSetRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        decl=decl,
        preview_decompile=bool(params.get("preview_decompile")),
        propagate_callers=bool(params.get("propagate_callers")),
    )


def _prototypes_parse_proto_check(params: Mapping[str, Any]) -> _prototypes_PrototypeCheckRequest:
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("prototype declaration is required")
    return _prototypes_PrototypeCheckRequest(
        identifier=require_str(params.get("identifier"), field="address or identifier"),
        decl=decl,
    )


def _prototypes_prototype_view(
    context: OperationContext, request: _prototypes_PrototypeGetRequest | _prototypes_PrototypeSetRequest
) -> _prototypes_PrototypeView | _prototypes_PrototypePreviewView | _prototypes_PrototypePreviewErrorView:
    runtime = context.runtime
    ea = runtime.function_ea(request.identifier)
    prototype = runtime.ida_typeinf.print_type(ea, runtime.ida_typeinf.PRTYPE_1LINE) or ""
    if not isinstance(request, _prototypes_PrototypeSetRequest) or not request.preview_decompile:
        return _prototypes_PrototypeView(address=hex(ea), prototype=prototype)
    try:
        cfunc = runtime.require_hexrays().decompile(ea)
        if cfunc is None:
            raise IdaOperationError(f"failed to decompile function at {hex(ea)}")
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        return _prototypes_PrototypePreviewErrorView(
            address=hex(ea), prototype=prototype, decompile=None, decompile_error=detail
        )
    return _prototypes_PrototypePreviewView(
        address=hex(ea), prototype=prototype, decompile=runtime.pseudocode_text(cfunc)
    )


def _prototypes_propagate_callee_tinfo(runtime: IdaRuntime, callee_ea: int, tif) -> tuple[int, int, int]:
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
    return (callers_considered, callers_updated, callers_failed)


def _prototypes_unknown_proto_types(runtime: IdaRuntime, decl: str) -> list[str]:
    working = decl.strip().rstrip(";")
    working = re.sub("@<[^>]+>", "", working)
    header, _, params_text = working.partition("(")
    param_chunks = [" ".join(header.split()[:-1])]
    if params_text:
        params_body = params_text.rsplit(")", 1)[0]
        for raw_param in params_body.split(","):
            segment = raw_param.strip()
            if not segment or segment == "void":
                continue
            param_name = re.search("([A-Za-z_][A-Za-z0-9_]*)\\s*$", segment)
            if param_name:
                segment = segment[: param_name.start()].strip()
            param_chunks.append(segment)
    unknown: list[str] = []
    seen: set[str] = set()
    for chunk in param_chunks:
        for token in re.findall("[A-Za-z_][A-Za-z0-9_]*", chunk):
            if token in _prototypes_PROTO_BUILTIN_TOKENS or token in seen or runtime.find_named_type(token) is not None:
                continue
            seen.add(token)
            unknown.append(token)
    return unknown


def _prototypes_parse_prototype_decl(runtime: IdaRuntime, decl: str):
    ida_typeinf = runtime.ida_typeinf
    parse_text = decl.strip()
    if not parse_text.endswith(";"):
        parse_text += ";"
    parse_flags = ida_typeinf.PT_VAR | ida_typeinf.PT_SIL | ida_typeinf.PT_SEMICOLON
    if "::" in parse_text:
        parse_flags |= ida_typeinf.PT_RELAXED
    tif = ida_typeinf.tinfo_t()
    return tif if ida_typeinf.parse_decl(tif, None, parse_text, parse_flags) else None


def _prototypes_prototype_arglocs_ok(runtime: IdaRuntime, tif) -> bool:
    if not tif.is_func():
        return False
    ida_typeinf = runtime.ida_typeinf
    details = ida_typeinf.func_type_data_t()
    return bool(tif.get_func_details(details, ida_typeinf.GTD_CALC_ARGLOCS))


def _prototypes_mark_prototype_dirty(runtime: IdaRuntime, ea: int, *, include_callers: bool) -> None:
    try:
        ida_hexrays = runtime.require_hexrays()
    except Exception:
        return
    with suppress_recoverable_ida_errors():
        ida_hexrays.mark_cfunc_dirty(ea, False)
        if include_callers:
            for ref in runtime.idautils.CodeRefsTo(ea, 0):
                caller = runtime.ida_funcs.get_func(ref)
                if caller is not None:
                    ida_hexrays.mark_cfunc_dirty(caller.start_ea, False)
        ida_hexrays.clear_cached_cfuncs()


def _prototypes_proto_get(
    context: OperationContext, request: _prototypes_PrototypeGetRequest
) -> _prototypes_PrototypeView:
    viewed = _prototypes_prototype_view(context, request)
    if isinstance(viewed, _prototypes_PrototypeView):
        return viewed
    raise IdaOperationError("internal error: expected a prototype view for proto_get")


def _prototypes_proto_check(
    context: OperationContext, request: _prototypes_PrototypeCheckRequest
) -> _prototypes_PrototypeCheckResult:
    runtime = context.runtime
    ea = runtime.function_ea(request.identifier)
    unknown_types = tuple(_prototypes_unknown_proto_types(runtime, request.decl))
    diagnostics: list[str] = []
    tif = _prototypes_parse_prototype_decl(runtime, request.decl)
    parsed = tif is not None
    is_function = False
    arglocs_calculated: bool | None = None
    if tif is None:
        if unknown_types:
            diagnostics.append("unknown type(s): " + ", ".join(unknown_types))
        else:
            diagnostics.append("IDA failed to parse the prototype declaration")
    else:
        is_function = bool(tif.is_func())
        if not is_function:
            diagnostics.append("declaration parsed but did not produce a function type")
        arglocs_calculated = _prototypes_prototype_arglocs_ok(runtime, tif)
        if arglocs_calculated is False:
            diagnostics.append("IDA could not calculate function argument locations")
    return _prototypes_PrototypeCheckResult(
        address=hex(ea),
        success=parsed and is_function and (arglocs_calculated is not False),
        parsed=parsed,
        is_function=is_function,
        arglocs_calculated=arglocs_calculated,
        unknown_types=unknown_types,
        diagnostics=tuple(diagnostics),
    )


def _prototypes_proto_set(
    context: OperationContext, request: _prototypes_PrototypeSetRequest
) -> _prototypes_PrototypeMutationResult:
    runtime = context.runtime
    ea = runtime.function_ea(request.identifier)
    decl = request.decl
    original_name = runtime.ida_name.get_name(ea) or ""
    unknown_types = _prototypes_unknown_proto_types(runtime, decl)
    tif = _prototypes_parse_prototype_decl(runtime, decl)
    if tif is None:
        if unknown_types:
            rendered = ", ".join(unknown_types)
            raise IdaOperationError(f"failed to apply prototype at {hex(ea)}; unknown type(s): {rendered}")
        current_prototype = runtime.ida_typeinf.print_type(ea, runtime.ida_typeinf.PRTYPE_1LINE) or ""
        raise IdaOperationError(
            f"failed to apply prototype at {hex(ea)}; current prototype: {current_prototype or '<unknown>'}; "
            "check declaration syntax, parser limitations, missing support types, and retry after "
            "`function prototype show`"
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
        callers_considered, callers_updated, callers_failed = _prototypes_propagate_callee_tinfo(runtime, ea, tif)
    _prototypes_mark_prototype_dirty(runtime, ea, include_callers=request.propagate_callers)
    normalized_decl = decl if decl.endswith(";") else f"{decl};"
    if original_name and re.search("~[A-Za-z_][A-Za-z0-9_]*\\s*\\(", normalized_decl):
        current_name = runtime.ida_name.get_name(ea) or ""
        if current_name and current_name != original_name:
            with suppress_recoverable_ida_errors():
                runtime.ida_name.set_name(ea, original_name, runtime.ida_name.SN_CHECK)
    return _prototypes_PrototypeMutationResult(
        address=hex(ea),
        prototype=runtime.ida_typeinf.print_type(ea, runtime.ida_typeinf.PRTYPE_1LINE) or "",
        changed=True,
        callers_considered=callers_considered,
        callers_updated=callers_updated,
        callers_failed=callers_failed,
    )


# ---- Named-type operations ----


@dataclass(frozen=True)
class _named_types_NamedTypeListRequest:
    pattern: str | None
    regex: bool
    ignore_case: bool


@dataclass(frozen=True)
class _named_types_NamedTypeShowRequest:
    name: str


@dataclass(frozen=True)
class _named_types_NamedTypeDepsResult:
    name: str
    kind: str
    decl: str
    dependencies_included: bool


@dataclass(frozen=True)
class _named_types_StructFieldSetRequest:
    struct_name: str
    field_name: str
    decl: str
    offset: int


@dataclass(frozen=True)
class _named_types_StructFieldRenameRequest:
    struct_name: str
    field_name: str
    new_name: str


@dataclass(frozen=True)
class _named_types_StructFieldDeleteRequest:
    struct_name: str
    field_name: str


@dataclass(frozen=True)
class _named_types_EnumMemberSetRequest:
    enum_name: str
    member_name: str
    value: int
    mask: int | None


@dataclass(frozen=True)
class _named_types_EnumMemberRenameRequest:
    enum_name: str
    member_name: str
    new_name: str


@dataclass(frozen=True)
class _named_types_EnumMemberDeleteRequest:
    enum_name: str
    member_name: str


@dataclass(frozen=True)
class _named_types_NamedTypeEntry:
    name: str
    kind: str
    decl: str


@dataclass(frozen=True)
class _named_types_StructMember:
    index: int
    name: str | None
    offset_bits: int
    offset: int
    size_bits: int
    size: int | None
    type: str
    comment: str


@dataclass(frozen=True)
class _named_types_EnumMember:
    index: int
    name: str | None
    value: int
    value_hex: str
    comment: str


@dataclass(frozen=True)
class _named_types_NamedTypeView:
    name: str
    kind: str
    size: int | None
    size_known: bool
    decl: str


@dataclass(frozen=True)
class _named_types_StructuredTypeView:
    name: str
    kind: str
    size: int | None
    size_known: bool
    decl: str
    layout: str
    members: tuple[_named_types_StructMember, ...]


@dataclass(frozen=True)
class _named_types_EnumTypeView:
    name: str
    kind: str
    size: int | None
    size_known: bool
    decl: str
    members: tuple[_named_types_EnumMember, ...]


@dataclass(frozen=True)
class _named_types_StructView:
    name: str
    kind: str
    layout: str
    members: tuple[_named_types_StructMember, ...]


@dataclass(frozen=True)
class _named_types_StructMutationResult:
    name: str
    kind: str
    layout: str
    members: tuple[_named_types_StructMember, ...]
    changed: bool


@dataclass(frozen=True)
class _named_types_EnumView:
    name: str
    kind: str
    decl: str
    members: tuple[_named_types_EnumMember, ...]


@dataclass(frozen=True)
class _named_types_EnumMutationResult:
    name: str
    kind: str
    decl: str
    members: tuple[_named_types_EnumMember, ...]
    changed: bool


_named_types_UNKNOWN_TINFO_SIZE_THRESHOLD = 1 << 63


def _named_types_require_name(
    params: Mapping[str, Any], *, key: str = "name", message: str = "type name is required"
) -> str:
    value = str(params.get(key) or "").strip()
    if not value:
        raise IdaOperationError(message)
    return value


def _named_types_parse_list(params: Mapping[str, Any]) -> _named_types_NamedTypeListRequest:
    pattern = str(params.get("pattern") or "").strip() or None
    return _named_types_NamedTypeListRequest(
        pattern=pattern,
        regex=bool(params.get("regex")),
        ignore_case=bool(params.get("ignore_case")),
    )


def _named_types_parse_show(params: Mapping[str, Any]) -> _named_types_NamedTypeShowRequest:
    return _named_types_NamedTypeShowRequest(name=_named_types_require_name(params))


def _named_types_parse_struct_show(params: Mapping[str, Any]) -> _named_types_NamedTypeShowRequest:
    return _named_types_NamedTypeShowRequest(name=_named_types_require_name(params, message="struct name is required"))


def _named_types_parse_enum_show(params: Mapping[str, Any]) -> _named_types_NamedTypeShowRequest:
    return _named_types_NamedTypeShowRequest(name=_named_types_require_name(params, message="enum name is required"))


def _named_types_parse_struct_field_set(params: Mapping[str, Any]) -> _named_types_StructFieldSetRequest:
    struct_name = _named_types_require_name(params, key="struct_name", message="struct name is required")
    field_name = _named_types_require_name(params, key="field_name", message="field name is required")
    decl = str(params.get("decl") or "")
    if not decl:
        raise IdaOperationError("struct field declaration is required")
    offset = param_int(params, "offset", label="struct field offset", minimum=0)
    return _named_types_StructFieldSetRequest(struct_name=struct_name, field_name=field_name, decl=decl, offset=offset)


def _named_types_parse_struct_field_rename(params: Mapping[str, Any]) -> _named_types_StructFieldRenameRequest:
    return _named_types_StructFieldRenameRequest(
        struct_name=_named_types_require_name(params, key="struct_name", message="struct name is required"),
        field_name=_named_types_require_name(params, key="field_name", message="field name is required"),
        new_name=_named_types_require_name(params, key="new_name", message="new field name is required"),
    )


def _named_types_parse_struct_field_delete(params: Mapping[str, Any]) -> _named_types_StructFieldDeleteRequest:
    return _named_types_StructFieldDeleteRequest(
        struct_name=_named_types_require_name(params, key="struct_name", message="struct name is required"),
        field_name=_named_types_require_name(params, key="field_name", message="field name is required"),
    )


def _named_types_parse_enum_member_set(params: Mapping[str, Any]) -> _named_types_EnumMemberSetRequest:
    return _named_types_EnumMemberSetRequest(
        enum_name=_named_types_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_named_types_require_name(params, key="member_name", message="enum member name is required"),
        value=param_int(params, "value", label="enum member value"),
        mask=None if params.get("mask") in (None, "") else optional_param_int(params, "mask", label="enum member mask"),
    )


def _named_types_parse_enum_member_rename(params: Mapping[str, Any]) -> _named_types_EnumMemberRenameRequest:
    return _named_types_EnumMemberRenameRequest(
        enum_name=_named_types_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_named_types_require_name(params, key="member_name", message="enum member name is required"),
        new_name=_named_types_require_name(params, key="new_name", message="new enum member name is required"),
    )


def _named_types_parse_enum_member_delete(params: Mapping[str, Any]) -> _named_types_EnumMemberDeleteRequest:
    return _named_types_EnumMemberDeleteRequest(
        enum_name=_named_types_require_name(params, key="enum_name", message="enum name is required"),
        member_name=_named_types_require_name(params, key="member_name", message="enum member name is required"),
    )


def _named_types_normalize_tinfo_size(value: Any) -> int | None:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return None
    if size < 0 or size >= _named_types_UNKNOWN_TINFO_SIZE_THRESHOLD:
        return None
    return size


def _named_types_coerce_named_type_entries(rows: list[dict[str, Any]]) -> tuple[_named_types_NamedTypeEntry, ...]:
    return tuple(
        _named_types_NamedTypeEntry(
            name=str(item.get("name") or ""), kind=str(item.get("kind") or ""), decl=str(item.get("decl") or "")
        )
        for item in rows
    )


def _named_types_coerce_struct_members(rows: list[dict[str, Any]]) -> tuple[_named_types_StructMember, ...]:
    return tuple(
        _named_types_StructMember(
            index=int(item.get("index") or 0),
            name=None if item.get("name") is None else str(item.get("name")),
            offset_bits=int(item.get("offset_bits") or 0),
            offset=int(item.get("offset") or 0),
            size_bits=int(item.get("size_bits") or 0),
            size=None if (raw_size := item.get("size")) is None else int(raw_size),
            type=str(item.get("type") or ""),
            comment=str(item.get("comment") or ""),
        )
        for item in rows
    )


def _named_types_coerce_enum_members(rows: list[dict[str, Any]]) -> tuple[_named_types_EnumMember, ...]:
    return tuple(
        _named_types_EnumMember(
            index=int(item.get("index") or 0),
            name=None if item.get("name") is None else str(item.get("name")),
            value=int(item.get("value") or 0),
            value_hex=str(item.get("value_hex") or hex(int(item.get("value") or 0))),
            comment=str(item.get("comment") or ""),
        )
        for item in rows
    )


def _named_types_ensure_terr_ok(runtime: IdaRuntime, code: int, action: str) -> None:
    ida_typeinf = runtime.mod("ida_typeinf")
    if code != ida_typeinf.TERR_OK:
        raise IdaOperationError(f"{action}: {ida_typeinf.tinfo_errstr(code)}")


def _named_types_persist_named_type(runtime: IdaRuntime, tif, name: str) -> None:
    ida_typeinf = runtime.mod("ida_typeinf")
    code = tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
    if code != ida_typeinf.TERR_OK:
        raise IdaOperationError(f"failed to persist type `{name}`: {ida_typeinf.tinfo_errstr(code)}")


def _named_types_struct_member_index(tif, struct_name: str, field_name: str) -> int:
    idx, _udm = tif.get_udm(field_name)
    if idx < 0:
        raise IdaOperationError(f"struct field not found: {struct_name}.{field_name}")
    return idx


def _named_types_parse_member_type(runtime: IdaRuntime, decl: str, field_name: str):
    ida_typeinf = runtime.mod("ida_typeinf")
    tif = ida_typeinf.tinfo_t()
    parse_flags = ida_typeinf.PT_VAR | ida_typeinf.PT_SIL | ida_typeinf.PT_SEMICOLON
    raw_decl = decl.strip()
    normalized_decl = f"{raw_decl.rstrip(';')};"
    candidates: list[str] = []
    if re.search(f"(?<![A-Za-z0-9_]){re.escape(field_name)}(?![A-Za-z0-9_])", raw_decl):
        candidates.append(normalized_decl)
    candidates.append(f"{raw_decl.rstrip(';')} {field_name};")
    for parse_text in dict.fromkeys(candidates):
        if ida_typeinf.parse_decl(tif, None, parse_text, parse_flags):
            return tif
    raise IdaOperationError(f"failed to parse member type: {decl}")


def _named_types_type_list(
    context: OperationContext, request: _named_types_NamedTypeListRequest
) -> tuple[_named_types_NamedTypeEntry, ...]:
    runtime = context.runtime
    return _named_types_coerce_named_type_entries(
        runtime.list_named_types(
            pattern=request.pattern,
            regex=request.regex,
            ignore_case=request.ignore_case,
        )
    )


def _named_types_type_show(
    context: OperationContext, request: _named_types_NamedTypeShowRequest
) -> _named_types_NamedTypeView | _named_types_StructuredTypeView | _named_types_EnumTypeView:
    runtime = context.runtime
    tif = runtime.get_named_type(request.name)
    kind = runtime.classify_tinfo(tif)
    size = _named_types_normalize_tinfo_size(tif.get_size())
    decl = runtime.tinfo_decl(tif, name=request.name, multi=True)
    if kind in {"struct", "union"}:
        members = _named_types_coerce_struct_members(runtime.tinfo_members(tif))
        return _named_types_StructuredTypeView(
            name=request.name,
            kind=kind,
            size=size,
            size_known=size is not None,
            decl=decl,
            layout=decl,
            members=members,
        )
    if kind == "enum":
        return _named_types_EnumTypeView(
            name=request.name,
            kind=kind,
            size=size,
            size_known=size is not None,
            decl=decl,
            members=_named_types_coerce_enum_members(runtime.enum_members(tif)),
        )
    return _named_types_NamedTypeView(name=request.name, kind=kind, size=size, size_known=size is not None, decl=decl)


def _named_types_type_deps(
    context: OperationContext, request: _named_types_NamedTypeShowRequest
) -> _named_types_NamedTypeDepsResult:
    runtime = context.runtime
    tif = runtime.get_named_type(request.name)
    kind = runtime.classify_tinfo(tif)
    decl = _named_types_print_type_deps(runtime, tif, request.name)
    return _named_types_NamedTypeDepsResult(
        name=request.name,
        kind=kind,
        decl=decl,
        dependencies_included=True,
    )


def _named_types_print_type_deps(runtime: IdaRuntime, tif, name: str) -> str:
    ida_typeinf = runtime.mod("ida_typeinf")
    ordinal = int(tif.get_ordinal())
    if ordinal <= 0:
        raise IdaOperationError(f"named type has no local ordinal: {name}")

    class Sink(ida_typeinf.text_sink_t):
        def __init__(self) -> None:
            super().__init__()
            self.text = ""

        def _print(self, text):
            self.text += str(text)
            return 0

    sink = Sink()
    flags = ida_typeinf.PDF_INCL_DEPS | ida_typeinf.PDF_DEF_FWD
    exported = int(ida_typeinf.print_decls(sink, None, [ordinal], flags))
    decl = sink.text.strip()
    if exported == 0 or not decl:
        raise IdaOperationError(f"failed to export dependencies for named type: {name}")
    return decl


def _named_types_struct_list(
    context: OperationContext, request: _named_types_NamedTypeListRequest
) -> tuple[_named_types_NamedTypeEntry, ...]:
    runtime = context.runtime
    return _named_types_coerce_named_type_entries(
        runtime.list_named_types(
            pattern=request.pattern,
            regex=request.regex,
            ignore_case=request.ignore_case,
            kinds={"struct", "union"},
        )
    )


def _named_types_struct_view(
    context: OperationContext,
    request: _named_types_NamedTypeShowRequest
    | _named_types_StructFieldSetRequest
    | _named_types_StructFieldRenameRequest
    | _named_types_StructFieldDeleteRequest,
) -> _named_types_StructView:
    runtime = context.runtime
    name = request.name if isinstance(request, _named_types_NamedTypeShowRequest) else request.struct_name
    tif = runtime.get_struct_or_union(name)
    return _named_types_StructView(
        name=name,
        kind=runtime.classify_tinfo(tif),
        layout=runtime.tinfo_decl(tif, name=name, multi=True),
        members=_named_types_coerce_struct_members(runtime.tinfo_members(tif)),
    )


def _named_types_persist_and_show_struct(runtime: IdaRuntime, tif, *, name: str) -> _named_types_StructMutationResult:
    _named_types_persist_named_type(runtime, tif, name)
    try:
        shown = _named_types_struct_view(
            OperationContext(runtime=runtime), _named_types_NamedTypeShowRequest(name=name)
        )
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"persisted named type `{name}` but failed to read it back: {detail}") from exc
    return _named_types_StructMutationResult(
        name=shown.name, kind=shown.kind, layout=shown.layout, members=shown.members, changed=True
    )


def _named_types_struct_field_set(
    context: OperationContext, request: _named_types_StructFieldSetRequest
) -> _named_types_StructMutationResult:
    runtime = context.runtime
    tif = runtime.get_struct_or_union(request.struct_name)
    offset_bits = request.offset * 8
    member_tif = _named_types_parse_member_type(runtime, request.decl, request.field_name)
    idx, udm = tif.get_udm_by_offset(offset_bits)
    if idx >= 0 and udm is not None and (udm.offset == offset_bits):
        _named_types_ensure_terr_ok(runtime, tif.set_udm_type(idx, member_tif), "failed to set field type")
        if udm.name != request.field_name:
            _named_types_ensure_terr_ok(runtime, tif.rename_udm(idx, request.field_name), "failed to rename field")
    else:
        _named_types_ensure_terr_ok(
            runtime, tif.add_udm(request.field_name, member_tif, offset_bits), "failed to add field"
        )
    return _named_types_persist_and_show_struct(runtime, tif, name=request.struct_name)


def _named_types_struct_field_rename(
    context: OperationContext, request: _named_types_StructFieldRenameRequest
) -> _named_types_StructMutationResult:
    runtime = context.runtime
    tif = runtime.get_struct_or_union(request.struct_name)
    idx = _named_types_struct_member_index(tif, request.struct_name, request.field_name)
    _named_types_ensure_terr_ok(runtime, tif.rename_udm(idx, request.new_name), "failed to rename field")
    return _named_types_persist_and_show_struct(runtime, tif, name=request.struct_name)


def _named_types_struct_field_delete(
    context: OperationContext, request: _named_types_StructFieldDeleteRequest
) -> _named_types_StructMutationResult:
    runtime = context.runtime
    tif = runtime.get_struct_or_union(request.struct_name)
    idx = _named_types_struct_member_index(tif, request.struct_name, request.field_name)
    _named_types_ensure_terr_ok(runtime, tif.del_udm(idx), "failed to delete field")
    return _named_types_persist_and_show_struct(runtime, tif, name=request.struct_name)


def _named_types_enum_list(
    context: OperationContext, request: _named_types_NamedTypeListRequest
) -> tuple[_named_types_NamedTypeEntry, ...]:
    runtime = context.runtime
    return _named_types_coerce_named_type_entries(
        runtime.list_named_types(
            pattern=request.pattern,
            regex=request.regex,
            ignore_case=request.ignore_case,
            kinds={"enum"},
        )
    )


def _named_types_enum_view(
    context: OperationContext,
    request: _named_types_NamedTypeShowRequest
    | _named_types_EnumMemberSetRequest
    | _named_types_EnumMemberRenameRequest
    | _named_types_EnumMemberDeleteRequest,
) -> _named_types_EnumView:
    runtime = context.runtime
    name = request.name if isinstance(request, _named_types_NamedTypeShowRequest) else request.enum_name
    tif = runtime.get_named_type(name, kind="enum")
    return _named_types_EnumView(
        name=name,
        kind="enum",
        decl=runtime.tinfo_decl(tif, name=name, multi=True),
        members=_named_types_coerce_enum_members(runtime.enum_members(tif)),
    )


def _named_types_persist_and_show_enum(runtime: IdaRuntime, tif, *, name: str) -> _named_types_EnumMutationResult:
    _named_types_persist_named_type(runtime, tif, name)
    try:
        shown = _named_types_enum_view(OperationContext(runtime=runtime), _named_types_NamedTypeShowRequest(name=name))
    except Exception as exc:
        detail = str(exc) or exc.__class__.__name__
        raise IdaOperationError(f"persisted named type `{name}` but failed to read it back: {detail}") from exc
    return _named_types_EnumMutationResult(
        name=shown.name, kind=shown.kind, decl=shown.decl, members=shown.members, changed=True
    )


def _named_types_enum_member_set(
    context: OperationContext, request: _named_types_EnumMemberSetRequest
) -> _named_types_EnumMutationResult:
    runtime = context.runtime
    tif = runtime.get_named_type(request.enum_name, kind="enum")
    ida_typeinf = runtime.mod("ida_typeinf")
    mask = ida_typeinf.DEFMASK64 if request.mask is None else request.mask
    idx, _edm = tif.get_edm(request.member_name)
    if idx >= 0:
        _named_types_ensure_terr_ok(runtime, tif.edit_edm(idx, request.value, mask), "failed to edit enum member")
    else:
        _named_types_ensure_terr_ok(
            runtime, tif.add_edm(request.member_name, request.value, mask), "failed to add enum member"
        )
    return _named_types_persist_and_show_enum(runtime, tif, name=request.enum_name)


def _named_types_enum_member_rename(
    context: OperationContext, request: _named_types_EnumMemberRenameRequest
) -> _named_types_EnumMutationResult:
    runtime = context.runtime
    tif = runtime.get_named_type(request.enum_name, kind="enum")
    idx, _edm = tif.get_edm(request.member_name)
    if idx < 0:
        raise IdaOperationError(f"enum member not found: {request.enum_name}.{request.member_name}")
    _named_types_ensure_terr_ok(runtime, tif.rename_edm(idx, request.new_name), "failed to rename enum member")
    return _named_types_persist_and_show_enum(runtime, tif, name=request.enum_name)


def _named_types_enum_member_delete(
    context: OperationContext, request: _named_types_EnumMemberDeleteRequest
) -> _named_types_EnumMutationResult:
    runtime = context.runtime
    tif = runtime.get_named_type(request.enum_name, kind="enum")
    _named_types_ensure_terr_ok(runtime, tif.del_edm(request.member_name), "failed to delete enum member")
    return _named_types_persist_and_show_enum(runtime, tif, name=request.enum_name)


# ---- Type declaration ----


_type_declare_FORWARD_DECL_RE = re.compile(
    "^\\s*(?:typedef\\s+)?(?:struct|class|union)\\s+(?P<tag>[A-Za-z_][A-Za-z0-9_:]*)(?:\\s+(?P<alias>[A-Za-z_][A-Za-z0-9_:]*))?\\s*;\\s*$",
    re.DOTALL,
)
_type_declare_CONCRETE_TYPE_RE = re.compile(
    "\\b(?:struct|class|union|enum)\\s+(?P<name>[A-Za-z_][A-Za-z0-9_:]*)\\s*\\{", re.DOTALL
)
_type_declare_TYPEDEF_ALIAS_RE = re.compile(
    "^\\s*typedef\\s+(?:struct|class|union|enum)\\s+(?:(?P<tag>[A-Za-z_][A-Za-z0-9_:]*)\\s*)?\\{.*\\}\\s*(?P<alias>[A-Za-z_][A-Za-z0-9_:]*)\\s*;\\s*$",
    re.DOTALL,
)
_type_declare_TYPEDEF_FUNC_ALIAS_RE = re.compile(
    "^\\s*typedef\\b.*\\(\\s*\\*\\s*(?P<alias>[A-Za-z_][A-Za-z0-9_:]*)\\s*\\)\\s*\\([^;]*\\)\\s*;\\s*$", re.DOTALL
)
_type_declare_TYPEDEF_SIMPLE_ALIAS_RE = re.compile(
    "^\\s*typedef\\b.*?\\b(?P<alias>[A-Za-z_][A-Za-z0-9_:]*)\\s*;\\s*$", re.DOTALL
)
_type_declare_BY_VALUE_MEMBER_RE = re.compile(
    "^(?:typedef\\s+)?(?:(?:const|volatile|mutable|signed|unsigned|short|long)\\s+)*(?:(?:struct|class|union)\\s+)?(?P<type>[A-Za-z_][A-Za-z0-9_:]*)(?:\\s+(?:const|volatile))*\\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\[[^\\]]+\\])?\\s*$",
    re.DOTALL,
)
_type_declare_BUILTIN_MEMBER_TYPES = frozenset(
    {
        "bool",
        "char",
        "double",
        "float",
        "int",
        "long",
        "short",
        "signed",
        "size_t",
        "ssize_t",
        "unsigned",
        "void",
        "wchar_t",
        "__int8",
        "__int16",
        "__int32",
        "__int64",
        "__int128",
    }
)
_type_declare_TypeAlias = TypedDict("_type_declare_TypeAlias", {"from": str, "to": str})
_type_declare_AppliedAlias = TypedDict("_type_declare_AppliedAlias", {"from": str, "to": str, "count": int})


class _type_declare_DeclarationChunkDict(TypedDict):
    text: str
    start_line: int
    end_line: int
    terminated: bool


class _type_declare_BlockingMember(TypedDict):
    type_name: str
    member_name: str


class _type_declare_BisectTrial(TypedDict):
    prefix_count: int
    errors: int
    success: bool


class _type_declare_TypeDiagnosticDict(TypedDict, total=False):
    kind: str
    message: str
    line: int
    end_line: int
    snippet: str
    construct: str
    balance: int


class _type_declare_FailingDeclaration(TypedDict, total=False):
    index: int
    line: int
    end_line: int
    snippet: str
    standalone_errors: int
    standalone_success: bool


class _type_declare_TypeDeclareBisectResult(TypedDict, total=False):
    requested: bool
    supported: bool
    mode: str
    declaration_count: int
    message: str
    trials: list[_type_declare_BisectTrial]
    diagnostics: list[_type_declare_TypeDiagnosticDict]
    failing_declaration: _type_declare_FailingDeclaration
    blocking_members: list[_type_declare_BlockingMember]


class _type_declare_TypeDeclareResult(TypedDict, total=False):
    errors: int
    replace: bool
    check: bool
    aliases_applied: list[_type_declare_AppliedAlias]
    diagnostics: list[_type_declare_TypeDiagnosticDict]
    imported_types: list[str]
    replaced_types: list[str]
    declaration_count: int
    success: bool
    bisect: _type_declare_TypeDeclareBisectResult | None


_type_declare_NamedTypeSnapshot = dict[str, str | None]


@dataclass(frozen=True)
class _type_declare_DeclarationChunk:
    text: str
    start_line: int
    end_line: int
    terminated: bool

    def to_dict(self) -> _type_declare_DeclarationChunkDict:
        return {
            "text": self.text,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "terminated": self.terminated,
        }


@dataclass(frozen=True)
class _type_declare_TypeDiagnostic:
    kind: str
    message: str
    line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    construct: str | None = None
    balance: int | None = None

    def to_dict(self) -> _type_declare_TypeDiagnosticDict:
        item: _type_declare_TypeDiagnosticDict = {"kind": self.kind, "message": self.message}
        if self.line is not None:
            item["line"] = self.line
        if self.end_line is not None:
            item["end_line"] = self.end_line
        if self.snippet:
            item["snippet"] = self.snippet[:240]
        if self.construct:
            item["construct"] = self.construct
        if self.balance is not None:
            item["balance"] = self.balance
        return item


@dataclass(frozen=True)
class _type_declare_TypeDeclareRequest:
    decl: str
    aliases: tuple[_type_declare_TypeAlias, ...]
    replace: bool
    bisect: bool
    clang: bool


@dataclass(frozen=True)
class _type_declare_TypeDeclarePreviewSnapshot:
    type_count: int
    class_count: int
    declarations: dict[str, str | None]


def _type_declare_named_type_map(rows: list[dict[str, Any]]) -> _type_declare_NamedTypeSnapshot:
    return {item["name"]: item.get("decl") for item in rows}


def _type_declare_named_types_snapshot(runtime: IdaRuntime) -> _type_declare_NamedTypeSnapshot:
    return _type_declare_named_type_map(runtime.list_named_types())


def _type_declare_strip_comments_preserve_lines(text: str) -> str:
    out: list[str] = []
    in_string: str | None = None
    in_line_comment = False
    in_block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                out.append(ch)
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            if ch == "\n":
                out.append(ch)
            i += 1
            continue
        if in_string:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        out.append(ch)
        if ch in {"'", '"'}:
            in_string = ch
        i += 1
    return "".join(out)


def _type_declare_strip_preprocessor_lines(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_directive_continuation = False
    for line in lines:
        stripped = line.lstrip()
        is_directive = stripped.startswith("#") or in_directive_continuation
        if is_directive:
            newline = "\n" if line.endswith("\n") else ""
            out.append(newline)
            in_directive_continuation = line.rstrip().endswith("\\")
            continue
        in_directive_continuation = False
        out.append(line)
    return "".join(out)


def _type_declare_parse_request(params: Mapping[str, Any]) -> _type_declare_TypeDeclareRequest:
    decl = _type_declare_strip_comments_preserve_lines(str(params.get("decl") or ""))
    decl = _type_declare_strip_preprocessor_lines(decl)
    if not decl.strip():
        raise IdaOperationError("type declarations are required via --decl or --file")
    try:
        aliases = cast("tuple[_type_declare_TypeAlias, ...]", tuple(parse_aliases(params.get("aliases") or [])))
    except ValueError as exc:
        raise IdaOperationError(str(exc)) from exc
    return _type_declare_TypeDeclareRequest(
        decl=decl,
        aliases=aliases,
        replace=bool(params.get("replace")),
        bisect=bool(params.get("bisect")),
        clang=bool(params.get("clang")),
    )


def _type_declare_parse_check_request(params: Mapping[str, Any]) -> _type_declare_TypeDeclareRequest:
    if {"replace", "bisect"} & params.keys():
        raise IdaOperationError("type check does not accept replace or bisect parameters")
    return _type_declare_parse_request(params)


def _type_declare_join_declaration_chunks(chunks: list[_type_declare_DeclarationChunk]) -> str:
    return "\n".join(chunk.text for chunk in chunks)


def _type_declare_apply_type_aliases(
    decl: str, aliases: list[_type_declare_TypeAlias]
) -> tuple[str, list[_type_declare_AppliedAlias]]:
    updated = decl
    applied: list[_type_declare_AppliedAlias] = []
    for alias in aliases:
        src = alias["from"]
        dst = alias["to"]
        pattern = re.compile(
            f"(?:(?P<global_prefix>(?:^|(?<=[^A-Za-z0-9_:]))::)|(?<![A-Za-z0-9_:]))(?P<name>{re.escape(src)})(?![A-Za-z0-9_:])"
        )

        def replace(match: re.Match[str], *, replacement: str = dst) -> str:
            prefix = match.group("global_prefix") or ""
            return f"{prefix}{replacement}"

        updated, count = pattern.subn(replace, updated)
        if count:
            applied.append({"from": src, "to": dst, "count": count})
    return (updated, applied)


def _type_declare_parse_declaration_chunks(text: str) -> tuple[list[_type_declare_DeclarationChunk], int]:
    chunks: list[_type_declare_DeclarationChunk] = []
    current: list[str] = []
    line = 1
    start_line = 1
    brace_depth = 0
    paren_depth = 0
    in_string: str | None = None
    in_line_comment = False
    in_block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        current.append(ch)
        if ch == "\n":
            line += 1
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                current.append(nxt)
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if ch == "\\":
                if nxt:
                    current.append(nxt)
                    if nxt == "\n":
                        line += 1
                    i += 2
                    continue
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            current.append(nxt)
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            current.append(nxt)
            in_block_comment = True
            i += 2
            continue
        if ch in {"'", '"'}:
            in_string = ch
            i += 1
            continue
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth = max(0, brace_depth - 1)
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
        elif ch == ";" and brace_depth == 0 and (paren_depth == 0):
            raw = "".join(current)
            stripped = raw.strip()
            if stripped:
                chunks.append(_type_declare_DeclarationChunk(stripped, start_line, line, True))
            current = []
            start_line = _type_declare_next_chunk_start_line(text, i + 1, line)
        i += 1
    tail = "".join(current).strip()
    if tail:
        chunks.append(_type_declare_DeclarationChunk(tail, start_line, line, False))
    return (chunks, brace_depth)


def _type_declare_next_chunk_start_line(text: str, index: int, line: int) -> int:
    next_line = line
    i = index
    while i < len(text):
        ch = text[i]
        if ch == "\n":
            next_line += 1
            i += 1
            continue
        if ch in {" ", "\t", "\r"}:
            i += 1
            continue
        break
    return next_line


def _type_declare_append_type_diagnostic(
    diagnostics: list[_type_declare_TypeDiagnostic],
    *,
    kind: str,
    message: str,
    line: int | None = None,
    end_line: int | None = None,
    snippet: str | None = None,
    construct: str | None = None,
) -> None:
    diagnostics.append(
        _type_declare_TypeDiagnostic(
            kind=kind, message=message, line=line, end_line=end_line, snippet=snippet, construct=construct
        )
    )


def _type_declare_chunk_type_diagnostics(
    chunk: _type_declare_DeclarationChunk, *, aliases_applied: list[_type_declare_AppliedAlias]
) -> list[_type_declare_TypeDiagnostic]:
    text = chunk.text
    snippet = text[:240]
    line = chunk.start_line
    end_line = chunk.end_line
    diagnostics: list[_type_declare_TypeDiagnostic] = []
    if "__cppobj" in text:
        _type_declare_append_type_diagnostic(
            diagnostics,
            kind="cppobj_hint",
            message=(
                "IDA may reject `__cppobj` in local type imports; retry with plain `struct` declarations "
                "and concrete placeholder support types"
            ),
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="__cppobj",
        )
    if re.match("^\\s*(class|struct|union)\\s+[A-Za-z_][A-Za-z0-9_:]*\\s*;\\s*$", text):
        _type_declare_append_type_diagnostic(
            diagnostics,
            kind="forward_declaration_hint",
            message=(
                "forward declarations are often insufficient here; import a concrete placeholder definition "
                "instead of only `type_name;`"
            ),
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="forward_declaration",
        )
    if "__cppobj" not in text and re.search("\\bclass\\s+[A-Za-z_][A-Za-z0-9_:]*\\b", text):
        _type_declare_append_type_diagnostic(
            diagnostics,
            kind="class_keyword_hint",
            message=(
                "if this is a recovered object layout, retry with plain `struct` declarations instead of `class` syntax"
            ),
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="class",
        )
    if "::" in text and (not aliases_applied):
        _type_declare_append_type_diagnostic(
            diagnostics,
            kind="namespace_hint",
            message="namespace-qualified identifiers may require --alias old=new before import",
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="::",
        )
    return diagnostics


def _type_declare_type_declare_diagnostics(
    decl: str,
    *,
    errors: int,
    aliases_applied: list[_type_declare_AppliedAlias],
    chunks: list[_type_declare_DeclarationChunk] | None = None,
    brace_balance: int | None = None,
) -> list[_type_declare_TypeDiagnosticDict]:
    diagnostics: dict[tuple[str, int | None, str | None], _type_declare_TypeDiagnostic] = {}

    def add_unique(item: _type_declare_TypeDiagnostic) -> None:
        key = (item.kind, item.line, item.construct)
        diagnostics.setdefault(key, item)

    if chunks is None:
        chunks, brace_balance = _type_declare_parse_declaration_chunks(decl)
    resolved_chunks = chunks
    resolved_brace_balance = cast("int", brace_balance)
    for chunk in resolved_chunks:
        if not chunk.terminated:
            add_unique(
                _type_declare_TypeDiagnostic(
                    kind="unterminated_declaration",
                    message="declaration does not end with a top-level semicolon",
                    line=chunk.start_line,
                    end_line=chunk.end_line,
                    snippet=chunk.text[:240],
                )
            )
    if resolved_brace_balance > 0:
        add_unique(
            _type_declare_TypeDiagnostic(
                kind="unbalanced_braces",
                message="more opening braces than closing braces were found",
                balance=resolved_brace_balance,
            )
        )
    if errors:
        for chunk in resolved_chunks:
            for item in _type_declare_chunk_type_diagnostics(chunk, aliases_applied=aliases_applied):
                add_unique(item)
    if errors and not diagnostics:
        first = resolved_chunks[0] if resolved_chunks else _type_declare_DeclarationChunk(decl.strip(), 1, 1, False)
        add_unique(
            _type_declare_TypeDiagnostic(
                kind="parser_error",
                message=f"IDA reported {errors} parser error(s); rerun with smaller declaration batches if needed",
                line=first.start_line,
                end_line=first.end_line,
                snippet=first.text[:240],
            )
        )
    return [item.to_dict() for item in diagnostics.values()]


def _type_declare_parse_type_declarations(runtime: IdaRuntime, decl: str, *, replace: bool, clang: bool) -> int:
    ida_typeinf = runtime.mod("ida_typeinf")
    if not clang:
        flags = ida_typeinf.PT_REPLACE if replace else 0
        return ida_typeinf.idc_parse_types(decl, flags)
    if replace:
        type_names = _type_declare_declared_type_names(_type_declare_parse_declaration_chunks(decl)[0])
        _type_declare_delete_named_types(runtime, type_names)
    return _type_declare_parse_type_declarations_with_clang(runtime, decl)


def _type_declare_parse_type_declarations_with_clang(runtime: IdaRuntime, decl: str) -> int:
    ida_typeinf = runtime.mod("ida_typeinf")
    ida_srclang = runtime.mod("ida_srclang")
    hti_flags = _type_declare_clang_parse_flags(ida_typeinf, decl, test=False)
    errors = ida_srclang.parse_decls_with_parser_ext("clang", None, decl, hti_flags)
    if errors < 0:
        raise IdaOperationError("clang parser is unavailable for type declare")
    return errors


def _type_declare_clang_parse_flags(ida_typeinf: Any, decl: str, *, test: bool) -> int:
    hti_flags = ida_typeinf.HTI_DCL | ida_typeinf.HTI_SEMICOLON
    if test:
        hti_flags |= ida_typeinf.HTI_TST
    if "::" in decl:
        hti_flags |= ida_typeinf.HTI_RELAXED
    return hti_flags


def _type_declare_test_type_declarations(runtime: IdaRuntime, decl: str, *, clang: bool) -> int:
    ida_typeinf = runtime.mod("ida_typeinf")
    if clang:
        ida_srclang = runtime.mod("ida_srclang")
        hti_flags = _type_declare_clang_parse_flags(ida_typeinf, decl, test=True)
        errors = ida_srclang.parse_decls_with_parser_ext("clang", None, decl, hti_flags)
        if errors < 0:
            raise IdaOperationError("clang parser is unavailable for type check")
        return errors
    hti_flags = ida_typeinf.HTI_DCL | ida_typeinf.HTI_SEMICOLON | ida_typeinf.HTI_TST
    if "::" in decl:
        hti_flags |= ida_typeinf.HTI_RELAXED
    return int(ida_typeinf.parse_decls(None, decl, None, hti_flags))


def _type_declare_typedef_alias_names(text: str) -> set[str]:
    names: set[str] = set()
    func_alias_match = _type_declare_TYPEDEF_FUNC_ALIAS_RE.match(text)
    if func_alias_match:
        alias = func_alias_match.group("alias")
        if alias:
            names.add(alias)
        return names
    simple_alias_match = _type_declare_TYPEDEF_SIMPLE_ALIAS_RE.match(text)
    if simple_alias_match:
        alias = simple_alias_match.group("alias")
        if alias:
            names.add(alias)
    return names


def _type_declare_declared_type_names(chunks: list[_type_declare_DeclarationChunk]) -> set[str]:
    names: set[str] = set()
    for chunk in chunks:
        names.update(_type_declare_concrete_type_names(chunk.text))
        names.update(_type_declare_forward_declared_type_names(chunk.text))
        names.update(_type_declare_typedef_alias_names(chunk.text))
    return {name for name in names if name}


def _type_declare_delete_named_types(runtime: IdaRuntime, type_names: set[str]) -> None:
    if not type_names:
        return
    ida_typeinf = runtime.mod("ida_typeinf")
    for name in sorted(type_names):
        if runtime.find_named_type(name) is None:
            continue
        if not ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE):
            raise IdaOperationError(f"failed to replace existing local type: {name}")


def _type_declare_apply_type_declarations(
    runtime: IdaRuntime, decl: str, *, replace: bool, clang: bool
) -> tuple[int, _type_declare_NamedTypeSnapshot, _type_declare_NamedTypeSnapshot]:
    before = _type_declare_named_types_snapshot(runtime)
    errors = _type_declare_parse_type_declarations(runtime, decl, replace=replace, clang=clang)
    return (errors, before, _type_declare_named_types_snapshot(runtime))


def _type_declare_forward_declared_type_names(text: str) -> set[str]:
    match = _type_declare_FORWARD_DECL_RE.match(text)
    if not match:
        return set()
    names = {match.group("tag")}
    alias = match.group("alias")
    if alias:
        names.add(alias)
    return {name for name in names if name}


def _type_declare_concrete_type_names(text: str) -> set[str]:
    names = {match.group("name") for match in _type_declare_CONCRETE_TYPE_RE.finditer(text)}
    alias_match = _type_declare_TYPEDEF_ALIAS_RE.match(text)
    if alias_match:
        alias = alias_match.group("alias")
        if alias:
            names.add(alias)
        tag = alias_match.group("tag")
        if tag:
            names.add(tag)
    return {name for name in names if name}


def _type_declare_opaque_by_value_members(
    failing_chunk: _type_declare_DeclarationChunk, *, earlier_chunks: list[_type_declare_DeclarationChunk]
) -> list[_type_declare_BlockingMember]:
    concrete: set[str] = set()
    forward: set[str] = set()
    for chunk in [*earlier_chunks, failing_chunk]:
        text = chunk.text
        concrete.update(_type_declare_concrete_type_names(text))
        forward.update(_type_declare_forward_declared_type_names(text))
    forward -= concrete
    if not forward:
        return []
    rows: list[_type_declare_BlockingMember] = []
    for raw_stmt in failing_chunk.text.replace("\n", " ").split(";"):
        stmt = raw_stmt.strip()
        if not stmt or any(token in stmt for token in ("*", "&", "(")):
            continue
        if "{" in stmt:
            stmt = stmt.rsplit("{", 1)[-1].strip()
        if "}" in stmt:
            stmt = stmt.split("}", 1)[0].strip()
        if not stmt:
            continue
        match = _type_declare_BY_VALUE_MEMBER_RE.match(stmt)
        if not match:
            continue
        type_name = match.group("type")
        member_name = match.group("name")
        if type_name.lower() in _type_declare_BUILTIN_MEMBER_TYPES or type_name not in forward:
            continue
        rows.append({"type_name": type_name, "member_name": member_name})
    return rows


def _type_declare_trial_type_parse_errors(
    runtime: IdaRuntime, decl: str, *, replace: bool, clang: bool, label: str
) -> int:
    action = re.sub("[^A-Za-z0-9_]+", "_", label).strip("_") or "trial"
    with ida_undo_restore_point(
        runtime,
        action_name=f"idac_type_declare_{action}",
        label=f"idac type declare {label}",
        unavailable_message="type declare bisect requires IDA undo support",
        restore_error_message="type declare bisect could not restore the trial import via undo",
    ):
        return _type_declare_parse_type_declarations(runtime, decl, replace=replace, clang=clang)


def _type_declare_bisect_type_declarations(
    runtime: IdaRuntime, chunks: list[_type_declare_DeclarationChunk], *, replace: bool, clang: bool
) -> _type_declare_TypeDeclareBisectResult:
    result: _type_declare_TypeDeclareBisectResult = {
        "requested": True,
        "supported": True,
        "mode": "ordered_prefix",
        "declaration_count": len(chunks),
        "trials": [],
    }
    if not chunks:
        result["supported"] = False
        result["message"] = "no declarations were available for bisect"
        return result
    try:
        if len(chunks) == 1:
            failing_index = 0
            standalone_errors = _type_declare_trial_type_parse_errors(
                runtime,
                _type_declare_join_declaration_chunks([chunks[0]]),
                replace=replace,
                clang=clang,
                label="single_decl",
            )
        else:
            low = 1
            high = len(chunks)
            while low < high:
                mid = (low + high) // 2
                errors = _type_declare_trial_type_parse_errors(
                    runtime,
                    _type_declare_join_declaration_chunks(chunks[:mid]),
                    replace=replace,
                    clang=clang,
                    label=f"prefix_{mid}",
                )
                result["trials"].append({"prefix_count": mid, "errors": errors, "success": errors == 0})
                if errors:
                    high = mid
                else:
                    low = mid + 1
            failing_index = low - 1
            standalone_errors = _type_declare_trial_type_parse_errors(
                runtime,
                _type_declare_join_declaration_chunks([chunks[failing_index]]),
                replace=replace,
                clang=clang,
                label=f"single_{failing_index + 1}",
            )
    except IdaOperationError as exc:
        result["supported"] = False
        result["message"] = str(exc) or exc.__class__.__name__
        result["diagnostics"] = [{"kind": "bisect_unavailable", "message": result["message"]}]
        return result
    failing_chunk = chunks[failing_index]
    diagnostics: list[_type_declare_TypeDiagnosticDict] = [
        {
            "kind": "bisect_culprit",
            "message": "ordered bisect isolated the first failing declaration",
            "line": failing_chunk.start_line,
            "end_line": failing_chunk.end_line,
            "snippet": failing_chunk.text[:240],
        }
    ]
    if standalone_errors == 0 and len(chunks) > 1:
        diagnostics.append(
            {
                "kind": "bisect_context_hint",
                "message": (
                    "the isolated declaration imports alone; the failure depends on earlier declarations "
                    "or ordered batch context"
                ),
                "line": failing_chunk.start_line,
                "end_line": failing_chunk.end_line,
                "snippet": failing_chunk.text[:240],
            }
        )
    blocking_members = _type_declare_opaque_by_value_members(failing_chunk, earlier_chunks=chunks[:failing_index])
    for member in blocking_members:
        diagnostics.append(
            {
                "kind": "opaque_by_value_member_hint",
                "message": (
                    f"by-value member `{member['member_name']}` uses forward-declared or opaque type "
                    f"`{member['type_name']}`; import a concrete placeholder definition first"
                ),
                "line": failing_chunk.start_line,
                "end_line": failing_chunk.end_line,
                "snippet": failing_chunk.text[:240],
                "construct": member["type_name"],
            }
        )
    result["message"] = diagnostics[0]["message"]
    result["failing_declaration"] = {
        "index": failing_index + 1,
        "line": failing_chunk.start_line,
        "end_line": failing_chunk.end_line,
        "snippet": failing_chunk.text[:240],
        "standalone_errors": standalone_errors,
        "standalone_success": standalone_errors == 0,
    }
    if blocking_members:
        result["blocking_members"] = blocking_members
    result["diagnostics"] = diagnostics
    return result


def _type_declare_bisect_unavailable_result(
    chunks: list[_type_declare_DeclarationChunk], exc: IdaOperationError
) -> _type_declare_TypeDeclareBisectResult:
    message = str(exc) or exc.__class__.__name__
    return {
        "requested": True,
        "supported": False,
        "mode": "ordered_prefix",
        "declaration_count": len(chunks),
        "message": message,
        "diagnostics": [{"kind": "bisect_unavailable", "message": message}],
    }


def _type_declare_apply_type_declarations_with_optional_bisect(
    runtime: IdaRuntime,
    decl: str,
    *,
    replace: bool,
    clang: bool,
    chunks: list[_type_declare_DeclarationChunk],
    bisect_requested: bool,
) -> tuple[
    int, _type_declare_NamedTypeSnapshot, _type_declare_NamedTypeSnapshot, _type_declare_TypeDeclareBisectResult | None
]:
    if not bisect_requested:
        errors, before, after = _type_declare_apply_type_declarations(runtime, decl, replace=replace, clang=clang)
        return (errors, before, after, None)
    try:
        trial_errors = _type_declare_trial_type_parse_errors(runtime, decl, replace=replace, clang=clang, label="full")
    except IdaOperationError as exc:
        before = _type_declare_named_types_snapshot(runtime)
        return (1, before, dict(before), _type_declare_bisect_unavailable_result(chunks, exc))
    if trial_errors == 0:
        errors, before, after = _type_declare_apply_type_declarations(runtime, decl, replace=replace, clang=clang)
        return (errors, before, after, None)
    before = _type_declare_named_types_snapshot(runtime)
    return (
        trial_errors,
        before,
        dict(before),
        _type_declare_bisect_type_declarations(runtime, chunks, replace=replace, clang=clang),
    )


def _type_declare_type_declare_result(
    decl: str,
    *,
    replace: bool,
    errors: int,
    before: _type_declare_NamedTypeSnapshot,
    after: _type_declare_NamedTypeSnapshot,
    aliases_applied: list[_type_declare_AppliedAlias],
    chunks: list[_type_declare_DeclarationChunk],
    brace_balance: int,
    bisect: _type_declare_TypeDeclareBisectResult | None = None,
) -> _type_declare_TypeDeclareResult:
    diagnostics = _type_declare_type_declare_diagnostics(
        decl, errors=errors, aliases_applied=aliases_applied, chunks=chunks, brace_balance=brace_balance
    )
    if bisect is not None:
        existing = {(item["kind"], item.get("line"), item["message"]) for item in diagnostics}
        for item in bisect.get("diagnostics") or []:
            key = (item["kind"], item.get("line"), item["message"])
            if key in existing:
                continue
            diagnostics.append(item)
            existing.add(key)
    return {
        "errors": errors,
        "replace": replace,
        "aliases_applied": aliases_applied,
        "diagnostics": diagnostics,
        "imported_types": sorted(set(after) - set(before)),
        "replaced_types": sorted(name for name in set(after) & set(before) if before.get(name) != after.get(name)),
        "declaration_count": len(chunks),
        "success": errors == 0,
        "bisect": bisect,
    }


def _type_declare_preview_snapshot(
    context: OperationContext, request: _type_declare_TypeDeclareRequest
) -> _type_declare_TypeDeclarePreviewSnapshot:
    runtime = context.runtime
    names = runtime.list_named_types()
    current = _type_declare_named_type_map(names)
    decl, _aliases_applied = _type_declare_apply_type_aliases(request.decl, list(request.aliases))
    declared_names = _type_declare_declared_type_names(_type_declare_parse_declaration_chunks(decl)[0])
    return _type_declare_TypeDeclarePreviewSnapshot(
        type_count=len(names),
        class_count=len(runtime.list_named_classes()),
        declarations={name: current.get(name) for name in sorted(declared_names)},
    )


def _type_declare_type_declare(
    context: OperationContext, request: _type_declare_TypeDeclareRequest
) -> _type_declare_TypeDeclareResult:
    runtime = context.runtime
    decl, aliases_applied = _type_declare_apply_type_aliases(request.decl, list(request.aliases))
    chunks, brace_balance = _type_declare_parse_declaration_chunks(decl)
    errors, before, after, bisect = _type_declare_apply_type_declarations_with_optional_bisect(
        runtime, decl, replace=request.replace, clang=request.clang, chunks=chunks, bisect_requested=request.bisect
    )
    return _type_declare_type_declare_result(
        decl,
        replace=request.replace,
        errors=errors,
        before=before,
        after=after,
        aliases_applied=aliases_applied,
        chunks=chunks,
        brace_balance=brace_balance,
        bisect=bisect,
    )


def _type_declare_type_declare_check(
    context: OperationContext, request: _type_declare_TypeDeclareRequest
) -> _type_declare_TypeDeclareResult:
    runtime = context.runtime
    decl, aliases_applied = _type_declare_apply_type_aliases(request.decl, list(request.aliases))
    chunks, brace_balance = _type_declare_parse_declaration_chunks(decl)
    errors = _type_declare_test_type_declarations(runtime, decl, clang=request.clang)
    result = _type_declare_type_declare_result(
        decl,
        replace=request.replace,
        errors=errors,
        before={},
        after={},
        aliases_applied=aliases_applied,
        chunks=chunks,
        brace_balance=brace_balance,
        bisect=None,
    )
    result["check"] = True
    return result


# ---- Class operations ----


@dataclass(frozen=True)
class _classes_ClassListRequest:
    pattern: str | None
    regex: bool
    ignore_case: bool


@dataclass(frozen=True)
class _classes_ClassCandidatesRequest:
    pattern: str
    kinds: tuple[str, ...]
    regex: bool
    ignore_case: bool


@dataclass(frozen=True)
class _classes_ClassNameRequest:
    name: str


@dataclass(frozen=True)
class _classes_ClassFieldsRequest:
    name: str
    derived_only: bool


@dataclass(frozen=True)
class _classes_ClassVtableRequest:
    name: str
    runtime: bool


def _classes_parse_list(params: Mapping[str, Any]) -> _classes_ClassListRequest:
    pattern = optional_str(params.get("pattern"))
    return _classes_ClassListRequest(
        pattern=pattern,
        regex=bool(params.get("regex")),
        ignore_case=bool(params.get("ignore_case")),
    )


def _classes_parse_candidates(params: Mapping[str, Any]) -> _classes_ClassCandidatesRequest:
    pattern = str(params.get("pattern") or "")
    kinds = tuple(str(item) for item in params.get("kinds") or [] if str(item))
    return _classes_ClassCandidatesRequest(
        pattern=pattern,
        kinds=kinds,
        regex=bool(params.get("regex")),
        ignore_case=bool(params.get("ignore_case")),
    )


def _classes_parse_name(params: Mapping[str, Any]) -> _classes_ClassNameRequest:
    return _classes_ClassNameRequest(name=require_str(params.get("name"), field="class name"))


def _classes_parse_fields(params: Mapping[str, Any]) -> _classes_ClassFieldsRequest:
    return _classes_ClassFieldsRequest(
        name=require_str(params.get("name"), field="class name"), derived_only=bool(params.get("derived_only"))
    )


def _classes_parse_class_vtable(params: Mapping[str, Any]) -> _classes_ClassVtableRequest:
    return _classes_ClassVtableRequest(
        name=require_str(params.get("name"), field="class name"), runtime=bool(params.get("runtime"))
    )


def _classes_class_graph(runtime: IdaRuntime) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    rows = runtime.list_named_classes()
    classes = {row["name"]: row for row in rows}
    children: dict[str, list[str]] = {name: [] for name in classes}
    for name, row in classes.items():
        for base_name in row.get("bases") or []:
            if base_name in children:
                children[base_name].append(name)
    for names in children.values():
        names.sort(key=str.lower)
    return (classes, children)


def _classes_iter_udt_members(runtime: IdaRuntime, tif, *, expand_bases: bool, base_offset_bits: int = 0):
    for member in runtime.udt_members(tif):
        offset_bits = base_offset_bits + int(member.offset)
        if member.is_baseclass():
            if expand_bases:
                base_name = member.type.get_type_name() or member.type.dstr()
                base_tif = runtime.find_named_type(base_name or "")
                if base_tif is not None:
                    yield from _classes_iter_udt_members(
                        runtime, base_tif, expand_bases=True, base_offset_bits=offset_bits
                    )
            continue
        yield (offset_bits, member)


def _classes_walk_graph(start: list[str], edges: dict[str, list[str]], *, known: set[str]) -> list[str]:
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


def _classes_vtable_header(runtime: IdaRuntime, table_ea: int, symbol_name: str, *, ptr_size: int):
    ida_name = runtime.mod("ida_name")
    if _classes_looks_like_itanium_vtable(runtime, table_ea, symbol_name):
        typeinfo_ea = runtime.read_pointer(table_ea + ptr_size)
        return (
            "itanium",
            table_ea + ptr_size * 2,
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
        return ("msvc", table_ea, [])
    return ("unknown", table_ea, [])


def _classes_flatten_class_fields(runtime: IdaRuntime, tif, *, derived_only: bool) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for offset_bits, member in _classes_iter_udt_members(runtime, tif, expand_bases=not derived_only):
        if member.is_method():
            continue
        fields.append(
            {
                "name": member.name or "",
                "offset_bits": offset_bits,
                "offset": offset_bits // 8,
                "size_bits": member.size,
                "size": member.size // 8 if member.size else None,
                "type": member.type.dstr() or runtime.tinfo_decl(member.type, multi=False),
                "is_vftable": member.is_vftable(),
            }
        )
    fields.sort(key=lambda item: (item["offset"], item["name"]))
    return fields


def _classes_vtable_members(runtime: IdaRuntime, vtable_tif) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, (offset_bits, member) in enumerate(_classes_iter_udt_members(runtime, vtable_tif, expand_bases=True)):
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


def _classes_looks_like_itanium_vtable(runtime: IdaRuntime, ea: int, symbol_name: str) -> bool:
    if is_vtable_symbol_name(symbol_name) and (not symbol_name.startswith("??_7")):
        return True
    ida_name = runtime.mod("ida_name")
    ptr_size = runtime.pointer_size()
    first = runtime.read_pointer(ea)
    second = runtime.read_pointer(ea + ptr_size)
    second_name = ida_name.get_name(second) or ""
    return first == 0 and str(second_name).startswith(("__ZTI", "_ZTI"))


def _classes_runtime_vtable_member(
    runtime: IdaRuntime, entry_ea: int, slot: int
) -> tuple[dict[str, Any] | None, str | None]:
    ida_name = runtime.mod("ida_name")
    ida_bytes = runtime.mod("ida_bytes")
    ida_funcs = runtime.mod("ida_funcs")
    target = runtime.read_pointer(entry_ea)
    if target == 0:
        return (None, "null_target")
    name = ida_name.get_name(target) or ""
    if (name or "").startswith(RTTI_SYMBOL_PREFIXES):
        return (None, "rtti_boundary")
    flags = ida_bytes.get_flags(target)
    is_code = bool(ida_bytes.is_code(flags)) or ida_funcs.get_func(target) is not None
    if not is_code:
        return (None, "non_function_target")
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


def _classes_runtime_vtable_members(runtime: IdaRuntime, slot_ea: int, *, slot_limit: int, ptr_size: int):
    rows: list[dict[str, Any]] = []
    for slot in range(max(1, slot_limit)):
        entry_ea = slot_ea + slot * ptr_size
        member, stop_reason = _classes_runtime_vtable_member(runtime, entry_ea, slot)
        if member is None:
            return (rows, stop_reason)
        rows.append(member)
    return (rows, "slot_limit")


def _classes_raw_vtable_dump(runtime: IdaRuntime, identifier: str, *, slot_limit: int = 64) -> dict[str, Any]:
    table_ea = runtime.resolve_address(identifier)
    symbol_name = runtime.mod("ida_name").get_name(table_ea) or str(identifier)
    demangled = runtime.demangle_name(symbol_name)
    ptr_size = runtime.pointer_size()
    abi, slot_ea, header = _classes_vtable_header(runtime, table_ea, symbol_name, ptr_size=ptr_size)
    members, stop_reason = _classes_runtime_vtable_members(runtime, slot_ea, slot_limit=slot_limit, ptr_size=ptr_size)
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


def _classes_raise_non_materialized_class_error(runtime: IdaRuntime, name: str, tif) -> None:
    kind = runtime.classify_tinfo(tif)
    if kind in {"struct", "union"}:
        raise IdaOperationError(
            f"type `{name}` exists as a {kind}, but is not class-materialized in local types; "
            + _classes_class_materialization_hint(runtime, name)
        )
    raise IdaOperationError(f"type `{name}` exists as `{kind}`, but is not class-materialized in local types")


def _classes_class_materialization_hint(runtime: IdaRuntime, name: str) -> str:
    hints = [
        f"try `type show {name}`",
        f"`type class candidates {name}`",
        "then import a concrete class layout with `type declare --replace`",
    ]
    evidence = _classes_symbol_evidence(runtime, name)
    if evidence:
        hints.append("symbol evidence: " + ", ".join(evidence))
    return "; ".join(hints)


def _classes_symbol_evidence(runtime: IdaRuntime, name: str) -> list[str]:
    try:
        symbols = runtime.find_symbols(pattern=name, ignore_case=True)
    except Exception as exc:
        if not is_recoverable_ida_error(exc):
            raise
        return []
    vtable_count = 0
    typeinfo_count = 0
    function_count = 0
    for item in symbols:
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


def _classes_local_type_candidate_rows(
    runtime: IdaRuntime,
    pattern: str,
    kind_filter: set[str],
    seen: set[tuple[str, str, str]],
    *,
    regex: bool,
    ignore_case: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in runtime.list_named_types(pattern=pattern or None, regex=regex, ignore_case=ignore_case):
        key = ("local_type", str(item.get("name") or ""), "")
        if key in seen or (kind_filter and "local_type" not in kind_filter):
            continue
        seen.add(key)
        rows.append(
            {"kind": "local_type", "name": item.get("name"), "decl": item.get("decl"), "type_kind": item.get("kind")}
        )
    return rows


def _classes_symbol_candidate_rows(
    runtime: IdaRuntime,
    pattern: str,
    kind_filter: set[str],
    seen: set[tuple[str, str, str]],
    *,
    regex: bool,
    ignore_case: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in runtime.find_symbols(pattern=pattern or None, regex=regex, ignore_case=ignore_case):
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


def _classes_require_class_tinfo(runtime: IdaRuntime, name: str):
    tif = runtime.find_named_type(name)
    if tif is None:
        raise IdaOperationError(f"class not found: {name}")
    if not runtime.is_class_tinfo(tif):
        _classes_raise_non_materialized_class_error(runtime, name, tif)
    return tif


def _classes_class_list(context: OperationContext, request: _classes_ClassListRequest) -> list[dict[str, Any]]:
    return context.runtime.list_named_classes(
        pattern=request.pattern,
        regex=request.regex,
        ignore_case=request.ignore_case,
    )


def _classes_class_candidates(
    context: OperationContext, request: _classes_ClassCandidatesRequest
) -> list[dict[str, Any]]:
    runtime = context.runtime
    kind_filter = set(request.kinds)
    seen: set[tuple[str, str, str]] = set()
    rows = _classes_local_type_candidate_rows(
        runtime,
        request.pattern,
        kind_filter,
        seen,
        regex=request.regex,
        ignore_case=request.ignore_case,
    )
    rows.extend(
        _classes_symbol_candidate_rows(
            runtime,
            request.pattern,
            kind_filter,
            seen,
            regex=request.regex,
            ignore_case=request.ignore_case,
        )
    )
    rows.sort(key=lambda item: (str(item.get("kind") or ""), str(item.get("name") or "").lower()))
    return rows


def _classes_class_show(context: OperationContext, request: _classes_ClassNameRequest) -> dict[str, Any]:
    runtime = context.runtime
    tif = _classes_require_class_tinfo(runtime, request.name)
    payload = dict(runtime.class_summary(tif, name=request.name, decl_multi=True))
    payload["members"] = _classes_flatten_class_fields(runtime, tif, derived_only=False)
    return payload


def _classes_class_hierarchy(context: OperationContext, request: _classes_ClassNameRequest) -> dict[str, Any]:
    runtime = context.runtime
    name = request.name
    classes, children = _classes_class_graph(runtime)
    if name not in classes:
        tif = runtime.find_named_type(name)
        if tif is not None and (not runtime.is_class_tinfo(tif)):
            _classes_raise_non_materialized_class_error(runtime, name, tif)
        raise IdaOperationError(f"class not found: {name}")
    base_edges = {class_name: row.get("bases") or [] for class_name, row in classes.items()}
    known = set(classes)
    ancestors = _classes_walk_graph(list(classes[name].get("bases") or []), base_edges, known=known)
    descendants = _classes_walk_graph(list(children.get(name, [])), children, known=known)
    return {
        "name": name,
        "bases": classes[name].get("bases") or [],
        "derived": children.get(name, []),
        "ancestors": ancestors,
        "descendants": descendants,
    }


def _classes_class_fields(context: OperationContext, request: _classes_ClassFieldsRequest) -> dict[str, Any]:
    runtime = context.runtime
    tif = _classes_require_class_tinfo(runtime, request.name)
    return {
        "name": request.name,
        "kind": "class_fields",
        "derived_only": request.derived_only,
        "fields": _classes_flatten_class_fields(runtime, tif, derived_only=request.derived_only),
    }


def _classes_class_vtable(context: OperationContext, request: _classes_ClassVtableRequest) -> dict[str, Any]:
    runtime = context.runtime
    tif = _classes_require_class_tinfo(runtime, request.name)
    vtable_name = runtime.class_vtable_type_name(tif)
    if not vtable_name:
        raise IdaOperationError(f"class has no vtable type: {request.name}")
    vtable_tif = runtime.get_named_type(vtable_name)
    payload = {
        "name": request.name,
        "kind": "class_vtable",
        "vtable_type": vtable_name,
        "decl": runtime.tinfo_decl(vtable_tif, name=vtable_name, multi=True),
        "members": _classes_vtable_members(runtime, vtable_tif),
    }
    if request.runtime:
        identifier = runtime.class_runtime_vtable_identifier(tif, name=request.name)
        if identifier is not None:
            payload["runtime_vtable"] = _classes_raw_vtable_dump(runtime, identifier)
    return payload


# ---- Miscellaneous operations ----


@dataclass(frozen=True)
class _misc_ReanalyzeRequest:
    identifier: str
    end: str | None = None


@dataclass(frozen=True)
class _misc_ReanalyzeRangeResult:
    mode: str
    start: str
    end: str
    waited: bool


@dataclass(frozen=True)
class _misc_ReanalyzeFunctionResult:
    mode: str
    function: str
    start: str
    end: str
    waited: bool


def _misc_parse_reanalyze(params: Mapping[str, Any]) -> _misc_ReanalyzeRequest:
    return _misc_ReanalyzeRequest(
        identifier=require_str(params.get("identifier"), field="identifier"), end=optional_str(params.get("end"))
    )


def _misc_reanalyze(
    context: OperationContext, request: _misc_ReanalyzeRequest
) -> _misc_ReanalyzeRangeResult | _misc_ReanalyzeFunctionResult:
    runtime = context.runtime
    ida_auto = runtime.mod("ida_auto")
    ida_funcs = runtime.mod("ida_funcs")
    if request.end is not None:
        start_ea = runtime.resolve_address(request.identifier)
        end_ea = runtime.resolve_address(request.end)
        if end_ea <= start_ea:
            raise IdaOperationError("reanalyze range end must be greater than the start")
        ida_auto.plan_and_wait(start_ea, end_ea, True)
        return _misc_ReanalyzeRangeResult(mode="range", start=hex(start_ea), end=hex(end_ea), waited=True)
    try:
        func = runtime.resolve_function(request.identifier)
    except IdaOperationError:
        ea = runtime.resolve_address(request.identifier)
        ida_auto.plan_and_wait(ea, ea + 1, True)
        return _misc_ReanalyzeRangeResult(mode="address", start=hex(ea), end=hex(ea + 1), waited=True)
    ea = func.start_ea
    ida_funcs.reanalyze_function(func)
    ida_auto.auto_wait()
    return _misc_ReanalyzeFunctionResult(
        mode="function", function=ida_funcs.get_func_name(ea), start=hex(ea), end=hex(func.end_ea), waited=True
    )


# ---- Operation registry and dispatch ----

_OPERATION_SPECS: tuple[OperationSpec[Any, Any], ...] = (
    OperationSpec(name="database_info", run=_database_database_info),
    OperationSpec(name="segment_list", parse=_segments_parse_segment_list, run=_segments_segment_list),
    OperationSpec(name="function_list", parse=_functions_parse_function_list, run=_functions_function_list),
    OperationSpec(name="function_show", parse=_functions_parse_identifier, run=_functions_function_show),
    OperationSpec(name="function_frame", parse=_functions_parse_identifier, run=_functions_function_frame),
    OperationSpec(name="function_stackvars", parse=_functions_parse_identifier, run=_functions_function_stackvars),
    OperationSpec(name="function_callers", parse=_functions_parse_identifier, run=_functions_function_callers),
    OperationSpec(name="function_callees", parse=_functions_parse_identifier, run=_functions_function_callees),
    OperationSpec(name="disasm", parse=_functions_parse_identifier, run=_functions_disasm),
    OperationSpec(name="disasm_range", parse=_functions_parse_disasm_range, run=_functions_disasm_range),
    OperationSpec(name="decompile", parse=_functions_parse_decompile, run=_functions_decompile),
    OperationSpec(name="ctree", parse=_functions_parse_ctree, run=_functions_ctree),
    OperationSpec(name="search_bytes", parse=_search_parse_search_bytes, run=_search_search_bytes),
    OperationSpec(name="xrefs", parse=_search_parse_xrefs, run=_search_xrefs),
    OperationSpec(name="strings", parse=_search_parse_strings, run=_search_strings),
    OperationSpec(name="imports", run=_search_imports),
    OperationSpec(name="bookmark_get", parse=_bookmarks_parse_get, run=_bookmarks_get_bookmark),
    OperationSpec(
        name="bookmark_add",
        parse=_bookmarks_parse_add,
        run=_bookmarks_add_bookmark,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_bookmarks_preview_single_slot,
            capture_after=_bookmarks_preview_single_slot,
            rollback=_bookmarks_restore_bookmark_state,
            prepare=_bookmarks_prepare_add_bookmark,
        ),
    ),
    OperationSpec(
        name="bookmark_set",
        parse=_bookmarks_parse_set,
        run=_bookmarks_set_bookmark,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_bookmarks_preview_single_slot,
            capture_after=_bookmarks_preview_single_slot,
            rollback=_bookmarks_restore_bookmark_state,
        ),
    ),
    OperationSpec(
        name="bookmark_delete",
        parse=_bookmarks_parse_delete,
        run=_bookmarks_delete_bookmark,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_bookmarks_preview_single_slot,
            capture_after=_bookmarks_preview_single_slot,
            rollback=_bookmarks_restore_bookmark_state,
        ),
    ),
    OperationSpec(name="comment_get", parse=_comments_parse_lookup, run=_comments_comment_view),
    OperationSpec(
        name="comment_set",
        parse=_comments_parse_change,
        run=_comments_change_comment,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_comments_comment_view,
            capture_after=_comments_comment_view,
            rollback=_comments_restore_comment,
        ),
    ),
    OperationSpec(
        name="comment_delete",
        parse=_comments_parse_lookup,
        run=_comments_change_comment,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_comments_comment_view,
            capture_after=_comments_comment_view,
            rollback=_comments_restore_comment,
        ),
    ),
    OperationSpec(
        name="name_set",
        parse=_names_parse_name_set,
        run=_names_set_name,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_names_name_state,
            capture_after=_names_name_state,
            rollback=_names_restore_name,
            prepare=_names_prepare_name_set,
        ),
    ),
    OperationSpec(name="local_list", parse=_locals_parse_local_list, run=_locals_local_list),
    OperationSpec(
        name="local_rename",
        parse=_locals_parse_local_rename,
        run=_locals_local_rename,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_locals_local_list,
            capture_after=_locals_local_list,
            cleanup=_locals_cleanup_local_preview,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="local_retype",
        parse=_locals_parse_local_retype,
        run=_locals_local_retype,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_locals_local_list,
            capture_after=_locals_local_list,
            cleanup=_locals_cleanup_local_preview,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="local_update",
        parse=_locals_parse_local_update,
        run=_locals_local_update,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_locals_local_list,
            capture_after=_locals_local_list,
            cleanup=_locals_cleanup_local_preview,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="local_apply_plan",
        parse=_locals_parse_local_apply_plan,
        run=_locals_local_apply_plan,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_locals_local_list,
            capture_after=_locals_local_list,
            cleanup=_locals_cleanup_local_preview,
            use_undo=True,
        ),
    ),
    OperationSpec(name="proto_get", parse=_prototypes_parse_proto_get, run=_prototypes_proto_get),
    OperationSpec(name="proto_check", parse=_prototypes_parse_proto_check, run=_prototypes_proto_check),
    OperationSpec(
        name="proto_set",
        parse=_prototypes_parse_proto_set,
        run=_prototypes_proto_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_prototypes_prototype_view,
            capture_after=_prototypes_prototype_view,
            use_undo=True,
        ),
    ),
    OperationSpec(name="type_list", parse=_named_types_parse_list, run=_named_types_type_list),
    OperationSpec(name="type_show", parse=_named_types_parse_show, run=_named_types_type_show),
    OperationSpec(name="type_deps", parse=_named_types_parse_show, run=_named_types_type_deps),
    OperationSpec(
        name="type_declare",
        parse=_type_declare_parse_request,
        run=_type_declare_type_declare,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_type_declare_preview_snapshot,
            capture_after=_type_declare_preview_snapshot,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="type_declare_check",
        parse=_type_declare_parse_check_request,
        run=_type_declare_type_declare_check,
    ),
    OperationSpec(name="class_list", parse=_classes_parse_list, run=_classes_class_list),
    OperationSpec(name="class_candidates", parse=_classes_parse_candidates, run=_classes_class_candidates),
    OperationSpec(name="class_show", parse=_classes_parse_name, run=_classes_class_show),
    OperationSpec(name="class_hierarchy", parse=_classes_parse_name, run=_classes_class_hierarchy),
    OperationSpec(name="class_fields", parse=_classes_parse_fields, run=_classes_class_fields),
    OperationSpec(name="class_vtable", parse=_classes_parse_class_vtable, run=_classes_class_vtable),
    OperationSpec(name="struct_list", parse=_named_types_parse_list, run=_named_types_struct_list),
    OperationSpec(name="struct_show", parse=_named_types_parse_struct_show, run=_named_types_struct_view),
    OperationSpec(
        name="struct_field_set",
        parse=_named_types_parse_struct_field_set,
        run=_named_types_struct_field_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_named_types_struct_view,
            capture_after=_named_types_struct_view,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="struct_field_rename",
        parse=_named_types_parse_struct_field_rename,
        run=_named_types_struct_field_rename,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_named_types_struct_view,
            capture_after=_named_types_struct_view,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="struct_field_delete",
        parse=_named_types_parse_struct_field_delete,
        run=_named_types_struct_field_delete,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_named_types_struct_view,
            capture_after=_named_types_struct_view,
            use_undo=True,
        ),
    ),
    OperationSpec(name="enum_list", parse=_named_types_parse_list, run=_named_types_enum_list),
    OperationSpec(name="enum_show", parse=_named_types_parse_enum_show, run=_named_types_enum_view),
    OperationSpec(
        name="enum_member_set",
        parse=_named_types_parse_enum_member_set,
        run=_named_types_enum_member_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_named_types_enum_view,
            capture_after=_named_types_enum_view,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="enum_member_rename",
        parse=_named_types_parse_enum_member_rename,
        run=_named_types_enum_member_rename,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_named_types_enum_view,
            capture_after=_named_types_enum_view,
            use_undo=True,
        ),
    ),
    OperationSpec(
        name="enum_member_delete",
        parse=_named_types_parse_enum_member_delete,
        run=_named_types_enum_member_delete,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_named_types_enum_view,
            capture_after=_named_types_enum_view,
            use_undo=True,
        ),
    ),
    OperationSpec(name="reanalyze", parse=_misc_parse_reanalyze, run=_misc_reanalyze, mutating=True),
)
_OPERATIONS = MappingProxyType({spec.name: spec for spec in _OPERATION_SPECS})
if len(_OPERATIONS) != len(_OPERATION_SPECS):
    raise RuntimeError("duplicate remote operation name")
SUPPORTED_OPERATIONS = tuple(_OPERATIONS)
MUTATING_OPERATIONS = tuple(name for name, spec in _OPERATIONS.items() if spec.mutating)


def dispatch(db, op: str, params: dict[str, Any], preview: bool):
    """Execute one idac operation in the active Nexus database interpreter."""

    del db  # Nexus binds the active ida-domain Database; IDAPython owns the APIs below.
    if not isinstance(op, str) or not op:
        raise IdaOperationError("operation name is required")
    if not isinstance(params, Mapping):
        raise IdaOperationError("operation parameters must be an object")
    if not isinstance(preview, bool):
        raise IdaOperationError("preview must be a boolean")
    if "preview" in params:
        raise IdaOperationError("preview must be passed as the dispatch argument")
    operation = _OPERATIONS.get(op)
    if operation is None:
        raise IdaOperationError(f"unsupported operation: {op}")

    runtime = IdaRuntime()
    context = OperationContext(runtime=runtime, preview=preview)
    request = operation.parse(params) if operation.parse is not None else None
    if preview:
        result = run_preview(
            context,
            operation.name,
            request,
            operation.run,
            operation.preview,
        )
    elif operation.mutating and operation.preview is not None and operation.preview.use_undo:
        ida_undo = runtime.mod("ida_undo")
        if not ida_undo.create_undo_point(
            action_name=f"idac_{operation.name}",
            label=f"idac {operation.name}",
        ):
            raise IdaOperationError(f"{operation.name} requires IDA undo support for atomic mutation")
        try:
            result = operation.run(context, request)
        except BaseException as exc:
            if not ida_undo.perform_undo():
                raise IdaOperationError(
                    f"{operation.name} failed and IDA could not restore the mutation via undo"
                ) from exc
            raise
        if isinstance(result, Mapping) and result.get("success") is False and not ida_undo.perform_undo():
            raise IdaOperationError(
                f"{operation.name} reported failure and IDA could not restore the mutation via undo"
            )
    else:
        result = operation.run(context, request)
    return payload_from_model(result)
