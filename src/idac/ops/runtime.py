from __future__ import annotations

import contextlib
import importlib
from dataclasses import dataclass
from typing import Any, Optional

from . import runtime_classes
from .helpers.matching import text_matches


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
        "idc",
        "ida_auto",
        "ida_bytes",
        "ida_entry",
        "ida_frame",
        "ida_funcs",
        "ida_ida",
        "ida_idc",
        "ida_idp",
        "ida_kernwin",
        "ida_lines",
        "ida_loader",
        "ida_moves",
        "ida_name",
        "ida_nalt",
        "ida_range",
        "ida_segment",
        "ida_strlist",
        "ida_typeinf",
        "ida_ua",
        "ida_undo",
        "ida_xref",
    }
)
_PYTHON_SCOPE_MODULE_NAMES = (
    "idaapi",
    "ida_auto",
    "ida_bytes",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_ida",
    "ida_idc",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_moves",
    "ida_name",
    "ida_nalt",
    "ida_range",
    "ida_segment",
    "ida_strlist",
    "ida_srclang",
    "ida_typeinf",
    "ida_ua",
    "ida_undo",
    "ida_xref",
)


def is_recoverable_ida_error(exc: BaseException) -> bool:
    """Return whether an IDA exception should degrade gracefully."""

    return isinstance(exc, RECOVERABLE_IDA_ERRORS) and not isinstance(exc, IdaOperationError)


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
    except Exception as exc:
        if not ida_undo.perform_undo():
            raise IdaOperationError(restore_failure_message or restore_error_message) from exc
        raise
    else:
        if not ida_undo.perform_undo():
            raise IdaOperationError(restore_error_message)


class IdaRuntime:
    """Small facade over imported IDA modules plus convenience helpers."""

    def __init__(
        self,
        *,
        database_path: Optional[str] = None,
        python_scope: Optional[dict[str, Any]] = None,
    ) -> None:
        self.database_path = database_path
        self._module_cache: dict[str, Any] = {}
        self._python_scope = python_scope

    @staticmethod
    def member_name(member) -> str:
        """Return the member name as a normalized string."""

        return member.name or ""

    @staticmethod
    def member_has(member, attr: str) -> bool:
        """Call an IDA member predicate when present."""

        return bool(getattr(member, attr, lambda: False)())

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

    @staticmethod
    def is_recoverable_error(exc: BaseException) -> bool:
        return is_recoverable_ida_error(exc)

    def python_exec_scope(self, *, persist: bool) -> dict[str, Any]:
        """Build the globals dict used by ``py exec`` operations."""

        scope: dict[str, Any]
        if persist:
            if self._python_scope is None:
                self._python_scope = {}
            scope = self._python_scope
        else:
            scope = {}
        for name in _PYTHON_SCOPE_MODULE_NAMES:
            try:
                scope.setdefault(name, self.mod(name))
            except (ImportError, OSError):
                continue
        with contextlib.suppress(IdaOperationError):
            scope.setdefault("ida_hexrays", self.require_hexrays())
        scope.setdefault("idc", self.idc)
        scope.setdefault("idautils", self.idautils)
        scope["result"] = None
        return scope

    def udt_members(self, tif):
        """Return UDT members for ``tif`` or an empty iterable when unavailable."""

        udt = self.ida_typeinf.udt_type_data_t()
        return udt if tif.get_udt_details(udt) else ()

    def _member_pointed_name(self, member) -> Optional[str]:
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
    def _looks_like_demangled_identifier(text: str) -> bool:
        stripped = str(text).strip()
        return any(
            marker in stripped
            for marker in (
                "::",
                "(",
                "~",
                "operator",
            )
        )

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

    def _render_demangled_lookup_texts(self, ea: int) -> list[str]:
        texts: list[str] = []
        short_flags = self.ida_name.GN_VISIBLE | self.ida_name.GN_DEMANGLED | self.ida_name.GN_SHORT
        long_flags = self.ida_name.GN_VISIBLE | self.ida_name.GN_DEMANGLED | self.ida_name.GN_LONG
        with suppress_recoverable_ida_errors():
            texts.extend(self._lookup_text_variants(self.ida_name.get_ea_name(ea, short_flags) or ""))
        with suppress_recoverable_ida_errors():
            texts.extend(self._lookup_text_variants(self.ida_name.get_ea_name(ea, long_flags) or ""))
        return texts

    def _raw_name_for_lookup(self, ea: int, raw_name: str | None = None) -> str:
        resolved = str(raw_name or "").strip()
        if resolved:
            return resolved

        with suppress_recoverable_ida_errors():
            return str(self.ida_name.get_name(ea) or "").strip()
        return ""

    def _demangled_lookup_texts(self, ea: int, raw_name: str | None = None) -> list[str]:
        texts = self._render_demangled_lookup_texts(ea)
        demangled_name = self.demangle_name(self._raw_name_for_lookup(ea, raw_name))
        texts.extend(self._lookup_text_variants(demangled_name or ""))
        return texts

    def _resolve_demangled_function_address(self, identifier: str) -> Optional[int]:
        if not self._looks_like_demangled_identifier(identifier):
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
        return self.function_name(ea), hex(ea)

    def function_ea(self, identifier: str) -> int:
        return self.resolve_function(identifier).start_ea

    def database_bounds(self) -> tuple[int, int]:
        return self.ida_ida.inf_get_min_ea(), self.ida_ida.inf_get_max_ea()

    def _segment_name(self, segment) -> str:
        ida_segment = self.ida_segment
        for attr in ("get_visible_segm_name", "get_segm_name"):
            getter = getattr(ida_segment, attr, None)
            if not callable(getter):
                continue
            try:
                value = getter(segment)
            except TypeError:
                continue
            except Exception as exc:
                if not self.is_recoverable_error(exc):
                    raise
                continue
            text = str(value or "").strip()
            if text:
                return text
        return hex(int(segment.start_ea))

    def iter_segments(self) -> tuple[SegmentRange, ...]:
        ida_segment = self.mod("ida_segment")
        rows: list[SegmentRange] = []
        segment = ida_segment.get_first_seg()
        while segment is not None:
            start_ea = int(segment.start_ea)
            end_ea = int(segment.end_ea)
            rows.append(
                SegmentRange(
                    name=self._segment_name(segment),
                    start_ea=start_ea,
                    end_ea=end_ea,
                )
            )
            next_segment = ida_segment.get_next_seg(start_ea)
            if next_segment is None:
                break
            if int(next_segment.start_ea) <= start_ea:
                raise IdaOperationError("segment enumeration did not advance")
            segment = next_segment
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
    def _validate_range_endpoint(
        *,
        label: str,
        value: int | None,
        bounds_start: int,
        bounds_end: int,
    ) -> None:
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

        bounds_start, bounds_end = self.database_bounds()
        range_start, range_end = bounds_start, bounds_end
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
            label="end",
            value=range_end if end is not None else None,
            bounds_start=bounds_start,
            bounds_end=bounds_end,
        )
        if range_end <= range_start:
            raise IdaOperationError("range end must be greater than the start")

        clipped = tuple(
            SegmentRange(
                name=item.name,
                start_ea=max(item.start_ea, range_start),
                end_ea=min(item.end_ea, range_end),
            )
            for item in segments
            if min(item.end_ea, range_end) > max(item.start_ea, range_start)
        )
        if not clipped:
            raise IdaOperationError(f"range does not overlap segment: {selector_text}")
        return clipped

    def database_bits(self) -> int:
        if self.ida_ida.inf_is_64bit():
            return 64
        if self.ida_ida.inf_is_32bit_exactly():
            return 32
        return 16

    def xref_type_name(self, type_code: int) -> str:
        names = {
            self.ida_xref.fl_U: "Data_Unknown",
            self.ida_xref.dr_O: "Data_Offset",
            self.ida_xref.dr_W: "Data_Write",
            self.ida_xref.dr_R: "Data_Read",
            self.ida_xref.dr_T: "Data_Text",
            self.ida_xref.dr_I: "Data_Informational",
            self.ida_xref.fl_CF: "Code_Far_Call",
            self.ida_xref.fl_CN: "Code_Near_Call",
            self.ida_xref.fl_JF: "Code_Far_Jump",
            self.ida_xref.fl_JN: "Code_Near_Jump",
            self.ida_xref.fl_F: "Ordinary_Flow",
        }
        return names.get(type_code, f"xref_{type_code}")

    def xref_kind(self, *, iscode: bool, type_code: int) -> str:
        if type_code in (self.ida_xref.fl_CF, self.ida_xref.fl_CN):
            return "call"
        if type_code in (self.ida_xref.fl_JF, self.ida_xref.fl_JN):
            return "jump"
        if type_code == self.ida_xref.fl_F:
            return "flow"
        if type_code == self.ida_xref.dr_O:
            return "offset"
        if type_code == self.ida_xref.dr_W:
            return "write"
        if type_code == self.ida_xref.dr_R:
            return "read"
        if type_code == self.ida_xref.dr_T:
            return "text"
        if type_code == self.ida_xref.dr_I:
            return "informational"
        if type_code == self.ida_xref.fl_U:
            return "unknown"
        return "code" if iscode else "data"

    def _normalize_xref(self, xref) -> XrefRecord:
        type_code = int(xref.type)
        return XrefRecord(
            from_ea=int(xref.frm),
            to_ea=int(xref.to),
            type=self.xref_type_name(type_code),
            kind=self.xref_kind(iscode=bool(xref.iscode), type_code=type_code),
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
        range_start, range_end = bounds_start, bounds_end
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
            label="end",
            value=range_end if end is not None else None,
            bounds_start=bounds_start,
            bounds_end=bounds_end,
        )
        if range_end <= range_start:
            raise IdaOperationError("range end must be greater than the start")
        return range_start, range_end

    def compile_binpat(
        self,
        pattern: str,
        *,
        ea: int | None = None,
        radix: int = 16,
        strlit_encoding: int = -1,
    ):
        """Compile an IDA byte-pattern string without going through ``find_bytes``."""

        text = str(pattern or "").strip()
        if not text:
            raise IdaOperationError("byte pattern is required")
        compile_ea = self.database_bounds()[0] if ea is None else ea
        try:
            compiled = self.ida_bytes.compiled_binpat_vec_t.parse(
                compile_ea,
                text,
                radix,
                strlit_encoding,
            )
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

    def get_named_type(self, name: str, *, kind: Optional[str] = None):
        """Resolve a named type, optionally constraining the expected kind."""

        tif = self.ida_typeinf.tinfo_t()
        kind_attr = {
            "struct": "BTF_STRUCT",
            "union": "BTF_UNION",
            "enum": "BTF_ENUM",
        }.get(kind or "")
        if kind_attr is None:
            ok = tif.get_named_type(None, name)
        else:
            ok = tif.get_named_type(
                self.ida_typeinf.get_idati(),
                name,
                getattr(self.ida_typeinf, kind_attr),
                True,
                False,
            )
        if not ok:
            raise IdaOperationError(f"type not found: {name}")
        return tif

    def find_named_type(self, name: str, *, kind: Optional[str] = None):
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

    def demangle_name(self, name: str) -> Optional[str]:
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

    def tinfo_decl(self, tif, *, name: Optional[str] = None, multi: bool = True) -> str:
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
        query: Optional[str] = None,
        pattern: Optional[str] = None,
        glob: bool = False,
        regex: bool = False,
        ignore_case: bool = False,
        kinds: Optional[set[str]] = None,
    ) -> list[dict[str, Any]]:
        """List named local types, optionally filtered by substring and kind."""

        pattern_text = str(pattern if pattern is not None else query or "")
        rows: list[dict[str, Any]] = []
        for tif in self.ida_typeinf.get_idati().named_types():
            name = tif.get_type_name() or ""
            kind = self.classify_tinfo(tif)
            if pattern_text and not text_matches(
                name,
                pattern=pattern_text,
                glob=glob,
                regex=regex,
                ignore_case=ignore_case or query is not None,
            ):
                continue
            if kinds is not None and kind not in kinds:
                continue
            rows.append(
                {
                    "name": name,
                    "kind": kind,
                    "decl": self.tinfo_decl(tif, name=name, multi=False),
                }
            )
        rows.sort(key=lambda item: (item["kind"], item["name"].lower()))
        return rows

    def iter_named_types(self):
        yield from self.ida_typeinf.get_idati().named_types()

    def _looks_like_vtable_type(self, tif) -> bool:
        return runtime_classes.looks_like_vtable_type(self, tif)

    def is_class_tinfo(self, tif) -> bool:
        return runtime_classes.is_class_tinfo(self, tif)

    def class_base_names(self, tif) -> list[str]:
        return runtime_classes.class_base_names(self, tif)

    def class_vtable_type_name(self, tif) -> Optional[str]:
        return runtime_classes.class_vtable_type_name(self, tif)

    def vtable_ea(self, tif) -> Optional[int]:
        return runtime_classes.vtable_ea(self, tif)

    def class_vtable_ea(self, tif) -> Optional[int]:
        return runtime_classes.class_vtable_ea(self, tif)

    def class_runtime_vtable_identifier(self, tif, *, name: Optional[str] = None) -> Optional[str]:
        return runtime_classes.class_runtime_vtable_identifier(self, tif, name=name)

    def class_summary(self, tif, *, name: Optional[str] = None, decl_multi: bool = False) -> dict[str, Any]:
        return runtime_classes.class_summary(self, tif, name=name, decl_multi=decl_multi)

    def list_named_classes(
        self,
        *,
        query: Optional[str] = None,
        pattern: Optional[str] = None,
        glob: bool = False,
        regex: bool = False,
        ignore_case: bool = False,
    ) -> list[dict[str, Any]]:
        return runtime_classes.list_named_classes(
            self,
            query=query,
            pattern=pattern,
            glob=glob,
            regex=regex,
            ignore_case=ignore_case,
        )

    def iter_names(self):
        for ea, name in self.idautils.Names():
            yield ea, name, self.demangle_name(name)

    def find_symbols(
        self,
        *,
        query: Optional[str] = None,
        pattern: Optional[str] = None,
        glob: bool = False,
        regex: bool = False,
        ignore_case: bool = False,
    ) -> list[dict[str, Any]]:
        pattern_text = str(pattern if pattern is not None else query or "")
        rows: list[dict[str, Any]] = []
        for ea, name, demangled in self.iter_names():
            haystack = "\n".join(part for part in (name, demangled or "") if part)
            if pattern_text and not text_matches(
                haystack,
                pattern=pattern_text,
                glob=glob,
                regex=regex,
                ignore_case=ignore_case or query is not None,
            ):
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

    def find_vtable_symbol(self, class_name: str) -> Optional[dict[str, Any]]:
        return runtime_classes.find_vtable_symbol(self, class_name)

    def pointer_size(self) -> int:
        if self.ida_ida.inf_is_64bit():
            return 8
        if self.ida_ida.inf_is_32bit_exactly():
            return 4
        if self.ida_ida.inf_is_16bit():
            return 2
        return 2

    def pointer_bits(self) -> int:
        return self.pointer_size() * 8

    def read_pointer(self, ea: int) -> int:
        width = self.pointer_size()
        if width == 8:
            return self.ida_bytes.get_qword(ea)
        if width == 4:
            return self.ida_bytes.get_wide_dword(ea)
        return self.ida_bytes.get_wide_word(ea)

    def vtable_slot(self, offset_bits: int) -> int:
        return offset_bits // self.pointer_bits()

    def pseudocode_text(self, cfunc) -> str:
        """Render Hex-Rays pseudocode as plain text."""

        lines: list[str] = []
        for item in cfunc.get_pseudocode():
            lines.append(_strip_tags(self, item.line).rstrip())
        return "\n".join(lines)


def _strip_tags(runtime: IdaRuntime, text: Any) -> str:
    ida_lines = runtime.mod("ida_lines")
    return ida_lines.tag_remove(str(text or ""))


def _ea_text(runtime: IdaRuntime, ea: Any) -> Optional[str]:
    idaapi = runtime.mod("idaapi")
    try:
        value = int(ea)
    except (TypeError, ValueError):
        return None
    if value == idaapi.BADADDR:
        return None
    return hex(value)
