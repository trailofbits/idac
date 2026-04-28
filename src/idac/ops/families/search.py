from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass

from ..base import OperationContext, OperationSpec
from ..helpers.matching import pattern_from_params, text_matches
from ..helpers.params import optional_param_int, optional_str, require_str
from ..runtime import IdaOperationError, IdaRuntime, SegmentRange

MEBIBYTE = 1024 * 1024
MAX_DSC_STRING_SCAN_BYTES = 16 * MEBIBYTE


@dataclass(frozen=True)
class SearchBytesRequest:
    pattern: str
    segment: str
    start: str | None
    end: str | None
    limit: int


@dataclass(frozen=True)
class XrefsRequest:
    identifier: str


@dataclass(frozen=True)
class StringsRequest:
    pattern: str
    glob: bool
    regex: bool
    ignore_case: bool
    scan: bool
    segment: str
    start: str | None
    end: str | None


def _require_identifier(params: dict[str, object], *, key: str = "identifier") -> str:
    return require_str(params.get(key), field="address or identifier")


def _require_segment_selector(params: dict[str, object]) -> str:
    return require_str(params.get("segment"), field="segment selector")


def _parse_search_bytes(params: dict[str, object]) -> SearchBytesRequest:
    pattern = require_str(params.get("pattern"), field="byte pattern")
    segment = _require_segment_selector(params)
    start = optional_str(params.get("start"))
    end = optional_str(params.get("end"))
    limit = optional_param_int(params, "limit", label="search result limit", minimum=1) or 100
    return SearchBytesRequest(pattern=pattern, segment=segment, start=start, end=end, limit=limit)


def _match_row(address: int, function: str | None) -> dict[str, object]:
    if function:
        return {"address": hex(address), "function": function}
    return {"address": hex(address)}


def _bin_search_address(result: object) -> int:
    if isinstance(result, tuple):
        return int(result[0])
    return int(result)


def _search_bytes_from_cursor(runtime: IdaRuntime, start: int, end: int, compiled_pattern, flags: int) -> int:
    return _bin_search_address(runtime.mod("ida_bytes").bin_search(start, end, compiled_pattern, flags))


def _has_more_search_bytes_matches(
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
        match_ea = _search_bytes_from_cursor(runtime, scope_cursor, scope.end_ea, compiled_pattern, flags)
        if match_ea != badaddr:
            return True
    return False


def _search_bytes(context: OperationContext, request: SearchBytesRequest) -> dict[str, object]:
    runtime = context.runtime
    ida_bytes = runtime.mod("ida_bytes")
    idaapi = runtime.mod("idaapi")
    ranges = runtime.resolve_segment_ranges(
        request.segment,
        start=request.start,
        end=request.end,
        require_bounds=False,
    )
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW
    compiled_pattern = runtime.compile_binpat(request.pattern, ea=ranges[0].start_ea)

    rows: list[dict[str, object]] = []
    truncated = False
    for index, scope in enumerate(ranges):
        cursor = scope.start_ea
        while cursor < scope.end_ea and len(rows) < request.limit:
            match_ea = _search_bytes_from_cursor(runtime, cursor, scope.end_ea, compiled_pattern, flags)
            if match_ea == idaapi.BADADDR:
                break
            func = runtime.ida_funcs.get_func(match_ea)
            function_name = None if func is None else runtime.function_name(func.start_ea)
            rows.append(_match_row(match_ea, function_name))
            cursor = match_ea + 1
        if len(rows) == request.limit:
            truncated = _has_more_search_bytes_matches(
                runtime,
                ranges=ranges,
                start_index=index,
                cursor=cursor,
                compiled_pattern=compiled_pattern,
                flags=flags,
                badaddr=idaapi.BADADDR,
            )
            break
    return {
        "pattern": request.pattern,
        "segment": request.segment,
        "start": hex(ranges[0].start_ea),
        "end": hex(ranges[-1].end_ea),
        "limit": request.limit,
        "truncated": truncated,
        "ranges": [
            {"name": item.name, "start": hex(item.start_ea), "end": hex(item.end_ea)} for item in ranges
        ],
        "results": rows,
    }


def _parse_xrefs(params: dict[str, object]) -> XrefsRequest:
    return XrefsRequest(identifier=_require_identifier(params))


def _xrefs(
    context: OperationContext,
    request: XrefsRequest,
) -> list[dict[str, object]]:
    runtime = context.runtime
    ea = runtime.resolve_address(request.identifier)
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str, bool, str | None]] = set()
    for flags in (
        runtime.ida_xref.XREF_FLOW,
        runtime.ida_xref.XREF_CODE,
        runtime.ida_xref.XREF_DATA,
    ):
        for ref in runtime.xrefs_to(ea, flags=flags):
            func = runtime.ida_funcs.get_func(ref.from_ea)
            row: dict[str, object] = {
                "from": hex(ref.from_ea),
                "to": hex(ref.to_ea),
                "type": ref.type,
                "kind": ref.kind,
                "user": ref.user,
                "function": None if func is None else runtime.function_name(func.start_ea),
            }
            key = (row["from"], row["to"], row["type"], row["kind"], row["user"], row["function"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    rows.sort(key=lambda item: (item["kind"], item["from"]))
    return rows


def _parse_strings(params: dict[str, object]) -> StringsRequest:
    pattern, glob, regex, ignore_case = pattern_from_params(params)
    segment = _require_segment_selector(params)
    start = optional_str(params.get("start"))
    end = optional_str(params.get("end"))
    return StringsRequest(
        pattern=pattern,
        glob=glob,
        regex=regex,
        ignore_case=ignore_case,
        scan=bool(params.get("scan")),
        segment=segment,
        start=start,
        end=end,
    )


def _string_text(runtime: IdaRuntime, ea: int, length: int, strtype: int) -> str:
    value = runtime.ida_bytes.get_strlit_contents(ea, length, strtype)
    if value is None:
        return ""
    return value.decode("UTF-8", "replace")


def _defined_string_rows(
    runtime: IdaRuntime,
    *,
    ranges: tuple[SegmentRange, ...],
    pattern: str,
    glob: bool,
    regex: bool,
    ignore_case: bool,
) -> list[dict[str, object]]:
    ida_strlist = runtime.ida_strlist
    known_types = (
        "STRTYPE_TERMCHR",
        "STRTYPE_C",
        "STRTYPE_C_16",
        "STRTYPE_C_32",
        "STRTYPE_PASCAL",
        "STRTYPE_PASCAL_16",
        "STRTYPE_PASCAL_32",
        "STRTYPE_LEN2",
        "STRTYPE_LEN2_16",
        "STRTYPE_LEN2_32",
        "STRTYPE_LEN4",
        "STRTYPE_LEN4_16",
        "STRTYPE_LEN4_32",
    )
    string_types: list[int] = []
    seen_types: set[int] = set()
    for name in known_types:
        value = getattr(runtime.ida_nalt, name, None)
        if not isinstance(value, int) or value in seen_types:
            continue
        seen_types.add(value)
        string_types.append(value)

    options = ida_strlist.get_strlist_options()
    saved_strtypes = list(options.strtypes)
    saved_minlen = int(options.minlen)
    saved_display_only_existing_strings = bool(options.display_only_existing_strings)
    saved_only_7bit = bool(options.only_7bit)
    saved_ignore_heads = bool(options.ignore_heads)

    rows: list[dict[str, object]] = []
    try:
        options.strtypes = string_types or [runtime.ida_nalt.STRTYPE_C]
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
            text = _string_text(runtime, ea, int(item.length), int(item.type))
            if text_matches(text, pattern=pattern, glob=glob, regex=regex, ignore_case=ignore_case):
                rows.append({"address": hex(ea), "text": text})
    finally:
        options.strtypes = saved_strtypes
        options.minlen = saved_minlen
        options.display_only_existing_strings = saved_display_only_existing_strings
        options.only_7bit = saved_only_7bit
        options.ignore_heads = saved_ignore_heads
        ida_strlist.build_strlist()
    return rows


def _scan_string_rows(
    runtime: IdaRuntime,
    *,
    ranges: tuple[SegmentRange, ...],
    pattern: str,
    glob: bool,
    regex: bool,
    ignore_case: bool,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for scope in ranges:
        cursor = scope.start_ea
        while cursor < scope.end_ea:
            length = runtime.ida_bytes.get_max_strlit_length(
                cursor,
                runtime.ida_nalt.STRTYPE_C,
                runtime.ida_bytes.ALOPT_IGNHEADS,
            )
            if length < 5 or (cursor + length) > scope.end_ea:
                cursor += 1
                continue
            text = _string_text(runtime, cursor, length, runtime.ida_nalt.STRTYPE_C)
            if not text:
                cursor += 1
                continue
            if not text_matches(text, pattern=pattern, glob=glob, regex=regex, ignore_case=ignore_case):
                cursor += max(length, 1)
                continue
            rows.append({"address": hex(cursor), "text": text})
            cursor += max(length, 1)
    return rows


def _input_file_basename(runtime: IdaRuntime) -> str:
    for module_name in ("idaapi", "ida_nalt"):
        with contextlib.suppress(Exception):
            module = runtime.mod(module_name)
            getter = getattr(module, "get_input_file_path", None)
            if not callable(getter):
                continue
            path = str(getter() or "").strip()
            if path:
                return os.path.basename(path)
    return ""


def _is_current_file_dsc(runtime: IdaRuntime) -> bool:
    basename = _input_file_basename(runtime).lower()
    return basename == "dyld_shared_cache" or basename.startswith("dyld_shared_cache_")


def _range_total_size(ranges: tuple[SegmentRange, ...]) -> int:
    return sum(max(0, item.end_ea - item.start_ea) for item in ranges)


def _validate_dsc_string_scan_ranges(ranges: tuple[SegmentRange, ...]) -> None:
    requested = _range_total_size(ranges)
    if requested <= MAX_DSC_STRING_SCAN_BYTES:
        return
    raise IdaOperationError(
        "dyld shared cache string scans are limited to "
        f"{MAX_DSC_STRING_SCAN_BYTES // MEBIBYTE} MiB; requested {requested // MEBIBYTE} MiB"
    )


def _strings(context: OperationContext, request: StringsRequest) -> list[dict[str, object]]:
    runtime = context.runtime
    is_dsc = _is_current_file_dsc(runtime)
    ranges = runtime.resolve_segment_ranges(
        request.segment,
        start=request.start,
        end=request.end,
        require_bounds=is_dsc and request.scan,
        missing_message="dyld shared cache string scan requires both start and end addresses",
    )
    if request.scan:
        if is_dsc:
            _validate_dsc_string_scan_ranges(ranges)
        return _scan_string_rows(
            runtime,
            ranges=ranges,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
        )
    if is_dsc:
        raise IdaOperationError(
            "defined string listing is disabled for dyld shared caches; use "
            "`search strings --scan --segment ... --start ... --end ...` with a range of at most "
            f"{MAX_DSC_STRING_SCAN_BYTES // MEBIBYTE} MiB"
        )
    return _defined_string_rows(
        runtime,
        ranges=ranges,
        pattern=request.pattern,
        glob=request.glob,
        regex=request.regex,
        ignore_case=request.ignore_case,
    )


def _parse_imports(_params: dict[str, object]) -> None:
    return None


def _imports(context: OperationContext, request: None) -> list[dict[str, object]]:
    del request
    runtime = context.runtime
    modules: list[dict[str, object]] = []
    for index in range(runtime.ida_nalt.get_import_module_qty()):
        module_name = runtime.ida_nalt.get_import_module_name(index) or "<unnamed>"
        entries: list[dict[str, object]] = []

        def imp_cb(ea: int, name: str | None, ordinal: int, entries: list[dict[str, object]] = entries) -> bool:
            entries.append(
                {
                    "address": hex(ea),
                    "name": name or f"ordinal_{ordinal}",
                    "ordinal": ordinal,
                }
            )
            return True

        runtime.ida_nalt.enum_import_names(index, imp_cb)
        modules.append({"module": module_name, "entries": entries})
    return modules


def search_operations() -> tuple[OperationSpec[object, object], ...]:
    return (
        OperationSpec(
            name="search_bytes",
            parse=_parse_search_bytes,
            run=_search_bytes,
        ),
        OperationSpec(
            name="xrefs",
            parse=_parse_xrefs,
            run=_xrefs,
        ),
        OperationSpec(
            name="strings",
            parse=_parse_strings,
            run=_strings,
        ),
        OperationSpec(
            name="imports",
            parse=_parse_imports,
            run=_imports,
        ),
    )


def op_strings(runtime: IdaRuntime, params: dict[str, object]) -> list[dict[str, object]]:
    request = _parse_strings(params)
    return _strings(OperationContext(runtime=runtime), request)


__all__ = [
    "SearchBytesRequest",
    "StringsRequest",
    "XrefsRequest",
    "op_strings",
    "search_operations",
]
