from __future__ import annotations

from dataclasses import dataclass

from ..base import OperationContext, OperationSpec
from ..helpers.matching import pattern_from_params, text_matches
from ..helpers.params import optional_param_int, optional_str, require_str
from ..runtime import IdaOperationError, IdaRuntime, _ea_text, _strip_tags


@dataclass(frozen=True)
class FunctionListRequest:
    pattern: str
    glob: bool
    regex: bool
    ignore_case: bool
    segment: str | None
    limit: int | None
    demangle: bool


@dataclass(frozen=True)
class FunctionIdentifierRequest:
    identifier: str


@dataclass(frozen=True)
class DecompileRequest:
    identifier: str
    no_cache: bool


@dataclass(frozen=True)
class CtreeRequest:
    identifier: str
    level: str
    maturity: str


def _function_header(runtime: IdaRuntime, func) -> tuple[str, str]:
    return runtime.function_identity(func)


def _require_identifier(params: dict[str, object], *, key: str = "identifier") -> str:
    return require_str(params.get(key), field="address or identifier")


def _parse_function_list(params: dict[str, object]) -> FunctionListRequest:
    pattern, glob, regex, ignore_case = pattern_from_params(params)
    return FunctionListRequest(
        pattern=pattern,
        glob=glob,
        regex=regex,
        ignore_case=ignore_case,
        segment=optional_str(params.get("segment")),
        limit=optional_param_int(params, "limit", label="function list limit", minimum=1),
        demangle=bool(params.get("demangle")),
    )


def _function_list(context: OperationContext, request: FunctionListRequest) -> list[dict[str, object]]:
    runtime = context.runtime
    ranges = () if request.segment is None else runtime.resolve_segment_ranges(request.segment)
    rows: list[dict[str, object]] = []
    for ea in runtime.idautils.Functions():
        if ranges and not runtime.ea_in_ranges(ea, ranges):
            continue
        name = runtime.function_name(ea)
        display_name = runtime.display_function_name(ea, demangle=True)
        if request.pattern and not text_matches(
            name,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
        ):
            continue
        func = runtime.ida_funcs.get_func(ea)
        rows.append(
            {
                "name": name,
                "display_name": display_name,
                "render_name": display_name if request.demangle else name,
                "address": hex(ea),
                "size": 0 if func is None else func.end_ea - func.start_ea,
            }
        )
        if request.limit is not None and len(rows) >= request.limit:
            break
    return rows


def _parse_identifier(params: dict[str, object]) -> FunctionIdentifierRequest:
    return FunctionIdentifierRequest(identifier=_require_identifier(params))


def _function_show(context: OperationContext, request: FunctionIdentifierRequest) -> dict[str, object]:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    ida_typeinf = runtime.ida_typeinf
    name, address = _function_header(runtime, func)
    ea = func.start_ea
    return {
        "name": name,
        "display_name": runtime.display_function_name(ea, demangle=True),
        "address": address,
        "size": func.end_ea - func.start_ea,
        "prototype": ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) or "",
        "flags": hex(func.flags),
    }


def _frame_members(
    runtime: IdaRuntime,
    func,
    *,
    include_special: bool,
    include_xrefs: bool,
    query: str | None = None,
) -> list[dict[str, object]]:
    frame_tif = runtime.ida_typeinf.tinfo_t()
    if not frame_tif.get_func_frame(func):
        raise IdaOperationError(f"function has no frame: {hex(func.start_ea)}")

    xref_names = {
        runtime.ida_xref.dr_R: "read",
        runtime.ida_xref.dr_W: "write",
    }
    members: list[dict[str, object]] = []
    for index, frame_udm in enumerate(frame_tif.iter_struct()):
        offset = frame_udm.begin() // 8
        end_offset = frame_udm.end() // 8
        tid = frame_tif.get_udm_tid(index)
        local_size = func.frsize
        saved_regs_size = func.frregs
        special_from_layout = local_size <= offset < (local_size + saved_regs_size)
        is_special = bool(runtime.ida_frame.is_special_frame_member(tid)) or special_from_layout
        if is_special and not include_special:
            continue
        name = str(frame_udm.name or f"<unnamed_{index}>")
        if query and not text_matches(name, pattern=query, ignore_case=True):
            continue
        is_arg = False if is_special else bool(runtime.ida_frame.is_funcarg_off(func, offset))
        xrefs: list[dict[str, object]] = []
        xref_count: int | None = None
        if include_xrefs:
            xreflist = runtime.ida_frame.xreflist_t()
            runtime.ida_frame.build_stkvar_xrefs(xreflist, func, offset, end_offset)
            for item_index in range(xreflist.size()):
                item = xreflist[item_index]
                xrefs.append(
                    {
                        "address": hex(item.ea),
                        "operand": item.opnum,
                        "type": item.type,
                        "access": xref_names.get(item.type, "unknown"),
                    }
                )
            xref_count = len(xrefs)
        members.append(
            {
                "index": index,
                "name": name,
                "offset": offset,
                "end_offset": end_offset,
                "size": max(0, end_offset - offset),
                "type": runtime.tinfo_decl(frame_udm.type, multi=False),
                "kind": "special" if is_special else "arg" if is_arg else "local",
                "is_special": is_special,
                "is_arg": is_arg,
                "fp_offset": None if is_special else runtime.ida_frame.soff_to_fpoff(func, offset),
                "xrefs": xrefs,
                "xref_count": xref_count,
            }
        )
    members.sort(key=lambda item: (int(item["offset"]), str(item["name"]).lower()))
    return members


def _function_frame(context: OperationContext, request: FunctionIdentifierRequest) -> dict[str, object]:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = _function_header(runtime, func)
    frame_tif = runtime.ida_typeinf.tinfo_t()
    if not frame_tif.get_func_frame(func):
        raise IdaOperationError(f"function has no frame: {address}")
    return {
        "function": name,
        "address": address,
        "frame_size": frame_tif.get_size(),
        "local_size": func.frsize,
        "saved_registers_size": func.frregs,
        "argument_size": func.argsize,
        "members": _frame_members(runtime, func, include_special=True, include_xrefs=False),
    }


def _function_stackvars(context: OperationContext, request: FunctionIdentifierRequest) -> dict[str, object]:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = _function_header(runtime, func)
    return {
        "function": name,
        "address": address,
        "stackvars": _frame_members(
            runtime,
            func,
            include_special=False,
            include_xrefs=True,
        ),
    }


def _incoming_edges(runtime: IdaRuntime, func) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
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
            {
                "call_site": hex(ref.from_ea),
                "caller": runtime.function_name(caller_ea),
                "caller_address": hex(caller_ea),
            }
        )
    rows.sort(key=lambda item: (str(item["caller"]).lower(), str(item["call_site"])))
    return rows


def _outgoing_edges(runtime: IdaRuntime, func) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
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
                {
                    "call_site": hex(item),
                    "callee": runtime.function_name(callee_ea),
                    "callee_address": hex(callee_ea),
                }
            )
    rows.sort(key=lambda item: (str(item["callee"]).lower(), str(item["call_site"])))
    return rows


def _function_callers(context: OperationContext, request: FunctionIdentifierRequest) -> dict[str, object]:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = _function_header(runtime, func)
    return {"function": name, "address": address, "edges": _incoming_edges(runtime, func)}


def _function_callees(context: OperationContext, request: FunctionIdentifierRequest) -> dict[str, object]:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = _function_header(runtime, func)
    return {"function": name, "address": address, "edges": _outgoing_edges(runtime, func)}


def _disasm(context: OperationContext, request: FunctionIdentifierRequest) -> dict[str, object]:
    runtime = context.runtime
    func_ea = runtime.function_ea(request.identifier)
    ida_lines = runtime.mod("ida_lines")
    lines = [
        f"{hex(ea)}: {_strip_tags(runtime, ida_lines.generate_disasm_line(ea, 0) or '')}"
        for ea in runtime.idautils.FuncItems(func_ea)
    ]
    return {"text": "\n".join(lines)}


def _parse_decompile(params: dict[str, object]) -> DecompileRequest:
    return DecompileRequest(
        identifier=_require_identifier(params),
        no_cache=bool(params.get("no_cache")),
    )


def _decompile(context: OperationContext, request: DecompileRequest) -> dict[str, object]:
    runtime = context.runtime
    ida_hexrays = runtime.require_hexrays()
    ea = runtime.function_ea(request.identifier)
    flags = ida_hexrays.DECOMP_NO_CACHE if request.no_cache else 0
    cfunc = ida_hexrays.decompile(ea, None, flags) if flags else ida_hexrays.decompile(ea)
    if cfunc is None:
        raise IdaOperationError(f"failed to decompile function at {hex(ea)}")
    return {"text": runtime.pseudocode_text(cfunc)}


def _parse_ctree(params: dict[str, object]) -> CtreeRequest:
    return CtreeRequest(
        identifier=_require_identifier(params),
        level=str(params.get("level") or "ctree").lower(),
        maturity=str(params.get("maturity") or "generated").lower(),
    )


def _ctree_rows(runtime: IdaRuntime, cfunc) -> list[dict[str, object]]:
    ida_hexrays = runtime.require_hexrays()
    rows: list[dict[str, object]] = []

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            super().__init__(ida_hexrays.CV_FAST | ida_hexrays.CV_PARENTS)

        def _append(self, kind: str, node) -> int:
            rows.append(
                {
                    "kind": kind,
                    "depth": max(0, len(self.parents) - 1),
                    "op": node.opname,
                    "ea": _ea_text(runtime, node.ea),
                    "text": _strip_tags(runtime, node.print1(cfunc)),
                }
            )
            return 0

        def visit_insn(self, insn):
            return self._append("insn", insn)

        def visit_expr(self, expr):
            return self._append("expr", expr)

    visitor = Visitor()
    visitor.apply_to(cfunc.body, None)
    return rows


def _render_ctree_text(nodes: list[dict[str, object]]) -> str:
    return "\n".join(
        f"{'  ' * int(node['depth'])}{node['kind']}:{node['op']}"
        + (f" @{node['ea']}" if node["ea"] else "")
        + (f"  {node['text']}" if node["text"] else "")
        for node in nodes
    )


def _maturity_value(runtime: IdaRuntime, name: str) -> int:
    ida_hexrays = runtime.require_hexrays()
    attr_names = {
        "generated": "MMAT_GENERATED",
        "preoptimized": "MMAT_PREOPTIMIZED",
        "locopt": "MMAT_LOCOPT",
        "calls": "MMAT_CALLS",
        "glbopt1": "MMAT_GLBOPT1",
        "glbopt2": "MMAT_GLBOPT2",
        "glbopt3": "MMAT_GLBOPT3",
        "lvars": "MMAT_LVARS",
    }
    try:
        return getattr(ida_hexrays, attr_names[name])
    except KeyError as exc:
        raise IdaOperationError(f"unsupported microcode maturity: {name}") from exc


def _microcode_lines(runtime: IdaRuntime, func, maturity: str) -> tuple[str, ...]:
    ida_hexrays = runtime.require_hexrays()
    maturity_value = _maturity_value(runtime, maturity)

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
        mbr,
        hf,
        None,
        ida_hexrays.DECOMP_WARNINGS | ida_hexrays.DECOMP_NO_CACHE,
        maturity_value,
    )
    if mba is None:
        raise IdaOperationError(f"failed to generate microcode: {hf.desc()}")
    printer = Printer()
    mba._print(printer)
    return tuple(line for line in printer.lines if line)


def _ctree(context: OperationContext, request: CtreeRequest) -> dict[str, object]:
    runtime = context.runtime
    func = runtime.resolve_function(request.identifier)
    name, address = _function_header(runtime, func)
    if request.level == "ctree":
        cfunc = runtime.require_hexrays().decompile(func.start_ea)
        if cfunc is None:
            raise IdaOperationError(f"failed to decompile function at {address}")
        nodes = _ctree_rows(runtime, cfunc)
        return {
            "function": name,
            "address": address,
            "level": request.level,
            "nodes": nodes,
            "text": _render_ctree_text(nodes),
        }
    if request.level == "micro":
        lines = _microcode_lines(runtime, func, request.maturity)
        return {
            "function": name,
            "address": address,
            "level": request.level,
            "maturity": request.maturity,
            "lines": list(lines),
            "text": "\n".join(lines),
        }
    raise IdaOperationError(f"unsupported ctree level: {request.level}")


def function_operations() -> tuple[OperationSpec[object, object], ...]:
    return (
        OperationSpec(
            name="function_list",
            parse=_parse_function_list,
            run=_function_list,
        ),
        OperationSpec(
            name="function_show",
            parse=_parse_identifier,
            run=_function_show,
        ),
        OperationSpec(
            name="function_frame",
            parse=_parse_identifier,
            run=_function_frame,
        ),
        OperationSpec(
            name="function_stackvars",
            parse=_parse_identifier,
            run=_function_stackvars,
        ),
        OperationSpec(
            name="function_callers",
            parse=_parse_identifier,
            run=_function_callers,
        ),
        OperationSpec(
            name="function_callees",
            parse=_parse_identifier,
            run=_function_callees,
        ),
        OperationSpec(
            name="disasm",
            parse=_parse_identifier,
            run=_disasm,
        ),
        OperationSpec(
            name="decompile",
            parse=_parse_decompile,
            run=_decompile,
        ),
        OperationSpec(
            name="ctree",
            parse=_parse_ctree,
            run=_ctree,
        ),
    )


def _direct_context(runtime: IdaRuntime) -> OperationContext:
    return OperationContext(runtime=runtime)


def op_decompile(runtime: IdaRuntime, params: dict[str, object]) -> dict[str, object]:
    request = _parse_decompile(params)
    return _decompile(_direct_context(runtime), request)


def op_function_frame(runtime: IdaRuntime, params: dict[str, object]) -> dict[str, object]:
    request = _parse_identifier(params)
    return _function_frame(_direct_context(runtime), request)


__all__ = [
    "CtreeRequest",
    "DecompileRequest",
    "FunctionIdentifierRequest",
    "FunctionListRequest",
    "function_operations",
    "op_decompile",
    "op_function_frame",
]
