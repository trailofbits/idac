from __future__ import annotations

import json
from typing import Any, Callable

from ...ops.families.type_declare import TypeDeclareDiagnostic, TypeDeclareResult
from ._registry import build_text_renderers
from ._registry import renderer_registry_drift as _renderer_registry_drift


def _fallback(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, sort_keys=True)


def _append_present_fields(lines: list[str], value: dict[str, Any], *keys: str) -> None:
    for key in keys:
        item = value.get(key)
        if item not in (None, ""):
            lines.append(f"{key}: {item}")


def _join_lines(lines: list[str], *, empty: str = "none") -> str:
    return "\n".join(lines) if lines else empty


def _display(value: Any, *, empty: str = "none") -> str:
    return empty if value in (None, "") else str(value)


def _get_first_present(mapping: dict[str, Any], *keys: str, empty: str = "<unknown>") -> str:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return str(value)
    return empty


def _join_inline(items: list[Any], *, empty: str = "none", sep: str = ", ") -> str:
    return sep.join(str(item) for item in items) if items else empty


def _render_list_rows(
    value: Any,
    render_row: Callable[[Any], str],
    *,
    empty: str = "none",
) -> str:
    if not isinstance(value, list) or not value:
        return empty
    return _join_lines([render_row(item) for item in value], empty=empty)


def _append_section(lines: list[str], label: str, rows: list[str], *, empty: str | None = None) -> bool:
    if not rows:
        if empty is not None:
            lines.append(f"{label}: {empty}")
        return False
    lines.append(f"{label}:")
    lines.extend(rows)
    return True


def _list_rows(items: list[Any], render_row: Callable[[Any], str]) -> list[str]:
    return [render_row(item) for item in items]


def _function_header(value: dict[str, Any], *, key: str = "function") -> str:
    return f"{_get_first_present(value, key)} @ {_get_first_present(value, 'address')}"


def render_target_list(value: Any) -> str:
    def render_row(item: Any) -> str:
        selector = _get_first_present(item, "selector", "target_id")
        module = item.get("module")
        pid = item.get("instance_pid")
        suffix = " [active]" if item.get("active") else ""
        details: list[str] = []
        if module:
            details.append(str(module))
        if pid not in (None, ""):
            details.append(f"pid={pid}")
        return f"{selector}{suffix}" + (f" ({', '.join(details)})" if details else "")

    return _render_list_rows(value, render_row)


def render_database_info(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = []
    _append_present_fields(
        lines,
        value,
        "path",
        "database_path",
        "module",
        "processor",
        "bits",
        "base",
        "min_ea",
        "max_ea",
        "start_ea",
        "entry_ea",
    )
    return "\n".join(lines) if lines else "none"


def render_segment_list(value: Any) -> str:
    def render_row(item: Any) -> str:
        if not isinstance(item, dict):
            return _fallback(item)
        name = _get_first_present(item, "name")
        start = _get_first_present(item, "start")
        end = _get_first_present(item, "end")
        size = item.get("size")
        suffix = "" if size in (None, "") else f" size={size}"
        return f"{name}  {start}-{end}{suffix}"

    return _render_list_rows(value, render_row)


def render_doctor(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines: list[str] = [
        f"status: {value.get('status', 'unknown')}",
        f"healthy: {value.get('healthy', False)}",
        f"backend: {value.get('backend', 'unknown')}",
    ]
    checks = value.get("checks")
    if not isinstance(checks, list) or not checks:
        lines.append("checks: none")
        return "\n".join(lines)
    lines.append("checks:")
    for item in checks:
        if not isinstance(item, dict):
            lines.append(f"- {_fallback(item)}")
            continue
        component = item.get("component", "unknown")
        name = item.get("name", "check")
        status = item.get("status", "unknown")
        summary = item.get("summary", "")
        lines.append(f"- [{status}] {component}.{name}: {summary}".rstrip())
    return "\n".join(lines)


def render_targets_cleanup(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = [
        f"runtime_dir: {value.get('runtime_dir', '<unknown>')}",
        f"removed: {value.get('removed_count', 0)}",
        f"kept: {value.get('kept_count', 0)}",
    ]
    missing_count = value.get("missing_count", 0)
    if missing_count:
        lines.append(f"missing: {missing_count}")
    log_path = value.get("log_path")
    if log_path not in (None, ""):
        lines.append(f"log: {log_path}")
    return "\n".join(lines)


def render_function_list(value: Any) -> str:
    return _render_list_rows(
        value,
        lambda item: f"{item.get('address', '<unknown>')}  {item.get('render_name') or item.get('name', '<unknown>')}",
    )


def render_function_show(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = [f"{value.get('name', '<unknown>')} @ {value.get('address', '<unknown>')}"]
    _append_present_fields(lines, value, "display_name", "prototype", "size", "flags")
    return "\n".join(lines)


def render_function_frame(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = [_function_header(value)]
    _append_present_fields(lines, value, "frame_size", "local_size", "saved_registers_size", "argument_size")
    members = value.get("members")
    if not isinstance(members, list) or not members:
        lines.append("members: none")
        return "\n".join(lines)

    def render_member(member: dict[str, Any]) -> str:
        offset = member.get("offset")
        kind = member.get("kind", "member")
        name = member.get("name", "<unnamed>")
        type_name = member.get("type", "")
        suffix: list[str] = []
        fp_offset = member.get("fp_offset")
        if fp_offset not in (None, ""):
            suffix.append(f"fp={fp_offset}")
        if member.get("is_special"):
            suffix.append("special")
        line = f"{offset!s:>8}  {kind:<7}  {name}  {type_name}".rstrip()
        if suffix:
            line += "  [" + ", ".join(str(item) for item in suffix) + "]"
        return line

    _append_section(lines, "members", _list_rows(members, render_member))
    return "\n".join(lines)


def render_function_stackvars(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = [_function_header(value)]
    members = value.get("stackvars")
    if not isinstance(members, list) or not members:
        lines.append("stackvars: none")
        return "\n".join(lines)
    for member in members:
        offset = member.get("offset")
        fp_offset = member.get("fp_offset")
        location = f"offset={offset}"
        if fp_offset not in (None, ""):
            location += f" fp={fp_offset}"
        lines.append(
            f"{member.get('name', '<unnamed>')}  {member.get('type', '')}  "
            f"{location}  xrefs={member.get('xref_count', 0)}".rstrip()
        )
        for xref in member.get("xrefs") or []:
            parts = [
                str(xref.get("address", "<unknown>")),
                str(xref.get("access", "unknown")),
            ]
            opnum = xref.get("operand")
            if opnum not in (None, ""):
                parts.append(f"op{opnum}")
            lines.append("  " + "  ".join(parts))
    return "\n".join(lines)


def render_function_relations(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = [_function_header(value)]
    rows = value.get("edges")
    if not isinstance(rows, list) or not rows:
        lines.append("none")
        return "\n".join(lines)
    for row in rows:
        if "callee" in row:
            lines.append(
                f"{row.get('call_site', '<unknown>')}  "
                f"{row.get('callee_address', '<unknown>')}  {row.get('callee', '<unknown>')}"
            )
        else:
            lines.append(
                f"{row.get('call_site', '<unknown>')}  "
                f"{row.get('caller_address', '<unknown>')}  {row.get('caller', '<unknown>')}"
            )
    return "\n".join(lines)


def render_decompile_bulk(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = [f"functions: {value.get('functions_succeeded', 0)}/{value.get('functions_total', 0)}"]
    out_file = value.get("out_file")
    out_dir = value.get("out_dir")
    manifest_path = value.get("manifest_path")
    if out_file not in (None, ""):
        lines.insert(0, f"out_file: {out_file}")
    else:
        lines.insert(0, f"out_dir: {out_dir or '<unknown>'}")
    if manifest_path not in (None, ""):
        lines.insert(1, f"manifest: {manifest_path}")
    if value.get("functions_failed"):
        lines.append(f"failed: {value.get('functions_failed')}")
    return "\n".join(lines)


def render_lines(value: Any, *, field: str = "text") -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get(field), str):
        return value[field]
    if isinstance(value, list):
        return "\n".join(str(item.get(field, "")) for item in value)
    return _fallback(value)


def render_xrefs(value: Any) -> str:
    def render_row(item: Any) -> str:
        return " | ".join(
            str(part)
            for part in (
                item.get("from"),
                item.get("to"),
                item.get("kind"),
                item.get("type"),
                "user" if item.get("user") else None,
                item.get("function"),
            )
            if part not in (None, "")
        )

    return _render_list_rows(value, render_row)


def render_strings(value: Any) -> str:
    return _render_list_rows(
        value,
        lambda item: f"{item.get('address', '<unknown>')}  {item.get('text', '')}",
    )


def render_imports(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return "none"
    rows: list[str] = []
    for module in value:
        name = module.get("module", "<unnamed>")
        rows.append(f"[{name}]")
        for item in module.get("entries", []):
            rows.append(f"{item.get('address', '<unknown>')}  {item.get('name', '<unnamed>')}")
    return "\n".join(rows)


def render_search_results(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    results = value.get("results")
    pattern = value.get("pattern", "")
    lines = [f"pattern: {pattern}"]
    if not isinstance(results, list) or not results:
        lines.append("results: none")
        return "\n".join(lines)
    for item in results:
        line = str(item.get("address", "<unknown>"))
        function = item.get("function")
        if function not in (None, ""):
            line += f"  {function}"
        lines.append(line)
    if value.get("truncated"):
        lines.append(f"truncated: limit={value.get('limit')}")
    return "\n".join(lines)


def render_comment(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    return _display(value.get("comment"))


def render_bookmarks(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    rows = value.get("bookmarks")
    if isinstance(rows, list):
        if not rows:
            return "none"
    else:
        rows = [value]

    def render_row(item: Any) -> str:
        slot = item.get("slot", "?")
        if not item.get("present"):
            return f"{slot}  <empty>"
        address = _get_first_present(item, "address")
        comment = item.get("comment")
        line = f"{slot}  {address}"
        if comment not in (None, ""):
            line += f"  {comment}"
        return line

    return _join_lines(_list_rows(rows, render_row))


def render_locals(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    rows = value.get("locals")
    if not isinstance(rows, list) or not rows:
        return "none"
    lines: list[str] = []
    function = value.get("function")
    address = value.get("address")
    if function or address:
        lines.append(_function_header(value))
    for item in rows:
        name = _get_first_present(item, "display_name", "name", empty="<unnamed>")
        prefix = "arg" if item.get("is_arg") else "local"
        if item.get("is_stack") and item.get("stack_offset") is not None:
            prefix += f"[sp+{item['stack_offset']}]"
        index = item.get("index")
        if index not in (None, ""):
            prefix += f"#{index}"
        line = f"{prefix:>12}  {name}  {item.get('type', '')}".rstrip()
        local_id = item.get("local_id")
        if local_id not in (None, ""):
            line += f"  {local_id}"
        lines.append(line)
    return "\n".join(lines)


def render_types(value: Any) -> str:
    def render_row(item: Any) -> str:
        decl = item.get("decl")
        suffix = f"  {decl}" if isinstance(decl, str) and decl else ""
        return f"{item.get('name', '<unknown>')}  {item.get('kind', '')}{suffix}".rstrip()

    return _render_list_rows(value, render_row)


def render_class_list(value: Any) -> str:
    def render_row(item: Any) -> str:
        bases = item.get("bases") or []
        suffix = f" : {', '.join(str(base) for base in bases)}" if bases else ""
        return f"{item.get('name', '<unknown>')}  size={item.get('size', '?')}{suffix}"

    return _render_list_rows(value, render_row)


def render_class_candidates(value: Any) -> str:
    def render_row(item: Any) -> str:
        kind = _get_first_present(item, "kind", empty="candidate")
        name = _get_first_present(item, "name")
        address = item.get("address")
        suffix = f" @ {address}" if address not in (None, "") else ""
        demangled = item.get("demangled")
        extra = f"  {demangled}" if isinstance(demangled, str) and demangled else ""
        return f"[{kind}] {name}{suffix}{extra}".rstrip()

    return _render_list_rows(value, render_row)


def render_class_hierarchy(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines = [_get_first_present(value, "name")]
    bases = value.get("bases") or []
    ancestors = value.get("ancestors") or []
    derived = value.get("derived") or []
    descendants = value.get("descendants") or []
    for label, items in (
        ("bases", bases),
        ("ancestors", ancestors),
        ("derived", derived),
        ("descendants", descendants),
    ):
        lines.append(f"{label}: {_join_inline(items)}")
    return "\n".join(lines)


def render_class_fields(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    fields = value.get("fields")
    if not isinstance(fields, list) or not fields:
        return "none"
    lines = [f"{value.get('name', '<unknown>')}  derived_only={bool(value.get('derived_only'))}"]

    def render_row(field: dict[str, Any]) -> str:
        name = _get_first_present(field, "name", empty="<unnamed>")
        offset = field.get("offset")
        type_name = field.get("type") or ""
        suffix = "  [vftable]" if field.get("is_vftable") else ""
        return f"{offset!s:>8}  {name}  {type_name}".rstrip() + suffix

    lines.extend(_list_rows(fields, render_row))
    return "\n".join(lines)


def render_class_vtable(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines: list[str] = []
    name = _get_first_present(value, "name")
    vtable_type = _get_first_present(value, "vtable_type")
    lines.append(f"{name}  vtable={vtable_type}")
    decl = value.get("decl")
    if isinstance(decl, str) and decl:
        lines.append(decl.rstrip())
    members = value.get("members")
    if isinstance(members, list) and members:
        _append_section(
            lines,
            "members",
            _list_rows(
                members,
                lambda member: (
                    f"{member.get('slot', '?')!s:>8}  {member.get('name', '<unnamed>')}  {member.get('type', '')}"
                ).rstrip(),
            ),
        )
    runtime = value.get("runtime_vtable")
    if isinstance(runtime, dict):
        lines.append("runtime:")
        symbol = _get_first_present(runtime, "symbol", "identifier")
        lines.append(f"  symbol: {symbol} @ {runtime.get('table_address', '<unknown>')}")
        lines.extend(
            _list_rows(
                list(runtime.get("members") or []),
                lambda member: (
                    f"  {member.get('slot', '?')!s:>6}  {member.get('name', member.get('target', '<unnamed>'))}"
                ),
            )
        )
    return "\n".join(lines)


def _render_member_rows(members: list[dict[str, Any]], *, enum: bool) -> list[str]:
    rows: list[str] = []
    for member in members:
        if enum:
            prefix = _get_first_present(member, "value_hex", "value")
        else:
            prefix = str(member.get("offset") if member.get("offset") is not None else "<unknown>")
        line = f"{prefix:>8}  {member.get('name', '<unnamed>')}"
        type_name = member.get("type")
        if isinstance(type_name, str) and type_name:
            line += f"  {type_name}"
        comment = member.get("comment")
        if isinstance(comment, str) and comment:
            line += f"  ; {comment}"
        rows.append(line)
    return rows


def render_type_show(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    lines: list[str] = []
    name = value.get("name")
    kind = value.get("kind")
    if name or kind:
        header = _display(name, empty="<unknown>")
        if kind:
            header += f"  {kind}"
        lines.append(header)
    if value.get("size_known") is False:
        lines.append("size: unknown")
    elif value.get("size") not in (None, ""):
        lines.append(f"size: {value.get('size')}")
    for key in ("prototype", "decl", "layout"):
        item = value.get(key)
        if isinstance(item, str) and item:
            lines.append(item.rstrip())
            break
    members = value.get("members")
    if isinstance(members, list) and members:
        _append_section(
            lines,
            "members",
            _render_member_rows(
                [item for item in members if isinstance(item, dict)],
                enum=kind == "enum",
            ),
        )
    return "\n".join(lines) if lines else _fallback(value)


def render_type_declare(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    result: TypeDeclareResult = value
    imported = result.get("imported_types")
    replaced = result.get("replaced_types")
    errors = result.get("errors")
    lines = [
        f"success: {bool(result.get('success'))}",
        f"errors: {errors}",
        f"replace: {bool(result.get('replace'))}",
    ]
    aliases = result.get("aliases_applied")
    if aliases:
        lines.append("aliases: " + ", ".join(f"{item['from']}->{item['to']} x{item['count']}" for item in aliases))
    if imported:
        lines.append(f"imported: {', '.join(str(item) for item in imported)}")
    else:
        lines.append("imported: none")
    if replaced:
        lines.append(f"replaced: {', '.join(str(item) for item in replaced)}")
    else:
        lines.append("replaced: none")
    bisect = result.get("bisect")
    if bisect is not None:
        if bisect.get("supported") is False:
            lines.append(f"bisect: unavailable ({bisect.get('message') or 'no details'})")
        else:
            failing = bisect.get("failing_declaration")
            if failing is not None:
                line = failing.get("line")
                end_line = failing.get("end_line")
                location = (
                    f"lines {line}-{end_line}"
                    if line not in (None, "") and end_line not in (None, "") and line != end_line
                    else f"line {line}"
                    if line not in (None, "")
                    else "unknown location"
                )
                lines.append(f"bisect: declaration #{failing.get('index')} at {location}")
            blocking = bisect.get("blocking_members")
            if blocking:
                lines.append(
                    "blocking members: " + ", ".join(f"{item['type_name']} {item['member_name']}" for item in blocking)
                )
    diagnostics = result.get("diagnostics")
    if diagnostics:
        _append_section(
            lines,
            "diagnostics",
            [_render_type_diagnostic(item) for item in diagnostics],
        )
    return "\n".join(lines)


def _render_type_diagnostic(item: TypeDeclareDiagnostic) -> str:
    line = item.get("line")
    message = item.get("message") or item.get("kind") or "diagnostic"
    if line not in (None, ""):
        return f"- line {line}: {message}"
    return f"- {message}"


def render_vtable_dump(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    symbol = _get_first_present(value, "symbol", "identifier")
    abi = value.get("abi", "unknown")
    lines = [
        f"{symbol}  abi={abi}",
        f"table: {value.get('table_address', '<unknown>')}",
        f"slots: {value.get('slot_address', '<unknown>')}",
    ]
    header = value.get("header")
    if isinstance(header, list) and header:
        _append_section(
            lines,
            "header",
            _list_rows(
                header,
                lambda item: (
                    f"  {item.get('index', '?')}: {item.get('name', '<unnamed>')} = {item.get('value', '<unknown>')}"
                ).rstrip(),
            ),
        )
    members = value.get("members")
    if isinstance(members, list) and members:
        _append_section(
            lines,
            "members",
            _list_rows(
                members,
                lambda member: (
                    f"{member.get('slot', '?')!s:>8}  {member.get('target', '<unknown>')}  {member.get('name', '')}"
                ).rstrip(),
            ),
        )
    stop_reason = value.get("stop_reason")
    if stop_reason not in (None, ""):
        lines.append(f"stop_reason: {stop_reason}")
    return "\n".join(lines)


def render_python_exec(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    stdout = value.get("stdout") or ""
    rendered_result = value.get("result_repr")
    if stdout and rendered_result:
        return f"{stdout.rstrip()}\n\nresult: {rendered_result}"
    if stdout:
        return stdout.rstrip()
    if rendered_result:
        return f"result: {rendered_result}"
    return "ok"


def render_workspace_init(value: Any) -> str:
    if not isinstance(value, dict):
        return _fallback(value)
    destination = str(value.get("display_destination") or value.get("destination") or ".")
    suffix = "" if destination.endswith("/") else "/"
    lines = [f"Created {destination}{suffix}"]
    for item in value.get("created") or []:
        lines.append(f"  {item}")
    overwritten = value.get("overwritten") or []
    if overwritten:
        lines.append("Overwrote:")
        for item in overwritten:
            lines.append(f"  {item}")
    git = value.get("git") or {}
    if git.get("initialized"):
        lines.append("Initialized git repository.")
    else:
        repo_root = git.get("repo_root")
        if repo_root not in (None, ""):
            lines.append(f"Using existing git repository: {repo_root}")
    next_steps = value.get("next_steps") or []
    if next_steps:
        lines.append("")
        lines.append("Next steps:")
        for index, step in enumerate(next_steps, start=1):
            lines.append(f"  {index}. {step}")
    return "\n".join(lines)


TEXT_RENDERERS = build_text_renderers(globals())


def renderer_registry_drift() -> tuple[list[str], list[str]]:
    return _renderer_registry_drift(TEXT_RENDERERS)


__all__ = [
    "TEXT_RENDERERS",
    "render_bookmarks",
    "render_class_candidates",
    "render_class_fields",
    "render_class_hierarchy",
    "render_class_list",
    "render_class_vtable",
    "render_comment",
    "render_database_info",
    "render_decompile_bulk",
    "render_doctor",
    "render_function_frame",
    "render_function_list",
    "render_function_relations",
    "render_function_show",
    "render_function_stackvars",
    "render_imports",
    "render_lines",
    "render_locals",
    "render_python_exec",
    "render_search_results",
    "render_segment_list",
    "render_strings",
    "render_target_list",
    "render_targets_cleanup",
    "render_type_declare",
    "render_type_show",
    "render_types",
    "render_vtable_dump",
    "render_workspace_init",
    "render_xrefs",
    "renderer_registry_drift",
]
