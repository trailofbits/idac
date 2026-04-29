from __future__ import annotations

import argparse
from typing import Any

from ..argparse_utils import (
    add_command,
    add_context_options,
    add_decl_input,
    add_output_options,
    add_pattern_options,
    read_decl_text,
)
from ..commands.common import parse_alias_list, send_op
from ..errors import CliUserError
from ..result import CommandResult


def _pattern_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "pattern": args.pattern,
        "regex": args.regex,
        "ignore_case": args.ignore_case,
    }


def _name_params(args: argparse.Namespace) -> dict[str, object]:
    return {"name": str(args.name)}


def _type_declare_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "decl": read_decl_text(args),
        "replace": bool(args.replace),
        "aliases": parse_alias_list(args.alias),
        "bisect": bool(args.bisect),
        "clang": bool(args.clang),
    }


def _class_candidates_params(args: argparse.Namespace) -> dict[str, object]:
    params = _pattern_params(args)
    if args.kind:
        params["kinds"] = list(args.kind)
    return params


def _class_fields_params(args: argparse.Namespace) -> dict[str, object]:
    return {"name": str(args.name), "derived_only": bool(args.derived_only)}


def _class_vtable_params(args: argparse.Namespace) -> dict[str, object]:
    return {"name": str(args.name), "runtime": bool(args.runtime)}


def _struct_field_set_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "struct_name": str(args.struct_name),
        "field_name": str(args.field_name),
        "offset": args.offset,
        "decl": read_decl_text(args),
    }


def _struct_field_rename_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "struct_name": str(args.struct_name),
        "field_name": str(args.field_name),
        "new_name": str(args.new_name),
    }


def _struct_field_delete_params(args: argparse.Namespace) -> dict[str, object]:
    return {"struct_name": str(args.struct_name), "field_name": str(args.field_name)}


def _enum_member_set_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {
        "enum_name": str(args.enum_name),
        "member_name": str(args.member_name),
        "value": args.value,
    }
    if args.mask is not None:
        params["mask"] = args.mask
    return params


def _enum_member_rename_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "enum_name": str(args.enum_name),
        "member_name": str(args.member_name),
        "new_name": str(args.new_name),
    }


def _enum_member_delete_params(args: argparse.Namespace) -> dict[str, object]:
    return {"enum_name": str(args.enum_name), "member_name": str(args.member_name)}


def _type_list_guard(args: argparse.Namespace) -> None:
    if args.pattern in (None, "") and args.out is None:
        raise CliUserError("this list can be very large; rerun with a pattern or `--out <path>`")


def run_type_list(args: argparse.Namespace) -> CommandResult:
    _type_list_guard(args)
    return send_op(args, op="type_list", params=_pattern_params(args), render_op="type_list")


def run_type_show(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="type_show", params=_name_params(args), render_op="type_show")


def run_type_declare(args: argparse.Namespace) -> CommandResult:
    result = send_op(args, op="type_declare", params=_type_declare_params(args), render_op="type_declare")
    exit_code = 0
    stderr_lines: list[str] = []
    if isinstance(result.value, dict) and (
        result.value.get("success") is False or int(result.value.get("errors") or 0) > 0
    ):
        exit_code = 1
        stderr_lines = _type_declare_failure_lines(result.value)
    return CommandResult(
        render_op=result.render_op,
        value=result.value,
        exit_code=exit_code,
        warnings=list(result.warnings),
        stderr_lines=stderr_lines,
        artifacts=list(result.artifacts),
    )


def _type_declare_failure_lines(payload: dict[str, Any]) -> list[str]:
    errors = int(payload.get("errors") or 0)
    lines = [f"type declare failed: {errors} parser error(s)" if errors else "type declare failed"]
    bisect = payload.get("bisect")
    if isinstance(bisect, dict):
        failing = bisect.get("failing_declaration")
        if isinstance(failing, dict):
            line = failing.get("line")
            end_line = failing.get("end_line")
            if line not in (None, "") and end_line not in (None, "") and line != end_line:
                location = f"lines {line}-{end_line}"
            elif line not in (None, ""):
                location = f"line {line}"
            else:
                location = "unknown location"
            lines.append(f"first failing declaration #{failing.get('index', '?')} at {location}")
        blocking = bisect.get("blocking_members")
        if isinstance(blocking, list) and blocking:
            lines.append(
                "blocking members: "
                + ", ".join(
                    f"{item.get('type_name', '<unknown>')} {item.get('member_name', '<unknown>')}"
                    for item in blocking
                    if isinstance(item, dict)
                )
            )
    diagnostics = payload.get("diagnostics")
    if isinstance(diagnostics, list):
        displayed = 0
        for item in diagnostics:
            if not isinstance(item, dict):
                continue
            message = str(item.get("message") or item.get("kind") or "diagnostic").strip()
            if not message:
                continue
            line = item.get("line")
            if line not in (None, ""):
                lines.append(f"line {line}: {message}")
            else:
                lines.append(message)
            displayed += 1
            if displayed >= 5:
                break
        remaining = sum(1 for item in diagnostics if isinstance(item, dict)) - displayed
        if remaining > 0:
            lines.append(f"... {remaining} more diagnostic(s)")
    return lines


def run_class_list(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="class_list", params=_pattern_params(args), render_op="class_list")


def run_class_candidates(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="class_candidates",
        params=_class_candidates_params(args),
        render_op="class_candidates",
    )


def run_class_show(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="class_show", params=_name_params(args), render_op="class_show")


def run_class_hierarchy(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="class_hierarchy", params=_name_params(args), render_op="class_hierarchy")


def run_class_fields(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="class_fields", params=_class_fields_params(args), render_op="class_fields")


def run_class_vtable(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="class_vtable", params=_class_vtable_params(args), render_op="class_vtable")


def run_struct_list(args: argparse.Namespace) -> CommandResult:
    _type_list_guard(args)
    return send_op(args, op="struct_list", params=_pattern_params(args), render_op="struct_list")


def run_struct_show(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="struct_show", params=_name_params(args), render_op="struct_show")


def run_struct_field_set(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="struct_field_set",
        params=_struct_field_set_params(args),
        render_op="struct_field_set",
    )


def run_struct_field_rename(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="struct_field_rename",
        params=_struct_field_rename_params(args),
        render_op="struct_field_rename",
    )


def run_struct_field_delete(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="struct_field_delete",
        params=_struct_field_delete_params(args),
        render_op="struct_field_delete",
    )


def run_enum_list(args: argparse.Namespace) -> CommandResult:
    _type_list_guard(args)
    return send_op(args, op="enum_list", params=_pattern_params(args), render_op="enum_list")


def run_enum_show(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="enum_show", params=_name_params(args), render_op="enum_show")


def run_enum_member_set(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="enum_member_set",
        params=_enum_member_set_params(args),
        render_op="enum_member_set",
    )


def run_enum_member_rename(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="enum_member_rename",
        params=_enum_member_rename_params(args),
        render_op="enum_member_rename",
    )


def run_enum_member_delete(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="enum_member_delete",
        params=_enum_member_delete_params(args),
        render_op="enum_member_delete",
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "type", help_text="Type and structure operations")
    type_subparsers = parser.add_subparsers(dest="type_command")

    child = add_command(parser, type_subparsers, "list", help_text="List types")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="TYPE_FILTER",
        help=(
            "Select types by one name substring; with --regex, treat as a regex. "
            "Omitting this filter requires --out because the list may be large."
        ),
    )
    add_pattern_options(child, label="TYPE_FILTER")
    child.set_defaults(
        run=run_type_list, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, type_subparsers, "show", help_text="Show one type")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("name", help="Type name")
    child.set_defaults(
        run=run_type_show, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, type_subparsers, "declare", help_text="Import declarations into local types")
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = """examples:
  # Import a recovered C/C++ header into IDA local types
  idac type declare --replace --decl-file recovered_types.h -c db:sample.i64

  # Diagnose the first declaration that IDA rejects
  idac type declare --replace --bisect --decl-file recovered_types.h -c db:sample.i64

  # Use IDA's clang parser for template-heavy or modern C++ declarations
  idac type declare --clang --decl-file recovered_templates.hpp -c db:sample.i64
"""
    add_context_options(child)
    add_output_options(child, default_format="json")
    add_decl_input(
        child,
        help_text="C/C++ declaration text to import into IDA local types",
        file_help="Read C/C++ declarations from this header/source file",
    )
    child.add_argument("--replace", action="store_true", help="Replace existing named local types when names collide")
    child.add_argument(
        "--alias", action="append", default=[], metavar="OLD=NEW", help="Rewrite identifiers before import"
    )
    child.add_argument(
        "--bisect",
        "--diagnose",
        dest="bisect",
        action="store_true",
        help="Diagnose the first failing declaration on import failure",
    )
    child.add_argument(
        "--clang",
        action="store_true",
        help="Use IDA's clang source parser for more complex C/C++ declarations",
    )
    child.set_defaults(
        run=run_type_declare, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    class_parser = add_command(parser, type_subparsers, "class", help_text="C++ class-oriented operations")
    class_subparsers = class_parser.add_subparsers(dest="class_command")

    child = add_command(class_parser, class_subparsers, "list", help_text="List C++ class types")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="CLASS_FILTER",
        help="Select classes by one name substring; with --regex, treat as a regex.",
    )
    add_pattern_options(child, label="CLASS_FILTER")
    child.set_defaults(
        run=run_class_list, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(
        class_parser, class_subparsers, "candidates", help_text="Find likely class-related names and symbols"
    )
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="CANDIDATE_FILTER",
        help=(
            "Select candidate names by one substring; with --regex, treat as a regex. "
            "Use --kind to narrow candidate categories."
        ),
    )
    add_pattern_options(child, label="CANDIDATE_FILTER")
    child.add_argument(
        "--kind",
        action="append",
        choices=("local_type", "symbol", "vtable_symbol", "typeinfo_symbol", "typeinfo_name_symbol", "function_symbol"),
        help="Filter candidate rows by kind; may be specified multiple times",
    )
    child.set_defaults(
        run=run_class_candidates,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=False,
    )

    child = add_command(class_parser, class_subparsers, "show", help_text="Show one C++ class")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("name", help="Class name")
    child.set_defaults(
        run=run_class_show, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(class_parser, class_subparsers, "hierarchy", help_text="Show base and derived classes")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("name", help="Class name")
    child.set_defaults(
        run=run_class_hierarchy,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=False,
    )

    child = add_command(class_parser, class_subparsers, "fields", help_text="Show class fields")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("name", help="Class name")
    child.add_argument(
        "--derived-only", action="store_true", help="Only show fields declared directly on the target class"
    )
    child.set_defaults(
        run=run_class_fields, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(class_parser, class_subparsers, "vtable", help_text="Show the vtable type for a class")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("name", help="Class name")
    child.add_argument(
        "--runtime", action="store_true", help="Also resolve the runtime vtable symbol and raw slot targets"
    )
    child.set_defaults(
        run=run_class_vtable, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    struct_parser = add_command(parser, type_subparsers, "struct", help_text="Structure operations")
    struct_subparsers = struct_parser.add_subparsers(dest="struct_command")

    child = add_command(struct_parser, struct_subparsers, "list", help_text="List structs and unions")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="STRUCT_FILTER",
        help=(
            "Select structs/unions by one name substring; with --regex, treat as a regex. "
            "Omitting this filter requires --out because the list may be large."
        ),
    )
    add_pattern_options(child, label="STRUCT_FILTER")
    child.set_defaults(
        run=run_struct_list, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(struct_parser, struct_subparsers, "show", help_text="Show one struct")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("name", help="Struct or union name")
    child.set_defaults(
        run=run_struct_show, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    field_parser = add_command(struct_parser, struct_subparsers, "field", help_text="Operate on struct fields")
    field_subparsers = field_parser.add_subparsers(dest="struct_field_command")

    child = add_command(field_parser, field_subparsers, "set", help_text="Set or replace a struct field")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("struct_name", help="Struct or union name")
    child.add_argument("field_name", help="Struct field name")
    child.add_argument("--offset", required=True, help="Field offset within the struct or union")
    add_decl_input(child, help_text="Struct field declaration text")
    child.set_defaults(
        run=run_struct_field_set,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=True,
    )

    child = add_command(field_parser, field_subparsers, "rename", help_text="Rename a struct field")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("struct_name", help="Struct or union name")
    child.add_argument("field_name", help="Struct field name")
    child.add_argument("new_name", help="Replacement name")
    child.set_defaults(
        run=run_struct_field_rename,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=True,
    )

    child = add_command(field_parser, field_subparsers, "delete", help_text="Delete a struct field")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("struct_name", help="Struct or union name")
    child.add_argument("field_name", help="Struct field name")
    child.set_defaults(
        run=run_struct_field_delete,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=True,
    )

    enum_parser = add_command(parser, type_subparsers, "enum", help_text="Enum operations")
    enum_subparsers = enum_parser.add_subparsers(dest="enum_command")

    child = add_command(enum_parser, enum_subparsers, "list", help_text="List enums")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="ENUM_FILTER",
        help=(
            "Select enums by one name substring; with --regex, treat as a regex. "
            "Omitting this filter requires --out because the list may be large."
        ),
    )
    add_pattern_options(child, label="ENUM_FILTER")
    child.set_defaults(
        run=run_enum_list, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(enum_parser, enum_subparsers, "show", help_text="Show one enum")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("name", help="Enum name")
    child.set_defaults(
        run=run_enum_show, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    member_parser = add_command(enum_parser, enum_subparsers, "member", help_text="Operate on enum members")
    member_subparsers = member_parser.add_subparsers(dest="enum_member_command")

    child = add_command(member_parser, member_subparsers, "set", help_text="Set or add an enum member")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("enum_name", help="Enum name")
    child.add_argument("member_name", help="Enum member name")
    child.add_argument("--value", required=True, help="Enum member value")
    child.add_argument("--mask", help="Optional enum bitmask value")
    child.set_defaults(
        run=run_enum_member_set, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    child = add_command(member_parser, member_subparsers, "rename", help_text="Rename an enum member")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("enum_name", help="Enum name")
    child.add_argument("member_name", help="Enum member name")
    child.add_argument("new_name", help="Replacement name")
    child.set_defaults(
        run=run_enum_member_rename,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=True,
    )

    child = add_command(member_parser, member_subparsers, "delete", help_text="Delete an enum member")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("enum_name", help="Enum name")
    child.add_argument("member_name", help="Enum member name")
    child.set_defaults(
        run=run_enum_member_delete,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=True,
    )
