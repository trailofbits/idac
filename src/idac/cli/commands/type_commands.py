from __future__ import annotations

import argparse
from typing import Any

from ..argparse_utils import (
    add_command,
    add_decl_input,
    add_pattern_options,
    add_standard_command,
    read_decl_text,
)
from ..commands.common import OperationBinding, bind_operation, parse_alias_list, run_bound_operation
from ..errors import CliUserError
from ..result import CommandResult


def _pattern_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "pattern": args.pattern,
        "regex": args.regex,
        "ignore_case": args.ignore_case,
    }


def _type_declare_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {
        "decl": read_decl_text(args),
        "aliases": parse_alias_list(args.alias),
        "clang": bool(args.clang),
    }
    if hasattr(args, "replace"):
        params["replace"] = bool(args.replace)
    if hasattr(args, "bisect"):
        params["bisect"] = bool(args.bisect)
    return params


def _class_candidates_params(args: argparse.Namespace) -> dict[str, object]:
    params = _pattern_params(args)
    if args.kind:
        params["kinds"] = list(args.kind)
    return params


def _struct_field_set_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "struct_name": str(args.struct_name),
        "field_name": str(args.field_name),
        "offset": args.offset,
        "decl": read_decl_text(args),
    }


def _enum_member_set_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {
        "enum_name": str(args.enum_name),
        "member_name": str(args.member_name),
        "value": args.value,
    }
    if args.mask is not None:
        params["mask"] = args.mask
    return params


def _large_list_params(args: argparse.Namespace) -> dict[str, object]:
    if args.pattern in (None, "") and args.out is None:
        raise CliUserError("this list can be very large; rerun with a pattern or `--out <path>`")
    return _pattern_params(args)


def run_type_declare(args: argparse.Namespace) -> CommandResult:
    result = run_bound_operation(args)
    if isinstance(result.value, dict) and (
        result.value.get("success") is False or int(result.value.get("errors") or 0) > 0
    ):
        result.exit_code = 1
        result.stderr_lines = _type_declare_failure_lines(result.value, action="type declare")
    return result


def run_type_check(args: argparse.Namespace) -> CommandResult:
    result = run_bound_operation(args)
    if isinstance(result.value, dict) and (
        result.value.get("success") is False or int(result.value.get("errors") or 0) > 0
    ):
        result.exit_code = 1
        result.stderr_lines = _type_declare_failure_lines(result.value, action="type check")
    return result


def _type_declare_failure_lines(payload: dict[str, Any], *, action: str) -> list[str]:
    errors = int(payload.get("errors") or 0)
    lines = [f"{action} failed: {errors} parser error(s)" if errors else f"{action} failed"]
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
        diagnostics = [item for item in diagnostics if isinstance(item, dict)]
        displayed = 0
        for item in diagnostics:
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
        remaining = len(diagnostics) - displayed
        if remaining > 0:
            lines.append(f"... {remaining} more diagnostic(s)")
    return lines


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "type", help_text="Type and structure operations")
    type_subparsers = parser.add_subparsers(dest="type_command")

    child = add_standard_command(
        parser,
        type_subparsers,
        "list",
        help_text="List types",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("type_list", params_builder=_large_list_params))
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

    child = add_standard_command(
        parser,
        type_subparsers,
        "show",
        help_text="Show one type",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("type_show", parameter_attrs=(("name", "name"),)))
    child.add_argument("name", help="Type name")

    child = add_standard_command(
        parser,
        type_subparsers,
        "deps",
        help_text="Show a type with IDA-printed dependencies",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("type_deps", parameter_attrs=(("name", "name"),)))
    child.add_argument("name", help="Type name")

    child = add_standard_command(
        parser,
        type_subparsers,
        "check",
        help_text="Validate declarations without importing them",
        run=run_type_check,
        default_format="json",
    )
    bind_operation(child, OperationBinding("type_declare_check", params_builder=_type_declare_params))
    add_decl_input(
        child,
        help_text="C/C++ declaration text to validate with IDA's parser",
        file_help="Read C/C++ declarations from this header/source file",
    )
    child.add_argument(
        "--alias", action="append", default=[], metavar="OLD=NEW", help="Rewrite identifiers before validation"
    )
    child.add_argument(
        "--clang",
        action="store_true",
        help="Use IDA's clang source parser for more complex C/C++ declarations",
    )

    child = add_standard_command(
        parser,
        type_subparsers,
        "declare",
        help_text="Import declarations into local types",
        run=run_type_declare,
        default_format="json",
    )
    bind_operation(child, OperationBinding("type_declare", params_builder=_type_declare_params))
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = """examples:
  # Import a recovered C/C++ header into IDA local types
  idac type declare --replace --decl-file recovered_types.h -c sample.i64

  # Diagnose the first declaration that IDA rejects
  idac type declare --replace --bisect --decl-file recovered_types.h -c sample.i64

  # Use IDA's clang parser for template-heavy or modern C++ declarations
  idac type declare --clang --decl-file recovered_templates.hpp -c sample.i64
"""
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
        action="store_true",
        help="Diagnose the first failing declaration on import failure",
    )
    child.add_argument(
        "--clang",
        action="store_true",
        help="Use IDA's clang source parser for more complex C/C++ declarations",
    )

    class_parser = add_command(parser, type_subparsers, "class", help_text="C++ class-oriented operations")
    class_subparsers = class_parser.add_subparsers(dest="class_command")

    child = add_standard_command(
        class_parser,
        class_subparsers,
        "list",
        help_text="List C++ class types",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("class_list", params_builder=_pattern_params))
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="CLASS_FILTER",
        help="Select classes by one name substring; with --regex, treat as a regex.",
    )
    add_pattern_options(child, label="CLASS_FILTER")

    child = add_standard_command(
        class_parser,
        class_subparsers,
        "candidates",
        help_text="Find likely class-related names and symbols",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("class_candidates", params_builder=_class_candidates_params))
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

    child = add_standard_command(
        class_parser,
        class_subparsers,
        "show",
        help_text="Show one C++ class",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("class_show", parameter_attrs=(("name", "name"),)))
    child.add_argument("name", help="Class name")

    child = add_standard_command(
        class_parser,
        class_subparsers,
        "hierarchy",
        help_text="Show base and derived classes",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("class_hierarchy", parameter_attrs=(("name", "name"),)))
    child.add_argument("name", help="Class name")

    child = add_standard_command(
        class_parser,
        class_subparsers,
        "fields",
        help_text="Show class fields",
        run=run_bound_operation,
    )
    bind_operation(
        child,
        OperationBinding("class_fields", parameter_attrs=(("name", "name"), ("derived_only", "derived_only"))),
    )
    child.add_argument("name", help="Class name")
    child.add_argument(
        "--derived-only", action="store_true", help="Only show fields declared directly on the target class"
    )

    child = add_standard_command(
        class_parser,
        class_subparsers,
        "vtable",
        help_text="Show the vtable type for a class",
        run=run_bound_operation,
    )
    bind_operation(
        child,
        OperationBinding("class_vtable", parameter_attrs=(("name", "name"), ("runtime", "runtime"))),
    )
    child.add_argument("name", help="Class name")
    child.add_argument(
        "--runtime", action="store_true", help="Also resolve the runtime vtable symbol and raw slot targets"
    )

    struct_parser = add_command(parser, type_subparsers, "struct", help_text="Structure operations")
    struct_subparsers = struct_parser.add_subparsers(dest="struct_command")

    child = add_standard_command(
        struct_parser,
        struct_subparsers,
        "list",
        help_text="List structs and unions",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("struct_list", params_builder=_large_list_params))
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

    child = add_standard_command(
        struct_parser,
        struct_subparsers,
        "show",
        help_text="Show one struct",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("struct_show", parameter_attrs=(("name", "name"),)))
    child.add_argument("name", help="Struct or union name")

    field_parser = add_command(struct_parser, struct_subparsers, "field", help_text="Operate on struct fields")
    field_subparsers = field_parser.add_subparsers(dest="struct_field_command")

    child = add_standard_command(
        field_parser,
        field_subparsers,
        "set",
        help_text="Set or replace a struct field",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("struct_field_set", params_builder=_struct_field_set_params))
    child.add_argument("struct_name", help="Struct or union name")
    child.add_argument("field_name", help="Struct field name")
    child.add_argument("--offset", required=True, help="Field offset within the struct or union")
    add_decl_input(child, help_text="Struct field declaration text")

    child = add_standard_command(
        field_parser,
        field_subparsers,
        "rename",
        help_text="Rename a struct field",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(
        child,
        OperationBinding(
            "struct_field_rename",
            parameter_attrs=(
                ("struct_name", "struct_name"),
                ("field_name", "field_name"),
                ("new_name", "new_name"),
            ),
        ),
    )
    child.add_argument("struct_name", help="Struct or union name")
    child.add_argument("field_name", help="Struct field name")
    child.add_argument("new_name", help="Replacement name")

    child = add_standard_command(
        field_parser,
        field_subparsers,
        "delete",
        help_text="Delete a struct field",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(
        child,
        OperationBinding(
            "struct_field_delete",
            parameter_attrs=(("struct_name", "struct_name"), ("field_name", "field_name")),
        ),
    )
    child.add_argument("struct_name", help="Struct or union name")
    child.add_argument("field_name", help="Struct field name")

    enum_parser = add_command(parser, type_subparsers, "enum", help_text="Enum operations")
    enum_subparsers = enum_parser.add_subparsers(dest="enum_command")

    child = add_standard_command(
        enum_parser,
        enum_subparsers,
        "list",
        help_text="List enums",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("enum_list", params_builder=_large_list_params))
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

    child = add_standard_command(
        enum_parser,
        enum_subparsers,
        "show",
        help_text="Show one enum",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("enum_show", parameter_attrs=(("name", "name"),)))
    child.add_argument("name", help="Enum name")

    member_parser = add_command(enum_parser, enum_subparsers, "member", help_text="Operate on enum members")
    member_subparsers = member_parser.add_subparsers(dest="enum_member_command")

    child = add_standard_command(
        member_parser,
        member_subparsers,
        "set",
        help_text="Set or add an enum member",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("enum_member_set", params_builder=_enum_member_set_params))
    child.add_argument("enum_name", help="Enum name")
    child.add_argument("member_name", help="Enum member name")
    child.add_argument("--value", required=True, help="Enum member value")
    child.add_argument("--mask", help="Optional enum bitmask value")

    child = add_standard_command(
        member_parser,
        member_subparsers,
        "rename",
        help_text="Rename an enum member",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(
        child,
        OperationBinding(
            "enum_member_rename",
            parameter_attrs=(
                ("enum_name", "enum_name"),
                ("member_name", "member_name"),
                ("new_name", "new_name"),
            ),
        ),
    )
    child.add_argument("enum_name", help="Enum name")
    child.add_argument("member_name", help="Enum member name")
    child.add_argument("new_name", help="Replacement name")

    child = add_standard_command(
        member_parser,
        member_subparsers,
        "delete",
        help_text="Delete an enum member",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(
        child,
        OperationBinding(
            "enum_member_delete",
            parameter_attrs=(("enum_name", "enum_name"), ("member_name", "member_name")),
        ),
    )
    child.add_argument("enum_name", help="Enum name")
    child.add_argument("member_name", help="Enum member name")
