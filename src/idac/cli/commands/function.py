from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..argparse_utils import (
    add_command,
    add_context_options,
    add_decl_input,
    add_output_options,
    add_pattern_options,
    add_segment_option,
    add_standard_command,
    positive_int,
    read_decl_text,
)
from ..commands.common import (
    OperationBinding,
    bind_operation,
    local_rename_params,
    local_retype_params,
    local_update_params,
    run_bound_operation,
)
from ..errors import CliUserError
from ..result import CommandResult

LOCAL_SELECTOR_HELP = (
    "Local selector from `function locals list`: current local name, numeric index, or canonical local_id. "
    "For batch or post-reanalysis work, prefer --local-id or --index over a guessed name."
)

LOCAL_SELECTOR_EPILOG = """examples:
  # Rename by current local name
  idac function locals rename sub_401000 v12 --new-name value_count

  # Rename by stable local id from `function locals list --json`
  idac function locals rename sub_401000 --local-id 'stack(16)@0x100000460' --new-name value_count

  # Retype by decompiler local index
  idac function locals retype sub_401000 --index 3 --type 'unsigned int'

  # Rename and retype in one mutation
  idac function locals update sub_401000 --local-id 'stack(16)@0x100000460' --rename value_count \\
    --decl 'unsigned int value_count;'
"""


def _list_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {
        "pattern": args.pattern,
        "regex": args.regex,
        "ignore_case": args.ignore_case,
        "demangle": args.demangle,
    }
    if args.segment:
        params["segment"] = args.segment
    if args.limit is not None:
        params["limit"] = args.limit
    return params


def _locals_apply_plan_params(args: argparse.Namespace) -> dict[str, object]:
    path = Path(args.json_file)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliUserError(f"failed to read local apply JSON file {path}: {exc}") from exc
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise CliUserError(f"invalid local apply JSON: {exc}") from exc
    if not isinstance(raw, list):
        raise CliUserError("local apply JSON must be a list")
    return {"identifier": args.function, "items": raw}


def _prototype_set_params(args: argparse.Namespace) -> dict[str, object]:
    params = {
        "identifier": args.function,
        "decl": read_decl_text(args),
    }
    if args.propagate_callers:
        params["propagate_callers"] = True
    if args._preview_wrapper:
        params["preview_decompile"] = True
    return params


def _prototype_check_failure_lines(value: dict[str, Any]) -> list[str]:
    diagnostics = [str(item) for item in value.get("diagnostics") or [] if str(item)]
    lines = ["function prototype check failed:"]
    if diagnostics:
        lines.extend(f"- {item}" for item in diagnostics)
    else:
        lines.append("- prototype declaration did not validate")
    return lines


def _prototype_check_params(args: argparse.Namespace) -> dict[str, object]:
    return {"identifier": args.function, "decl": read_decl_text(args)}


def run_prototype_check(args: argparse.Namespace) -> CommandResult:
    result = run_bound_operation(args)
    if isinstance(result.value, dict) and result.value.get("success") is False:
        result.exit_code = 1
        result.stderr_lines = _prototype_check_failure_lines(result.value)
    return result


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "function", help_text="Function operations")
    parser_subparsers = parser.add_subparsers(dest="function_command")

    child = add_command(parser, parser_subparsers, "list", help_text="List functions")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="NAME_FILTER",
        help=(
            "Select functions by one name substring; with --regex, treat as a regex. "
            "This is a filter, not a list of function names."
        ),
    )
    child.add_argument("--limit", type=positive_int, help="Maximum number of functions to return")
    child.add_argument(
        "--demangle",
        action="store_true",
        help="Render matching functions with demangled display names when available",
    )
    add_segment_option(child)
    add_pattern_options(child, label="NAME_FILTER")
    child.set_defaults(
        run=run_bound_operation,
        allow_batch=True,
        allow_preview=True,
        limit=None,
        demangle=False,
    )
    bind_operation(child, OperationBinding("function_list", params_builder=_list_params))

    child = add_standard_command(
        parser,
        parser_subparsers,
        "metadata",
        help_text="Show function metadata",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("function_show", parameter_attrs=(("identifier", "function"),)))
    child.add_argument("function", help="Function name or address")

    child = add_standard_command(
        parser,
        parser_subparsers,
        "frame",
        help_text="Show raw function frame layout",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("function_frame", parameter_attrs=(("identifier", "function"),)))
    child.add_argument("function", help="Function name or address")

    child = add_standard_command(
        parser,
        parser_subparsers,
        "stackvars",
        help_text="Show stack variables and xrefs",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("function_stackvars", parameter_attrs=(("identifier", "function"),)))
    child.add_argument("function", help="Function name or address")

    child = add_standard_command(
        parser,
        parser_subparsers,
        "callees",
        help_text="Show called functions and call sites",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("function_callees", parameter_attrs=(("identifier", "function"),)))
    child.add_argument("function", help="Function name or address")

    child = add_standard_command(
        parser,
        parser_subparsers,
        "callers",
        help_text="Show callers and call sites",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("function_callers", parameter_attrs=(("identifier", "function"),)))
    child.add_argument("function", help="Function name or address")

    locals_parser = add_command(parser, parser_subparsers, "locals", help_text="Decompiler local variable operations")
    locals_subparsers = locals_parser.add_subparsers(dest="locals_command")

    child = add_standard_command(
        locals_parser,
        locals_subparsers,
        "list",
        help_text="List decompiler locals",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("local_list", parameter_attrs=(("identifier", "function"),)))
    child.add_argument("function", help="Function name or address")

    child = add_standard_command(
        locals_parser,
        locals_subparsers,
        "rename",
        help_text="Rename one local variable",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("local_rename", params_builder=local_rename_params))
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = LOCAL_SELECTOR_EPILOG
    child.add_argument("function", help="Function name or address")
    child.add_argument(
        "selector",
        nargs="?",
        metavar="LOCAL_SELECTOR",
        help=LOCAL_SELECTOR_HELP,
    )
    child.add_argument("--local-id", dest="local_id", help="Stable local id from `function locals list --json`")
    child.add_argument("--index", help="Decompiler local index from `function locals list --json`")
    child.add_argument("--new-name", required=True, metavar="NEW_NAME", help="Replacement local variable name")

    child = add_standard_command(
        locals_parser,
        locals_subparsers,
        "retype",
        help_text="Retype one local variable",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("local_retype", params_builder=local_retype_params))
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = LOCAL_SELECTOR_EPILOG
    child.add_argument("function", help="Function name or address")
    child.add_argument(
        "selector",
        nargs="?",
        metavar="LOCAL_SELECTOR",
        help=LOCAL_SELECTOR_HELP,
    )
    child.add_argument("--local-id", dest="local_id", help="Stable local id from `function locals list --json`")
    child.add_argument("--index", help="Decompiler local index from `function locals list --json`")
    retype_input = child.add_mutually_exclusive_group(required=True)
    retype_input.add_argument(
        "--type",
        dest="type_text",
        help="Local type text shorthand, for example `unsigned int`; use --decl or --decl-file for complex declarators",
    )
    retype_input.add_argument(
        "--decl",
        help="Full local variable declaration text, for example `unsigned int value;`",
    )
    retype_input.add_argument(
        "--decl-file",
        dest="decl_file",
        type=Path,
        help="Read full local variable declaration text from this file",
    )
    child.set_defaults(_input_path_attrs=("decl_file",))

    child = add_standard_command(
        locals_parser,
        locals_subparsers,
        "update",
        help_text="Rename and/or retype one local variable",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("local_update", params_builder=local_update_params))
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = LOCAL_SELECTOR_EPILOG
    child.add_argument("function", help="Function name or address")
    child.add_argument("selector", nargs="?", metavar="LOCAL_SELECTOR", help=LOCAL_SELECTOR_HELP)
    child.add_argument("--local-id", dest="local_id", help="Stable local id from `function locals list --json`")
    child.add_argument("--index", help="Decompiler local index from `function locals list --json`")
    child.add_argument("--rename", metavar="NEW_NAME", help="Replacement local variable name")
    update_decl_group = child.add_mutually_exclusive_group(required=False)
    update_decl_group.add_argument("--decl", help="Full local variable declaration text")
    update_decl_group.add_argument(
        "--decl-file",
        dest="decl_file",
        type=Path,
        help="Read full local variable declaration text from this file",
    )
    child.set_defaults(_input_path_attrs=("decl_file",))

    child = add_standard_command(
        locals_parser,
        locals_subparsers,
        "apply",
        help_text="Apply local updates from JSON",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("local_apply_plan", params_builder=_locals_apply_plan_params))
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = """plan JSON:
  [
    {"local_id": "stack(16)@0x100000460", "rename": "count", "decl": "unsigned int count;"},
    {"index": 3, "type": "uint64_t"}
  ]
"""
    child.add_argument("function", help="Function name or address")
    child.add_argument("--json-file", required=True, type=Path, help="Read local update plan JSON from this file")
    child.set_defaults(_input_path_attrs=("json_file",))

    proto_parser = add_command(parser, parser_subparsers, "prototype", help_text="Prototype operations")
    proto_subparsers = proto_parser.add_subparsers(dest="prototype_command")

    child = add_standard_command(
        proto_parser,
        proto_subparsers,
        "show",
        help_text="Show a prototype",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("proto_get", parameter_attrs=(("identifier", "function"),)))
    child.add_argument("function", help="Function name or address")

    child = add_standard_command(
        proto_parser,
        proto_subparsers,
        "check",
        help_text="Validate a prototype without applying it",
        run=run_prototype_check,
        default_format="json",
    )
    bind_operation(child, OperationBinding("proto_check", params_builder=_prototype_check_params))
    child.add_argument("function", help="Function name or address")
    add_decl_input(child, help_text="Prototype declaration text")

    child = add_command(proto_parser, proto_subparsers, "set", help_text="Set a prototype")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("function", help="Function name or address")
    add_decl_input(child, help_text="Prototype declaration text")
    child.add_argument(
        "--propagate-callers",
        action="store_true",
        help="Also apply the new callee type at matching caller call sites",
    )
    child.set_defaults(
        run=run_bound_operation,
        allow_batch=True,
        allow_preview=True,
        propagate_callers=False,
    )
    bind_operation(child, OperationBinding("proto_set", params_builder=_prototype_set_params))
