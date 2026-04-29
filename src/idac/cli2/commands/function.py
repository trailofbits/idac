from __future__ import annotations

import argparse
from pathlib import Path

from ..argparse_utils import (
    add_command,
    add_context_options,
    add_decl_input,
    add_output_options,
    add_pattern_options,
    add_retype_input,
    add_segment_option,
    positive_int,
    read_decl_text,
)
from ..commands.common import local_rename_params, local_retype_params, local_update_params, send_op
from ..errors import CliUserError
from ..invocation import Invocation
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
    if args.pattern and args.query:
        raise CliUserError("function list accepts either positional pattern or --query, not both")
    params: dict[str, object] = {
        "pattern": args.pattern if args.pattern is not None else args.query,
        "regex": args.regex,
        "ignore_case": args.ignore_case,
        "demangle": args.demangle,
    }
    if args.segment:
        params["segment"] = args.segment
    if args.limit is not None:
        params["limit"] = args.limit
    return params


def run_list(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(invocation, op="function_list", params=_list_params(args), render_op="function_list")


def run_metadata(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(invocation, op="function_show", params={"identifier": args.function}, render_op="function_show")


def run_frame(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(invocation, op="function_frame", params={"identifier": args.function}, render_op="function_frame")


def run_stackvars(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(
        invocation, op="function_stackvars", params={"identifier": args.function}, render_op="function_stackvars"
    )


def run_callees(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(
        invocation, op="function_callees", params={"identifier": args.function}, render_op="function_callees"
    )


def run_callers(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(
        invocation, op="function_callers", params={"identifier": args.function}, render_op="function_callers"
    )


def run_locals_list(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(invocation, op="local_list", params={"identifier": args.function}, render_op="local_list")


def run_locals_rename(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="local_rename", params=local_rename_params(invocation.args), render_op="local_rename")


def run_locals_retype(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="local_retype", params=local_retype_params(invocation.args), render_op="local_retype")


def run_locals_update(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="local_update", params=local_update_params(invocation.args), render_op="local_update")


def run_prototype_show(invocation: Invocation) -> CommandResult:
    args = invocation.args
    return send_op(invocation, op="proto_get", params={"identifier": args.function}, render_op="proto_get")


def _prototype_set_params(invocation: Invocation) -> dict[str, object]:
    args = invocation.args
    params = {
        "identifier": args.function,
        "decl": read_decl_text(args),
    }
    if args.propagate_callers:
        params["propagate_callers"] = True
    if invocation.preview:
        params["preview_decompile"] = True
    return params


def run_prototype_set(invocation: Invocation) -> CommandResult:
    params = _prototype_set_params(invocation)
    return send_op(invocation, op="proto_set", params=params, render_op="proto_set")


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
    child.add_argument("--query", help=argparse.SUPPRESS)
    child.add_argument("--limit", type=positive_int, help="Maximum number of functions to return")
    child.add_argument(
        "--demangle",
        action="store_true",
        help="Render matching functions with demangled display names when available",
    )
    add_segment_option(child)
    add_pattern_options(child, label="NAME_FILTER")
    child.set_defaults(
        run=run_list,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=False,
        query=None,
        limit=None,
        demangle=False,
    )

    child = add_command(parser, parser_subparsers, "metadata", help_text="Show function metadata")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("function", help="Function name or address")
    child.set_defaults(
        run=run_metadata, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, parser_subparsers, "frame", help_text="Show raw function frame layout")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("function", help="Function name or address")
    child.set_defaults(
        run=run_frame, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, parser_subparsers, "stackvars", help_text="Show stack variables and xrefs")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("function", help="Function name or address")
    child.set_defaults(
        run=run_stackvars, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, parser_subparsers, "callees", help_text="Show called functions and call sites")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("function", help="Function name or address")
    child.set_defaults(
        run=run_callees, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, parser_subparsers, "callers", help_text="Show callers and call sites")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("function", help="Function name or address")
    child.set_defaults(
        run=run_callers, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    locals_parser = add_command(parser, parser_subparsers, "locals", help_text="Decompiler local variable operations")
    locals_subparsers = locals_parser.add_subparsers(dest="locals_command")

    child = add_command(locals_parser, locals_subparsers, "list", help_text="List decompiler locals")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("function", help="Function name or address")
    child.set_defaults(
        run=run_locals_list, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(locals_parser, locals_subparsers, "rename", help_text="Rename one local variable")
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = LOCAL_SELECTOR_EPILOG
    add_context_options(child)
    add_output_options(child, default_format="json")
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
    child.set_defaults(
        run=run_locals_rename, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    child = add_command(locals_parser, locals_subparsers, "retype", help_text="Retype one local variable")
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = LOCAL_SELECTOR_EPILOG
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("function", help="Function name or address")
    child.add_argument(
        "selector",
        nargs="?",
        metavar="LOCAL_SELECTOR",
        help=LOCAL_SELECTOR_HELP,
    )
    child.add_argument("--local-id", dest="local_id", help="Stable local id from `function locals list --json`")
    child.add_argument("--index", help="Decompiler local index from `function locals list --json`")
    add_retype_input(child)
    child.set_defaults(
        run=run_locals_retype, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    child = add_command(locals_parser, locals_subparsers, "update", help_text="Rename and/or retype one local variable")
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = LOCAL_SELECTOR_EPILOG
    add_context_options(child)
    add_output_options(child, default_format="json")
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
    child.set_defaults(
        run=run_locals_update, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    proto_parser = add_command(parser, parser_subparsers, "prototype", help_text="Prototype operations")
    proto_subparsers = proto_parser.add_subparsers(dest="prototype_command")

    child = add_command(proto_parser, proto_subparsers, "show", help_text="Show a prototype")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("function", help="Function name or address")
    child.set_defaults(
        run=run_prototype_show, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

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
        run=run_prototype_set,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=True,
        propagate_callers=False,
    )
