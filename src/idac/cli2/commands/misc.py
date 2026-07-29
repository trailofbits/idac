from __future__ import annotations

import argparse

from ..argparse_utils import (
    add_command,
    add_context_options,
    add_output_options,
)
from ..commands.common import send_op
from ..result import CommandResult


def _rename(args: argparse.Namespace) -> CommandResult:
    params = {"identifier": args.identifier, "new_name": args.new_name}
    return send_op(args, op="name_set", params=params)


def _reanalyze(args: argparse.Namespace) -> CommandResult:
    params: dict[str, object] = {"identifier": args.identifier}
    if args.end:
        params["end"] = args.end
    return send_op(args, op="reanalyze", params=params)


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "misc", help_text="Maintenance and utility commands")
    misc_subparsers = parser.add_subparsers(dest="misc_command")

    child = add_command(parser, misc_subparsers, "rename", help_text="Rename an item")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Function name, symbol, or address")
    child.add_argument("new_name", help="Replacement name")
    child.set_defaults(
        run=_rename, context_policy="standard", allow_batch=False, allow_preview=False, _mutating_command=True
    )

    child = add_command(parser, misc_subparsers, "reanalyze", help_text="Re-run IDA analysis on a function or range")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Function name, symbol, or address")
    child.add_argument("--end", help="Optional end address for range reanalysis")
    child.set_defaults(
        run=_reanalyze, context_policy="standard", allow_batch=True, allow_preview=False, _mutating_command=True
    )
