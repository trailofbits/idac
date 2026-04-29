from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_context_options, add_output_options, add_pattern_options
from ..commands.common import send_op
from ..invocation import Invocation
from ..result import CommandResult


def _list_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "pattern": args.pattern,
        "regex": args.regex,
        "ignore_case": args.ignore_case,
    }


def _list(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="segment_list", params=_list_params(invocation.args), render_op="segment_list")


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "segment", help_text="Segment operations")
    segment_subparsers = parser.add_subparsers(dest="segment_command")

    child = add_command(parser, segment_subparsers, "list", help_text="List segments")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="SEGMENT_FILTER",
        help="Optional substring filter over segment names; with --regex, treat as a regex",
    )
    add_pattern_options(child, label="SEGMENT_FILTER")
    child.set_defaults(
        run=_list, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )
