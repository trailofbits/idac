from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_pattern_options, add_standard_command
from ..commands.common import send_op
from ..result import CommandResult


def _list_params(args: argparse.Namespace) -> dict[str, object]:
    return {
        "pattern": args.pattern,
        "regex": args.regex,
        "ignore_case": args.ignore_case,
    }


def _list(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="segment_list", params=_list_params(args))


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "segment", help_text="Segment operations")
    segment_subparsers = parser.add_subparsers(dest="segment_command")

    child = add_standard_command(parser, segment_subparsers, "list", help_text="List segments", run=_list)
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="SEGMENT_FILTER",
        help="Optional substring filter over segment names; with --regex, treat as a regex",
    )
    add_pattern_options(child, label="SEGMENT_FILTER")
