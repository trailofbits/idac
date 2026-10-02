from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_pattern_options, add_standard_command
from ..commands.common import OperationBinding, bind_operation, run_bound_operation


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "segment", help_text="Segment operations")
    segment_subparsers = parser.add_subparsers(dest="segment_command")

    child = add_standard_command(
        parser,
        segment_subparsers,
        "list",
        help_text="List segments",
        run=run_bound_operation,
    )
    bind_operation(
        child,
        OperationBinding(
            "segment_list",
            parameter_attrs=(("pattern", "pattern"), ("regex", "regex"), ("ignore_case", "ignore_case")),
        ),
    )
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="SEGMENT_FILTER",
        help="Optional substring filter over segment names; with --regex, treat as a regex",
    )
    add_pattern_options(child, label="SEGMENT_FILTER")
