from __future__ import annotations

import argparse
from dataclasses import dataclass

from ..argparse_utils import add_command, add_context_options, add_output_options, add_pattern_options
from ..commands.common import send_op
from ..result import CommandResult


@dataclass(frozen=True)
class SegmentListRequest:
    pattern: str | None
    regex: bool
    ignore_case: bool

    def to_params(self) -> dict[str, object]:
        params: dict[str, object] = {
            "pattern": self.pattern,
            "regex": self.regex,
            "ignore_case": self.ignore_case,
        }
        return params


def _list_request(args: argparse.Namespace) -> SegmentListRequest:
    return SegmentListRequest(pattern=args.pattern, regex=args.regex, ignore_case=args.ignore_case)


def _list(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="segment_list", params=_list_request(args).to_params(), render_op="segment_list")


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
