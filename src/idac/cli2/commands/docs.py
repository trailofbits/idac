from __future__ import annotations

import argparse

from ...docs import docs_payload
from ..argparse_utils import add_command, add_output_options
from ..commands.common import command_result
from ..errors import CliUserError
from ..result import CommandResult


def _show(args: argparse.Namespace) -> CommandResult:
    try:
        payload = docs_payload(args.topic, list_only=bool(args.list), all_topics=bool(args.all))
    except ValueError as exc:
        raise CliUserError(str(exc)) from exc
    return command_result("docs", payload)


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "docs", help_text="Print bundled idac help and IDA guidance")
    add_output_options(parser, default_format="text")
    parser.add_argument(
        "topic",
        nargs="?",
        help="Topic to print, such as cli, workflows, class-recovery, ida-cpp-type-details, or workspace",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="List available docs topics")
    mode.add_argument("--all", action="store_true", help="Print all bundled docs; use --out for large output")
    parser.set_defaults(
        run=_show,
        context_policy="none",
        allow_batch=True,
        allow_preview=False,
        _mutating_command=False,
    )
