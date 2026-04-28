from __future__ import annotations

import argparse

from ...doctor import run_doctor_cleanup
from ..argparse_utils import add_command, add_context_options, add_output_options
from ..commands.common import command_result, send_op
from ..result import CommandResult


def _list(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="list_targets", params={}, render_op="list_targets")


def _cleanup(_args: argparse.Namespace) -> CommandResult:
    return command_result("targets_cleanup", run_doctor_cleanup())


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "targets", help_text="List and clean up IDA targets")
    targets_subparsers = parser.add_subparsers(dest="targets_command")

    child = add_command(parser, targets_subparsers, "list", help_text="List open targets")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.set_defaults(
        run=_list, context_policy="targets_list", allow_batch=True, allow_preview=False, _mutating_command=False
    )

    child = add_command(
        parser, targets_subparsers, "cleanup", help_text="Remove stale GUI bridge and idalib runtime files"
    )
    add_output_options(child, default_format="text")
    child.set_defaults(
        run=_cleanup, context_policy="none", allow_batch=True, allow_preview=False, _mutating_command=False
    )
