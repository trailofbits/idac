from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_context_options, add_output_options, set_context_defaults
from ..commands.common import send_op
from ..invocation import Invocation
from ..result import CommandResult


def _open_params(args: argparse.Namespace) -> dict[str, object]:
    return {"path": str(args.path), "run_auto_analysis": bool(args.run_auto_analysis)}


def _save_params(args: argparse.Namespace) -> dict[str, object]:
    return {} if args.path is None else {"path": str(args.path)}


def _close_params(args: argparse.Namespace) -> dict[str, object]:
    return {"discard": bool(args.discard)}


def _show(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="database_info", params={}, render_op="database_info")


def _open(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="db_open", params=_open_params(invocation.args), render_op="db_open")


def _save(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="db_save", params=_save_params(invocation.args), render_op="db_save")


def _close(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="db_close", params=_close_params(invocation.args), render_op="db_close")


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "database", help_text="Inspect or manage database state")
    db_subparsers = parser.add_subparsers(dest="database_command")

    child = add_command(parser, db_subparsers, "show", help_text="Show database info")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.set_defaults(
        run=_show, context_policy="standard", allow_batch=True, allow_preview=False, _mutating_command=False
    )

    child = add_command(parser, db_subparsers, "open", help_text="Open a database in the idalib daemon")
    add_output_options(child, default_format="json")
    child.add_argument("path", help="Path to a database or binary to open")
    child.add_argument(
        "--no-auto-analysis",
        dest="run_auto_analysis",
        action="store_false",
        help="Open without waiting for auto-analysis",
    )
    set_context_defaults(child)
    child.set_defaults(
        run=_open,
        context_policy="database_open",
        allow_batch=True,
        allow_preview=False,
        _mutating_command=False,
        run_auto_analysis=True,
    )

    child = add_command(parser, db_subparsers, "save", help_text="Save the current database")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("path", nargs="?", help="Optional destination database path")
    child.set_defaults(
        run=_save, context_policy="standard", allow_batch=True, allow_preview=False, _mutating_command=True
    )

    child = add_command(parser, db_subparsers, "close", help_text="Close the current idalib database")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("--discard", action="store_true", help="Close without saving pending changes")
    child.set_defaults(
        run=_close, context_policy="database_close", allow_batch=True, allow_preview=False, _mutating_command=True
    )
