from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_context_options, add_output_options
from ..errors import CliUserError
from ..result import CommandResult
from .common import OperationBinding, bind_operation, command_result, run_bound_operation


def _save(args: argparse.Namespace) -> CommandResult:
    session = getattr(args, "_nexus_session", None)
    if session is None:
        raise CliUserError("database save requires a Nexus context")
    return command_result("db_save", session.save_database())


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "database", help_text="Inspect or checkpoint database state")
    db_subparsers = parser.add_subparsers(dest="database_command")

    child = add_command(parser, db_subparsers, "show", help_text="Show database info")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.set_defaults(
        run=run_bound_operation,
        allow_batch=True,
        allow_preview=False,
    )
    bind_operation(child, OperationBinding("database_info"))

    child = add_command(parser, db_subparsers, "save", help_text="Checkpoint the current database")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.set_defaults(run=_save, allow_batch=True, allow_preview=False)


__all__ = ["register"]
