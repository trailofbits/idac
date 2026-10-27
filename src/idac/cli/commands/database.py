from __future__ import annotations

import argparse
from functools import partial
from pathlib import Path

from ...host import HostedCommand, host_status, start_host, stop_host
from ..argparse_utils import add_command, add_context_options, add_output_options, positive_timeout
from ..errors import CliUserError
from ..path_resolution import reject_output_aliases
from ..result import CommandResult
from .common import OperationBinding, bind_operation, command_result, run_bound_operation


def _save(args: argparse.Namespace) -> CommandResult:
    session = getattr(args, "_nexus_session", None)
    if session is None:
        raise CliUserError("database save requires a Nexus context")
    return command_result("db_save", session.save_database())


def _reject_lifecycle_output_aliases(
    output: Path | None, database: Path, state: dict[str, object] | None = None
) -> None:
    protected: list[tuple[str, Path | None]] = [
        ("database or binary", database),
        ("database", Path(f"{database}.i64")),
    ]
    if state is not None:
        for key in ("database", "idb_path", "exe_path"):
            path = state.get(key)
            if isinstance(path, str) and path:
                protected.append(("database or binary", Path(path)))
                if key != "idb_path" and not path.lower().endswith(".i64"):
                    protected.append(("database", Path(f"{path}.i64")))
    reject_output_aliases(output, protected, option_label="--out")


def _lifecycle(args: argparse.Namespace) -> CommandResult:
    state = None
    host_id = None
    if args.database_command == "close":
        record_id = vars(args).get("instance")
        if not record_id:
            raise CliUserError("database close requires --instance with the record ID returned by database open")
        command = HostedCommand.for_instance(record_id)
        if command is None:
            raise CliUserError(f"target {record_id} was not opened with database open")
        host_id = command.directory.name
        state = host_status(host_id)
    database = args.database if state is None else Path(state["database"])
    _reject_lifecycle_output_aliases(args.out, database, state)
    if args.database_command == "open":
        state = start_host(
            database,
            timeout=args.timeout,
            validate_state=partial(_reject_lifecycle_output_aliases, args.out, database),
        )
    else:
        assert host_id is not None
        state = stop_host(host_id, discard=args.discard, timeout=args.timeout)
    return command_result("db_lifecycle", {key: value for key, value in state.items() if key != "host_id"})


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(
        root_parser, subparsers, "database", help_text="Open, inspect, checkpoint, or close a database"
    )
    db_subparsers = parser.add_subparsers(dest="database_command")

    child = add_command(parser, db_subparsers, "open", help_text="Open or reuse a persistent shared database (Linux)")
    child.add_argument("database", type=Path, help="Database or binary to open outside the command sandbox")
    child.add_argument(
        "--timeout", type=positive_timeout, default=argparse.SUPPRESS, help="Startup timeout in seconds (default: 120)"
    )
    add_output_options(child, default_format="json")
    child.set_defaults(run=_lifecycle, _accepts_timeout=True, _default_timeout=120.0)

    child = add_command(
        parser, db_subparsers, "close", help_text="Drain commands, save, and wait for database shutdown"
    )
    child.add_argument("--instance", default=argparse.SUPPRESS, help="Exact record ID returned by database open")
    child.add_argument("--discard", action="store_true", help="Close without saving; required after uncertain failures")
    child.add_argument(
        "--timeout",
        type=positive_timeout,
        default=argparse.SUPPRESS,
        help="Drain and shutdown timeout in seconds (default: 120)",
    )
    add_output_options(child, default_format="json")
    child.set_defaults(run=_lifecycle, _accepts_timeout=True, _default_timeout=120.0)

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
