from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Optional

from ..transport.gui import list_discovered_instances as list_gui_discovered_instances
from ..transport.gui import list_instances as list_gui_instances
from ..transport.idalib import list_instances as list_idalib_instances
from .errors import CliUserError

DATABASE_CONTEXT_PREFIX = "db:"


@dataclass(frozen=True)
class ResolvedContext:
    backend: str | None
    target: str | None
    database: str | None
    timeout: float | None


def database_path_from_context(locator: str) -> Optional[str]:
    text = str(locator).strip()
    if not text:
        return None
    lowered = text.lower()
    if not lowered.startswith(DATABASE_CONTEXT_PREFIX):
        return None
    database = text[len(DATABASE_CONTEXT_PREFIX) :].strip()
    return database or None


def merge_parent_context(inner_args: argparse.Namespace, outer_args: argparse.Namespace) -> None:
    if hasattr(outer_args, "context") and not hasattr(inner_args, "context"):
        inner_args.context = outer_args.context
    if hasattr(outer_args, "timeout") and not hasattr(inner_args, "timeout"):
        inner_args.timeout = outer_args.timeout


def require_timeout_if_needed(args: argparse.Namespace) -> None:
    if not args._require_timeout:
        return
    if getattr(args, "timeout", None) is not None:
        return
    label = str(args._timeout_requirement_label or "this command")
    raise CliUserError(f"{label} requires --timeout")


def resolve_context(parser: argparse.ArgumentParser, args: argparse.Namespace) -> ResolvedContext:
    if not args._uses_context:
        return ResolvedContext(None, None, None, None)

    policy = args.context_policy
    timeout = getattr(args, "timeout", None)
    context = getattr(args, "context", None)

    if policy in {"none", "wrapper"}:
        return ResolvedContext(None, None, None, timeout)

    if policy == "database_open":
        return ResolvedContext("idalib", None, None, timeout)

    if policy == "targets_list":
        if context:
            locator = str(context).strip()
            database = database_path_from_context(locator)
            if database is not None:
                return ResolvedContext("idalib", None, database, timeout)
            return ResolvedContext("gui", locator, None, timeout)
        return ResolvedContext(None, None, None, timeout)

    if context:
        locator = str(context).strip()
        database = database_path_from_context(locator)
        if database is not None:
            return ResolvedContext("idalib", None, database, timeout)
        return ResolvedContext("gui", locator, None, timeout)

    discovered_instances = list_gui_discovered_instances(warnings=[])
    warnings: list[str] = []
    gui_instances = list_gui_instances(timeout=timeout, warnings=warnings)
    idalib_instances = list_idalib_instances()
    timeout_warnings = [warning for warning in warnings if "timed out" in warning.lower()]
    candidate_count = len(gui_instances) + len(idalib_instances)
    if candidate_count == 1 and timeout_warnings and len(discovered_instances) > len(gui_instances):
        raise CliUserError(
            "IDA target autodiscovery is ambiguous because at least one GUI session timed out during "
            "discovery; increase --timeout or pass an explicit context with "
            "`-c pid:<pid>`, `-c <module>`, or `-c db:<database.i64>`. "
            f"Details: {timeout_warnings[0]}"
        )
    if candidate_count == 1 and gui_instances:
        return ResolvedContext("gui", None, None, timeout)
    if candidate_count == 1:
        return ResolvedContext("idalib", None, idalib_instances[0].database_path, timeout)
    if candidate_count == 0:
        if timeout_warnings:
            raise CliUserError(
                "IDA GUI autodiscovery timed out; increase --timeout or pass an explicit context with "
                "`-c pid:<pid>`, `-c <module>`, or `-c db:<database.i64>`. "
                f"Details: {timeout_warnings[0]}"
            )
        parser.error("no live IDA context found; start IDA, open an idalib database, or pass -c db:<database.i64>")
    parser.error("multiple live IDA contexts found; pass -c pid:<pid>, -c <module>, or -c db:<database.i64>")


def apply_context(args: argparse.Namespace, resolved: ResolvedContext) -> None:
    args.backend = resolved.backend
    args.target = resolved.target
    args.database = resolved.database
    if resolved.timeout is not None:
        args.timeout = resolved.timeout


def validate_context(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    backend = args.backend
    if backend is None:
        return

    policy = args.context_policy
    database = args.database

    if policy == "database_open":
        return
    if policy == "database_close":
        if backend != "idalib":
            parser.error("`idac database close` is only supported for idalib contexts")
        if not database:
            parser.error("`idac database close` requires -c db:<database.i64>")
        return
    if backend == "idalib" and not database:
        parser.error("-c db:<database.i64> is required for idalib commands")
