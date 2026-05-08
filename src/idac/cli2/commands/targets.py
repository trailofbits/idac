from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ...doctor import run_doctor_cleanup
from ...transport import BackendError
from ...transport.idalib_common import normalize_database_path
from ...transport.schema import RequestEnvelope
from ..argparse_utils import add_command, add_context_options, add_output_options
from ..commands.common import command_result, send_request
from ..errors import CliUserError
from ..result import CommandResult

AGGREGATE_GUI_DISCOVERY_TIMEOUT = 2.0


def _target_sort_key(item: dict[str, Any]) -> tuple[int, str, int, str]:
    backend_order = {"gui": 0, "idalib": 1}
    backend = str(item.get("backend") or "")
    try:
        pid = int(item.get("instance_pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    return (
        backend_order.get(backend, 99),
        str(item.get("module") or ""),
        pid,
        str(item.get("filename") or ""),
    )


def _row_matches_database(item: dict[str, Any], database: str) -> bool:
    try:
        requested = normalize_database_path(database)
    except (OSError, RuntimeError, ValueError):
        requested = str(Path(database).expanduser())
    values = {
        str(item.get("filename") or ""),
        str(item.get("database_path") or ""),
    }
    for value in values:
        if not value:
            continue
        try:
            if normalize_database_path(value) == requested:
                return True
        except (OSError, RuntimeError, ValueError):
            if value == database:
                return True
    return False


def _row_matches_target(item: dict[str, Any], target: str) -> bool:
    target_text = str(target).strip()
    if not target_text:
        return True
    values = {
        str(item.get("target_id") or ""),
        str(item.get("selector") or ""),
        str(item.get("local_selector") or ""),
        str(item.get("local_target_id") or ""),
        str(item.get("instance_selector") or ""),
        str(item.get("module") or ""),
        str(item.get("filename") or ""),
    }
    return target_text in values


def _list_backend(args: argparse.Namespace, backend: str) -> tuple[list[dict[str, Any]], list[str]]:
    timeout = getattr(args, "timeout", None)
    if backend == "gui" and args.backend is None and timeout is None:
        timeout = AGGREGATE_GUI_DISCOVERY_TIMEOUT
    response = send_request(
        RequestEnvelope(
            op="list_targets",
            backend=backend,
            target=args.target,
            database=args.database,
            timeout=timeout,
        )
    )
    if not response.get("ok"):
        raise CliUserError(str(response.get("error") or f"{backend} target listing failed"))
    rows = [dict(item) for item in (response.get("result") or []) if isinstance(item, dict)]
    for row in rows:
        row.setdefault("backend", backend)
    if backend == "gui" and args.target:
        rows = [row for row in rows if _row_matches_target(row, str(args.target))]
    if backend == "idalib" and args.database:
        rows = [row for row in rows if _row_matches_database(row, str(args.database))]
    warnings = [str(item) for item in (response.get("warnings") or []) if str(item)]
    return rows, warnings


def _list(args: argparse.Namespace) -> CommandResult:
    backends = [args.backend] if args.backend else ["gui", "idalib"]
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    for backend in backends:
        try:
            backend_rows, backend_warnings = _list_backend(args, str(backend))
        except BackendError as exc:
            errors.append(f"{backend}: {exc}")
            continue
        rows.extend(backend_rows)
        warnings.extend(backend_warnings)

    if errors and not rows:
        raise CliUserError("; ".join(errors))
    warnings.extend(f"failed to list {error}" for error in errors)
    rows.sort(key=_target_sort_key)
    return command_result("list_targets", rows, warnings=warnings)


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
