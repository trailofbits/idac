from __future__ import annotations

import argparse
from typing import Any

from ...doctor import run_doctor
from ..argparse_utils import add_command, add_output_options, positive_timeout
from ..commands.common import command_result
from ..result import CommandResult


def _check(args: argparse.Namespace) -> CommandResult:
    result = run_doctor(
        backend="all",
        timeout=getattr(args, "timeout", None),
    )
    healthy = bool(result.get("healthy"))
    return command_result(
        "doctor",
        result,
        exit_code=0 if healthy else 1,
        stderr_lines=[] if healthy else _doctor_failure_lines(result),
    )


def _doctor_failure_lines(result: dict[str, Any]) -> list[str]:
    backend = result.get("backend", "unknown")
    status = result.get("status", "unknown")
    lines = [f"doctor failed: backend={backend} status={status}"]
    checks = result.get("checks")
    if not isinstance(checks, list):
        return lines
    error_rows = [item for item in checks if isinstance(item, dict) and item.get("status") == "error"]
    if not error_rows:
        return lines
    for item in error_rows:
        component = item.get("component", "unknown")
        name = item.get("name", "check")
        summary = str(item.get("summary") or "failed").strip()
        lines.append(f"{component}.{name}: {summary}")
    return lines


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "doctor", help_text="Inspect local GUI and idalib health")
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=argparse.SUPPRESS,
        help="Backend request timeout in seconds; omit to wait indefinitely",
    )
    add_output_options(parser, default_format="text")
    parser.set_defaults(
        run=_check,
        _accepts_timeout=True,
        context_policy="none",
        allow_batch=True,
        allow_preview=False,
        _mutating_command=False,
    )
