from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from .errors import CliUserError
from .path_resolution import reject_output_aliases


@dataclass(frozen=True)
class ResolvedContext:
    locator: str | None
    instance_id: str | None


def _context_path(value: object) -> str:
    locator = str(value).strip()
    if not locator:
        raise CliUserError("-c/--context requires a database or binary path")
    lowered = locator.lower()
    if lowered.startswith(("db:", "pid:", "module:")):
        raise CliUserError(
            "legacy db:/pid:/module: context locators were removed; pass an .i64 or binary path, "
            "or use --instance with an exact Nexus record ID"
        )
    path = Path(locator).expanduser()
    if path.suffix.lower() == ".idb":
        raise CliUserError("32-bit .idb databases are not supported; convert the database to .i64")
    if not path.is_file():
        raise CliUserError(f"context path is not a file: {path}")
    return str(path)


def merge_parent_context(inner_args: argparse.Namespace, outer_args: argparse.Namespace) -> None:
    if hasattr(inner_args, "context") or hasattr(inner_args, "instance"):
        raise CliUserError(
            "batch and preview child commands cannot switch Nexus targets; "
            "put -c/--context or --instance on the wrapper command"
        )
    if hasattr(inner_args, "timeout"):
        raise CliUserError(
            "batch and preview child commands cannot set --timeout; put --timeout on the wrapper command"
        )
    if hasattr(outer_args, "context"):
        inner_args.context = outer_args.context
    if hasattr(outer_args, "instance"):
        inner_args.instance = outer_args.instance
    if hasattr(outer_args, "timeout"):
        inner_args.timeout = outer_args.timeout
    session = getattr(outer_args, "_nexus_session", None)
    if session is not None:
        inner_args._nexus_session = session
    protected_paths = getattr(outer_args, "_protected_context_paths", None)
    if protected_paths is not None:
        inner_args._protected_context_paths = protected_paths


def reject_output_context_aliases(args: argparse.Namespace, protected_paths: tuple[str, ...]) -> None:
    """Keep command artifacts from replacing a selected input or IDA database."""

    protected: list[tuple[str, Path | None]] = [
        ("selected input or database", Path(value)) for value in protected_paths
    ]
    protected.extend(
        (f"--{key.replace('_', '-')} input", value)
        for key, value in vars(args).items()
        if isinstance(value, Path) and key not in {"out", "out_file", "out_dir"}
    )
    for output_key in ("out", "out_file"):
        output_value = getattr(args, output_key, None)
        if output_value is None:
            continue
        reject_output_aliases(
            Path(output_value),
            protected,
            option_label=f"--{output_key.replace('_', '-')}",
        )


def require_timeout_if_needed(args: argparse.Namespace) -> None:
    if not getattr(args, "_require_timeout", False):
        return
    if getattr(args, "timeout", None) is not None:
        return
    label = str(getattr(args, "_timeout_requirement_label", None) or "this command")
    raise CliUserError(f"{label} requires --timeout")


def resolve_context(args: argparse.Namespace) -> ResolvedContext:
    if not args._uses_context:
        return ResolvedContext(None, None)

    raw_locator = getattr(args, "context", None)
    raw_instance_id = getattr(args, "instance", None)
    locator = _context_path(raw_locator) if raw_locator is not None else None
    instance_id = str(raw_instance_id).strip() if raw_instance_id is not None else None
    if instance_id == "":
        raise CliUserError("--instance requires a non-empty Nexus record ID")
    if locator is not None and instance_id is not None:
        raise CliUserError("-c/--context and --instance are mutually exclusive")
    return ResolvedContext(locator, instance_id)


__all__ = [
    "ResolvedContext",
    "merge_parent_context",
    "reject_output_context_aliases",
    "require_timeout_if_needed",
    "resolve_context",
]
