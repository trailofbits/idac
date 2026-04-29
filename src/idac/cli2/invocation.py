from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .context import (
    ResolvedContext,
    apply_context,
    merge_parent_context,
    require_timeout_if_needed,
    resolve_context,
    validate_context,
)
from .errors import CliUserError
from .path_resolution import resolve_relative_paths
from .result import CommandResult


@dataclass(frozen=True)
class CommandSpec:
    handler: Callable[[Invocation], CommandResult] | None
    mutating: bool
    allow_batch: bool
    allow_preview: bool
    hidden: bool
    uses_context: bool
    accepts_timeout: bool
    context_policy: str
    requires_timeout: bool
    timeout_requirement_label: str | None

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> CommandSpec:
        return cls(
            handler=getattr(args, "run", None),
            mutating=bool(getattr(args, "_mutating_command", False)),
            allow_batch=bool(getattr(args, "allow_batch", True)),
            allow_preview=bool(getattr(args, "allow_preview", True)),
            hidden=bool(getattr(args, "_hidden_command", False)),
            uses_context=bool(getattr(args, "_uses_context", False)),
            accepts_timeout=bool(getattr(args, "_accepts_timeout", False)),
            context_policy=str(getattr(args, "context_policy", "standard")),
            requires_timeout=bool(getattr(args, "_require_timeout", False)),
            timeout_requirement_label=getattr(args, "_timeout_requirement_label", None),
        )


@dataclass(frozen=True)
class Invocation:
    spec: CommandSpec
    args: argparse.Namespace
    argv: tuple[str, ...]
    context: ResolvedContext | None
    preview: bool = False
    batch_mode: bool = False
    prepared: bool = True
    base_dir: Path | None = None


def _parent_args(parent: Invocation | argparse.Namespace | None) -> argparse.Namespace | None:
    if parent is None:
        return None
    if isinstance(parent, Invocation):
        return parent.args
    return parent


def _reject_unsupported_forwarded_context(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    spec = CommandSpec.from_args(args)
    if spec.uses_context:
        return
    command = f"`{parser.prog}`"
    if hasattr(args, "context"):
        raise CliUserError(f"{command} does not accept -c/--context")
    if hasattr(args, "timeout") and not spec.accepts_timeout:
        raise CliUserError(f"{command} does not accept --timeout")


def _prepare_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> ResolvedContext | None:
    _reject_unsupported_forwarded_context(parser, args)
    spec = CommandSpec.from_args(args)
    if not spec.uses_context:
        return None
    require_timeout_if_needed(args)
    resolved = resolve_context(parser, args)
    apply_context(args, resolved)
    validate_context(parser, args)
    return resolved


def invocation_from_args(
    args: argparse.Namespace,
    *,
    argv: list[str] | tuple[str, ...] | None = None,
    parent: Invocation | argparse.Namespace | None = None,
    base_dir: Path | None = None,
    preview: bool = False,
    batch_mode: bool = False,
    prepare: bool = True,
) -> Invocation:
    parent_namespace = _parent_args(parent)
    if parent_namespace is not None:
        merge_parent_context(args, parent_namespace)
    if base_dir is not None:
        resolve_relative_paths(args, base_dir=base_dir)

    parser = args._selected_parser
    resolved = _prepare_args(parser, args) if prepare else None
    spec = CommandSpec.from_args(args)
    args._spec = spec
    invocation = Invocation(
        spec=spec,
        args=args,
        argv=tuple(argv or getattr(args, "_raw_argv", ())),
        context=resolved,
        preview=bool(preview),
        batch_mode=bool(batch_mode),
        prepared=prepare,
        base_dir=base_dir if base_dir is not None else (parent.base_dir if isinstance(parent, Invocation) else None),
    )
    return invocation


def parse_invocation(
    root_parser: argparse.ArgumentParser,
    argv: list[str],
    *,
    parent: Invocation | argparse.Namespace | None = None,
    base_dir: Path | None = None,
    preview: bool = False,
    batch_mode: bool = False,
    prepare: bool = True,
) -> Invocation:
    args = root_parser.parse_args(argv)
    args._raw_argv = list(argv)
    return invocation_from_args(
        args,
        argv=argv,
        parent=parent,
        base_dir=base_dir,
        preview=preview,
        batch_mode=batch_mode,
        prepare=prepare,
    )


def prepare_invocation(invocation: Invocation) -> Invocation:
    if invocation.prepared:
        return invocation
    args = invocation.args
    parser = args._selected_parser
    resolved = _prepare_args(parser, args)
    spec = CommandSpec.from_args(args)
    args._spec = spec
    return Invocation(
        spec=spec,
        args=args,
        argv=invocation.argv,
        context=resolved,
        preview=invocation.preview,
        batch_mode=invocation.batch_mode,
        prepared=True,
        base_dir=invocation.base_dir,
    )


def run_invocation(invocation: Invocation) -> CommandResult:
    invocation = prepare_invocation(invocation)
    handler = invocation.spec.handler
    if handler is None:
        selected_parser = invocation.args._selected_parser
        selected_parser.print_help()
        raise SystemExit(2)
    return handler(invocation)
