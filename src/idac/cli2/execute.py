from __future__ import annotations

import argparse

from .context import apply_context, require_timeout_if_needed, resolve_context, validate_context
from .errors import CliUserError


def _reject_unsupported_forwarded_context(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args._uses_context:
        return
    command = f"`{parser.prog}`"
    if hasattr(args, "context"):
        raise CliUserError(f"{command} does not accept -c/--context")
    if hasattr(args, "timeout") and not getattr(args, "_accepts_timeout", False):
        raise CliUserError(f"{command} does not accept --timeout")


def prepare_args(args: argparse.Namespace) -> argparse.Namespace:
    parser = args._selected_parser
    _reject_unsupported_forwarded_context(parser, args)
    if args._uses_context:
        require_timeout_if_needed(args)
        resolved = resolve_context(parser, args)
        apply_context(args, resolved)
        validate_context(parser, args)
    return args


def execute_parsed(args: argparse.Namespace, *, root_parser: argparse.ArgumentParser):
    handler = args.run
    if handler is None:
        selected_parser = args._selected_parser
        selected_parser.print_help()
        raise SystemExit(2)
    prepare_args(args)
    return handler(args)
