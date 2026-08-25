from __future__ import annotations

import argparse
from contextlib import ExitStack

from ..nexus import NexusSession as _NexusSession
from .context import reject_output_context_aliases, require_timeout_if_needed, resolve_context
from .errors import CliUserError


def reject_unsupported_forwarded_context(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args._uses_context:
        return
    command = f"`{parser.prog}`"
    if hasattr(args, "context"):
        raise CliUserError(f"{command} does not accept -c/--context")
    if hasattr(args, "timeout") and not getattr(args, "_accepts_timeout", False):
        raise CliUserError(f"{command} does not accept --timeout")


def prepare_args(args: argparse.Namespace) -> None:
    parser = args._selected_parser
    reject_unsupported_forwarded_context(parser, args)
    if args._uses_context:
        require_timeout_if_needed(args)
        resolved = resolve_context(args)
        if resolved.locator is not None:
            args.context = resolved.locator
            protected_paths = [resolved.locator]
            if not resolved.locator.lower().endswith(".i64"):
                protected_paths.append(f"{resolved.locator}.i64")
            args._protected_context_paths = tuple(protected_paths)
        if resolved.instance_id is not None:
            args.instance = resolved.instance_id
        inherited_paths = getattr(args, "_protected_context_paths", ())
        if inherited_paths:
            reject_output_context_aliases(args, inherited_paths)


def execute_parsed(args: argparse.Namespace):
    handler = args.run
    if handler is None:
        selected_parser = args._selected_parser
        selected_parser.print_help()
        raise SystemExit(2)
    prepare_args(args)
    session = getattr(args, "_nexus_session", None)
    with ExitStack() as session_context:
        if args._uses_context and session is None:
            from .. import nexus

            try:
                session = nexus.NexusSession(
                    locator=getattr(args, "context", None),
                    instance_id=getattr(args, "instance", None),
                    timeout=getattr(args, "timeout", None),
                )
            except (TypeError, ValueError) as exc:
                raise CliUserError(str(exc)) from exc
            args._nexus_session = session
            session_context.push(_NexusSession.__exit__.__get__(session))
        output_requested = getattr(args, "out", None) is not None or getattr(args, "out_file", None) is not None
        if args._uses_context and not getattr(args, "_protected_context_paths", ()) and output_requested:
            assert session is not None
            targets = session.list_targets()
            instance_id = getattr(args, "instance", None)
            if instance_id is not None:
                targets = [target for target in targets if target.get("record_id") == instance_id]
            protected_paths: list[str] = []
            for target in targets:
                for key in ("idb_path", "exe_path"):
                    value = target.get(key)
                    if not isinstance(value, str) or not value:
                        continue
                    protected_paths.append(value)
                    if key == "exe_path" and not value.lower().endswith(".i64"):
                        protected_paths.append(f"{value}.i64")
            args._protected_context_paths = tuple(dict.fromkeys(protected_paths))
            reject_output_context_aliases(args, args._protected_context_paths)
        return handler(args)
