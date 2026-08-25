from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from ..nexus import NexusSessionError
from ..output import OutputTooLargeError
from ..version import VERSION
from . import batch, preview
from .argparse_utils import add_root_context_options, create_parser, finalize_help_tree
from .commands import (
    bookmark,
    comment,
    database,
    docs,
    doctor,
    function,
    misc,
    python_exec,
    search,
    segment,
    setup,
    targets,
    top_level,
    type_commands,
    workspace,
)
from .errors import CliUserError
from .execute import execute_parsed
from .serialize import artifact_notice, emit_result, json_or_jsonl_from_path

DOCS_INLINE_CHAR_LIMIT = 50_000


def build_parser(*, prog: str = "idac") -> argparse.ArgumentParser:
    parser = create_parser(prog=prog, description="Agent-friendly CLI for IDA")
    add_root_context_options(parser)
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command")

    doctor.register(parser, subparsers)
    docs.register(parser, subparsers)
    database.register(parser, subparsers)
    function.register(parser, subparsers)
    segment.register(parser, subparsers)
    setup.register(parser, subparsers)
    targets.register(parser, subparsers)
    top_level.register(parser, subparsers)
    search.register(parser, subparsers)
    bookmark.register(parser, subparsers)
    comment.register(parser, subparsers)
    type_commands.register(parser, subparsers)
    batch.register(parser, subparsers)
    workspace.register(parser, subparsers)
    python_exec.register(parser, subparsers)
    preview.register(parser, subparsers)
    misc.register(parser, subparsers)
    finalize_help_tree(parser)
    return parser


def _print_error_payload(fmt: str, exc: OutputTooLargeError) -> None:
    if fmt in {"json", "jsonl"}:
        payload = {
            "ok": False,
            "code": "output_too_large",
            "error": str(exc),
            "chars": exc.chars,
            "limit": exc.limit,
            "rerun_with_out": True,
        }
        if exc.hint:
            payload["hint"] = exc.hint
        rendered = json.dumps(payload, indent=None if fmt == "jsonl" else 2, sort_keys=True)
        print(rendered, file=sys.stderr)
        return
    print(str(exc), file=sys.stderr)


def main(argv: list[str] | None = None, *, prog: str = "idac") -> int:
    parser = build_parser(prog=prog)
    args = parser.parse_args(argv)
    arg_map = vars(args)
    try:
        result = execute_parsed(args)
        if args.command == "batch":
            if arg_map.get("out") is None:
                emit_result(result, fmt="json", out_path=None)
                return result.exit_code
            artifacts = result.artifacts
        else:
            emit_kwargs: dict[str, Any] = {}
            if args.command == "preview":
                fmt = json_or_jsonl_from_path(arg_map["out"])
                out_path = arg_map["out"]
            else:
                fmt = arg_map.get("format", "text")
                out_path = arg_map.get("out")
                if args.command == "docs" and not arg_map.get("all", False):
                    emit_kwargs["inline_limit"] = DOCS_INLINE_CHAR_LIMIT
            artifacts = emit_result(
                result,
                fmt=fmt,
                out_path=out_path,
                **emit_kwargs,
            )
            result.artifacts.extend(artifacts)
        if result.exit_code == 0:
            for artifact in artifacts:
                if notice := artifact_notice(result, artifact):
                    print(notice, file=sys.stderr)
        else:
            for line in result.stderr_lines:
                if text := line.rstrip():
                    print(text, file=sys.stderr)
        return result.exit_code
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        raise
    except OutputTooLargeError as exc:
        _print_error_payload(arg_map.get("format", "text"), exc)
        return 1
    except (KeyboardInterrupt, NexusSessionError, CliUserError, OSError) as exc:
        if isinstance(exc, KeyboardInterrupt):
            message = "interrupted"
            exit_code = 130
        else:
            message = str(exc) or exc.__class__.__name__
            exit_code = 1
        print(message, file=sys.stderr)
        for note in getattr(exc, "__notes__", ()):
            print(f"note: {note}", file=sys.stderr)
        return exit_code
