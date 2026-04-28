from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from ..output import OutputTooLargeError
from ..transport import BackendError
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
    targets,
    top_level,
    type_commands,
    workspace,
)
from .errors import CliUserError
from .execute import execute_parsed
from .result import CommandResult
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


def _print_result_stderr(result: CommandResult) -> None:
    for line in result.stderr_lines:
        text = line.rstrip()
        if text:
            print(text, file=sys.stderr)


def _print_artifact_notices(result: CommandResult, artifacts: list[dict[str, object]]) -> None:
    for artifact in artifacts:
        notice = artifact_notice(result, artifact)
        if notice:
            print(notice, file=sys.stderr)


def main(argv: Optional[list[str]] = None, *, prog: str = "idac") -> int:
    parser = build_parser(prog=prog)
    args = parser.parse_args(argv)
    args._raw_argv = list(argv) if argv is not None else sys.argv[1:]
    arg_map = vars(args)
    try:
        result = execute_parsed(args, root_parser=parser)
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)

        if args.command == "preview" and not arg_map.get("_batch_mode", False):
            if result.exit_code == 0:
                _print_artifact_notices(result, result.artifacts)
            else:
                _print_result_stderr(result)
            return result.exit_code

        if args.command == "batch":
            if arg_map.get("out") is None:
                fmt = json_or_jsonl_from_path(None, default="json")
                emit_result(result, fmt=fmt, out_path=None)
            elif result.exit_code == 0:
                _print_artifact_notices(result, result.artifacts)
            else:
                _print_result_stderr(result)
            return result.exit_code

        emit_kwargs = {}
        if args.command == "docs" and not arg_map.get("all", False):
            emit_kwargs["inline_limit"] = DOCS_INLINE_CHAR_LIMIT
        artifacts = emit_result(
            result,
            fmt=arg_map.get("format", "text"),
            out_path=arg_map.get("out"),
            **emit_kwargs,
        )
        if artifacts:
            result.artifacts.extend(artifacts)
            if result.exit_code == 0:
                _print_artifact_notices(result, artifacts)
        if result.exit_code != 0:
            _print_result_stderr(result)
        return result.exit_code
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        raise
    except OutputTooLargeError as exc:
        _print_error_payload(arg_map.get("format", "text"), exc)
        return 1
    except (BackendError, CliUserError, OSError) as exc:
        print(str(exc) or exc.__class__.__name__, file=sys.stderr)
        return 1
