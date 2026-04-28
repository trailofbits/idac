from __future__ import annotations

import argparse
from pathlib import Path

from ..output import write_output_result
from .argparse_utils import add_command, add_context_options, bind_root_handler
from .errors import CliUserError
from .invocation import Invocation, parse_invocation, run_invocation
from .result import CommandResult


def _preview_payload(*, command: str, result: CommandResult, wrapped: Invocation) -> dict[str, object]:
    value = result.value
    stderr = result.stderr_lines
    if wrapped.spec.mutating:
        if not isinstance(value, dict):
            raise RuntimeError("preview expected an object result for a mutating command")
        before = value.get("before")
        after = value.get("after")
        result_payload = value.get("result")
        if result_payload is None:
            result_payload = {
                key: item
                for key, item in value.items()
                if key not in {"before", "after", "preview", "preview_mode", "persisted"}
            }
        return {
            "command": command,
            "status": "ok" if result.exit_code == 0 else "failed",
            "before": before,
            "after": after,
            "result": result_payload,
            "readback": after,
            "undo": {
                "status": "ok",
                "mode": value.get("preview_mode", "undo"),
                "persisted": value.get("persisted", False),
            },
            "artifacts": list(result.artifacts),
            "stderr": stderr,
        }
    return {
        "command": command,
        "status": "ok" if result.exit_code == 0 else "failed",
        "before": value,
        "after": value,
        "result": value,
        "readback": value,
        "undo": {"status": "noop", "mode": "read_only", "persisted": False},
        "artifacts": list(result.artifacts),
        "stderr": stderr,
    }


def run(args: argparse.Namespace, *, root_parser: argparse.ArgumentParser):
    tokens = list(args.command_tokens or [])
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    if not tokens:
        raise CliUserError("preview requires a command to wrap")
    preview_invocation = getattr(args, "_invocation", args)
    relative_path_base_dir = getattr(args, "_relative_path_base_dir", None)
    child = parse_invocation(
        root_parser,
        tokens,
        parent=preview_invocation,
        base_dir=Path(relative_path_base_dir) if relative_path_base_dir is not None else None,
        preview=True,
        batch_mode=bool(args._batch_mode),
        prepare=False,
    )
    if child.spec.hidden or not child.spec.allow_preview:
        raise CliUserError("command is not available in preview mode")
    if child.args.command == "preview":
        raise CliUserError("nested preview is not supported")
    if not args._batch_mode and args.out is None:
        raise CliUserError("preview requires `--out <path.json|path.jsonl>`")
    result = run_invocation(child)
    payload = _preview_payload(command=" ".join(tokens), result=result, wrapped=child)
    if args._batch_mode:
        return CommandResult(
            render_op="preview",
            value=payload,
            exit_code=result.exit_code,
            stderr_lines=list(result.stderr_lines),
            artifacts=list(result.artifacts),
        )
    out_path = Path(args.out)
    fmt = "jsonl" if out_path.suffix.lower() == ".jsonl" else "json"
    output = write_output_result(payload, fmt=fmt, out_path=out_path, stem="preview")
    artifacts = [output.artifact] if output.artifact is not None else []
    return CommandResult(
        render_op="preview",
        value={"ok": result.exit_code == 0, "out": str(out_path), "format": fmt},
        exit_code=result.exit_code,
        stderr_lines=list(result.stderr_lines),
        artifacts=artifacts,
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(
        root_parser, subparsers, "preview", help_text="Run a command under undo and emit structured preview data"
    )
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = """examples:
  # Preview a prototype change; omit the leading `idac` from the wrapped command
  idac preview -o .idac/tmp/proto_preview.json function prototype set sub_401000 --decl-file proto.h -c db:sample.i64

  # Preview a local-variable update and write the full before/after JSON
  idac preview -o .idac/tmp/local_preview.json function locals update sub_401000 \\
    --local-id 'stack(16)@0x1000' --rename count

  # Use -- when the wrapped command begins with an option
  idac preview -o .idac/tmp/comment_preview.json -- comment set 0x401000 'entry point'
"""
    add_context_options(parser)
    parser.add_argument("-o", "--out", type=Path, help="Write preview JSON or JSONL to this file")
    parser.add_argument(
        "command_tokens",
        nargs=argparse.REMAINDER,
        metavar="COMMAND...",
        help=(
            "idac subcommand to preview, without the leading `idac`. "
            "Outside batch mode, preview requires --out so the full JSON/JSONL artifact is preserved."
        ),
    )
    parser.set_defaults(
        run=bind_root_handler(root_parser, run),
        context_policy="wrapper",
        allow_batch=True,
        allow_preview=False,
        _mutating_command=False,
    )
