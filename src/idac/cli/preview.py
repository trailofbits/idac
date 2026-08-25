from __future__ import annotations

import argparse
from pathlib import Path

from .argparse_utils import add_command, add_context_options, bind_root_handler
from .context import merge_parent_context
from .errors import CliUserError
from .execute import execute_parsed
from .path_resolution import reject_output_aliases, resolve_relative_paths
from .result import CommandResult


def normalize_wrapped_command_tokens(tokens: list[str] | None) -> list[str]:
    normalized = list(tokens or [])
    return normalized[1:] if normalized[:1] == ["--"] else normalized


def _preview_payload(*, command: str, result: CommandResult, wrapped_args: argparse.Namespace) -> dict[str, object]:
    value = result.value
    if wrapped_args._mutating_command:
        if not isinstance(value, dict):
            raise RuntimeError("preview expected an object result for a mutating command")
        missing = {"before", "after", "result", "preview_mode", "persisted"} - value.keys()
        if missing:
            raise RuntimeError(f"preview response is missing field(s): {', '.join(sorted(missing))}")
        before = value["before"]
        after = value["after"]
        return {
            "command": command,
            "status": "ok" if result.exit_code == 0 else "failed",
            "before": before,
            "after": after,
            "result": value["result"],
            "readback": after,
            "undo": {
                "status": "ok",
                "mode": value["preview_mode"],
                "persisted": value["persisted"],
            },
            "artifacts": list(result.artifacts),
            "stderr": result.stderr_lines,
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
        "stderr": result.stderr_lines,
    }


def run(args: argparse.Namespace, *, root_parser: argparse.ArgumentParser):
    tokens = normalize_wrapped_command_tokens(args.command_tokens)
    if not tokens:
        raise CliUserError("preview requires a command to wrap")
    parsed = getattr(args, "_wrapped_args", None) or root_parser.parse_args(tokens)
    parsed_map = vars(parsed)
    if not parsed_map.get("allow_preview", False):
        raise CliUserError("command is not available in preview mode")
    child_outputs = [key for key in ("out", "out_file", "out_dir") if parsed_map.get(key) is not None]
    if child_outputs:
        rendered = ", ".join(f"--{key.replace('_', '-')}" for key in child_outputs)
        raise CliUserError(
            f"commands wrapped by preview cannot set their own output option(s): {rendered}; use preview --out"
        )
    if not args._batch_mode and args.out is None:
        raise CliUserError("preview requires `--out <path.json|path.jsonl>`")
    merge_parent_context(parsed, args)
    relative_path_base_dir = getattr(args, "_relative_path_base_dir", None)
    if args._batch_mode and relative_path_base_dir is not None:
        resolve_relative_paths(parsed, base_dir=Path(relative_path_base_dir))
    if args.out is not None:
        reject_output_aliases(
            Path(args.out),
            [
                (f"wrapped --{key.replace('_', '-')} input", value)
                for key, value in vars(parsed).items()
                if isinstance(value, Path) and key not in {"out", "out_file", "out_dir"}
            ],
            option_label="preview --out",
        )
    parsed._preview_wrapper = True
    parsed._batch_mode = args._batch_mode
    result = execute_parsed(parsed)
    payload = _preview_payload(command=" ".join(tokens), result=result, wrapped_args=parsed)
    return CommandResult(
        render_op="preview",
        value=payload,
        exit_code=result.exit_code,
        stderr_lines=list(result.stderr_lines),
        artifacts=list(result.artifacts) if args._batch_mode else [],
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(
        root_parser, subparsers, "preview", help_text="Run and roll back a command, emitting structured preview data"
    )
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = """examples:
  # Preview a prototype change; omit the leading `idac` from the wrapped command
  idac preview -c sample.i64 -o .idac/tmp/proto_preview.json function prototype set sub_401000 --decl-file proto.h

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
        allow_batch=True,
        allow_preview=False,
    )
