from __future__ import annotations

import argparse
import contextlib
import io
import json
import shlex
import time
from pathlib import Path
from typing import Any

from ..output import write_output_result
from ..transport import BackendError
from .argparse_utils import add_command, add_context_options, bind_root_handler
from .context import merge_parent_context
from .errors import CliUserError
from .execute import execute_parsed
from .path_resolution import resolve_relative_paths
from .renderers import TEXT_RENDERERS
from .result import CommandResult
from .serialize import emit_result, json_or_jsonl_from_path


class BatchParseError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _line_record(
    *,
    line: int,
    command: str,
    status: str,
    exit_code: int,
    stderr: str | None = None,
    result: Any = None,
    timing_ms: float,
    artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "line": line,
        "command": command,
        "status": status,
        "exit_code": exit_code,
        "timing_ms": round(timing_ms, 3),
        "artifacts": list(artifacts or []),
    }
    if stderr:
        payload["stderr"] = stderr
    if result is not None:
        payload["result"] = result
    return payload


def _serialize_child_if_needed(result, args) -> list[dict[str, Any]]:
    artifacts = list(result.artifacts)
    arg_map = vars(args)
    out_path = arg_map.get("out")
    if out_path is None:
        return artifacts
    artifacts.extend(emit_result(result, fmt=arg_map.get("format", "text"), out_path=out_path))
    return artifacts


def _fallback_child_failure(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, indent=2, sort_keys=True)
    except TypeError:
        return str(value)


def _render_child_failure(result: CommandResult) -> str | None:
    if result.stderr_lines:
        stderr_text = "\n".join(line for line in result.stderr_lines if line.strip()).strip()
        if stderr_text:
            return stderr_text
    renderer = TEXT_RENDERERS.get(result.render_op)
    if renderer is not None:
        try:
            rendered_text = renderer(result.value).strip()
            if rendered_text:
                return rendered_text
        except Exception as exc:
            fallback_text = (_fallback_child_failure(result.value) or "").strip()
            failure_prefix = f"(renderer failure while formatting {result.render_op}: {exc.__class__.__name__}: {exc})"
            return failure_prefix if not fallback_text else f"{failure_prefix}\n{fallback_text}"
    fallback_text = (_fallback_child_failure(result.value) or "").strip()
    return fallback_text or None


def _parse_batch_args(root_parser: argparse.ArgumentParser, argv: list[str]) -> argparse.Namespace:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            return root_parser.parse_args(argv)
    except SystemExit as exc:
        message = _captured_cli_message(stdout_buffer.getvalue(), stderr_buffer.getvalue(), fallback="parse failed")
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
        raise BatchParseError(message, exit_code=exit_code) from exc


def _execute_batch_args(parsed: argparse.Namespace, *, root_parser: argparse.ArgumentParser) -> CommandResult:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            return execute_parsed(parsed, root_parser=root_parser)
    except SystemExit as exc:
        message = _captured_cli_message(stdout_buffer.getvalue(), stderr_buffer.getvalue(), fallback="command exited")
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
        raise BatchParseError(message, exit_code=exit_code) from exc


def _captured_cli_message(*parts: str, fallback: str) -> str:
    message = "\n".join(part.strip() for part in parts if part.strip())
    return message or fallback


def _command_lines(batch_path: Path) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(batch_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append((line_number, stripped))
    return lines


def _argv_from_batch_line(stripped: str) -> list[str]:
    argv = shlex.split(stripped, comments=True, posix=True)
    if argv and argv[0] == "idac":
        argv = argv[1:]
    return argv


def _reject_mutating_batch_without_out(
    *,
    root_parser: argparse.ArgumentParser,
    command_lines: list[tuple[int, str]],
    out_path: Path | None,
) -> None:
    if out_path is not None:
        return
    for line_number, stripped in command_lines:
        try:
            argv = _argv_from_batch_line(stripped)
            if not argv:
                continue
            parsed = _parse_batch_args(root_parser, argv)
        except (BatchParseError, ValueError):
            continue
        if bool(vars(parsed).get("_mutating_command", False)):
            raise CliUserError(
                "mutating batch commands require `--out <path.json|path.jsonl>` so the ordered "
                f"result log is preserved before changes run; first mutating line is {line_number}: {stripped}"
            )


def failure_lines(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    rows = payload.get("results")
    if not isinstance(rows, list):
        return []
    lines: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("exit_code") == 0:
            continue
        lines.append(f"batch line {row.get('line', '?')}: {row.get('command', '<unknown>')}")
        message = str(row.get("stderr") or "").strip()
        if not message:
            message = "step failed"
        for item in message.splitlines():
            lines.append(f"  {item}")
    return lines


def run(args: argparse.Namespace, *, root_parser: argparse.ArgumentParser) -> CommandResult:
    rows: list[dict[str, Any]] = []
    batch_path = Path(args.batch_file)
    batch_dir = batch_path.parent.resolve(strict=False)
    command_lines = _command_lines(batch_path)
    _reject_mutating_batch_without_out(root_parser=root_parser, command_lines=command_lines, out_path=args.out)
    for line_number, stripped in command_lines:
        started = time.perf_counter()
        try:
            try:
                argv = _argv_from_batch_line(stripped)
            except ValueError as exc:
                raise BatchParseError(str(exc), exit_code=2) from exc
            if not argv:
                raise CliUserError("empty command")
            parsed = _parse_batch_args(root_parser, argv)
            parsed._raw_argv = list(argv)
            parsed_map = vars(parsed)
            if parsed_map.get("_hidden_command", False) or not parsed_map.get("allow_batch", True):
                raise CliUserError("command is not available in batch mode")
            merge_parent_context(parsed, args)
            resolve_relative_paths(parsed, base_dir=batch_dir)
            parsed._relative_path_base_dir = batch_dir
            parsed._batch_mode = True
            result = _execute_batch_args(parsed, root_parser=root_parser)
            artifacts = _serialize_child_if_needed(result, parsed)
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="ok" if result.exit_code == 0 else "failed",
                    exit_code=result.exit_code,
                    stderr=_render_child_failure(result) if result.exit_code != 0 else None,
                    result=result.value,
                    timing_ms=(time.perf_counter() - started) * 1000.0,
                    artifacts=artifacts,
                )
            )
            if result.exit_code != 0 and args.fail_fast:
                break
        except BatchParseError as exc:
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="failed",
                    exit_code=exc.exit_code,
                    stderr=str(exc),
                    timing_ms=(time.perf_counter() - started) * 1000.0,
                )
            )
            if args.fail_fast:
                break
        except (BackendError, CliUserError) as exc:
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="failed",
                    exit_code=1,
                    stderr=str(exc) or exc.__class__.__name__,
                    timing_ms=(time.perf_counter() - started) * 1000.0,
                )
            )
            if args.fail_fast:
                break

    payload = {
        "ok": all(row["exit_code"] == 0 for row in rows),
        "batch_file": str(batch_path),
        "commands_total": len(rows),
        "commands_succeeded": sum(1 for row in rows if row["exit_code"] == 0),
        "commands_failed": sum(1 for row in rows if row["exit_code"] != 0),
        "results": rows,
    }
    exit_code = 0 if payload["ok"] else 1
    fmt = json_or_jsonl_from_path(args.out, default="json")
    artifacts: list[dict[str, Any]] = []
    if args.out is not None:
        path = Path(args.out)
        value = rows if fmt == "jsonl" else payload
        output = write_output_result(value, fmt=fmt, out_path=path, stem="batch")
        if output.artifact is not None:
            artifacts.append(output.artifact)
    return CommandResult(
        render_op="batch",
        value=payload,
        exit_code=exit_code,
        stderr_lines=failure_lines(payload),
        artifacts=artifacts,
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(
        root_parser, subparsers, "batch", help_text="Apply one idac subcommand per line from a batch file"
    )
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = """batch file format:
  - one shell-like idac subcommand per line
  - omit the leading `idac`; a leading `idac` is also accepted
  - blank lines and lines starting with # are ignored
  - relative child paths such as --decl-file, --functions-file, and --out resolve from the batch file directory
  - preview lines are allowed, for example `preview function prototype set ...`

example recovery.idac:
  type declare --replace --decl-file recovered_types.h
  preview function prototype set sub_401000 --decl-file sub_401000.h
  function prototype set sub_401000 --decl-file sub_401000.h
  function locals update sub_401000 --local-id 'stack(16)@0x1000' --rename count
"""
    add_context_options(parser)
    parser.add_argument(
        "batch_file",
        type=Path,
        metavar="BATCH_FILE",
        help="Read one shell-like idac subcommand per line from this file",
    )
    parser.add_argument("-o", "--out", type=Path, help="Write ordered batch results to a JSON or JSONL file")
    parser.add_argument("--fail-fast", action="store_true", help="Stop after the first failing command")
    parser.set_defaults(
        run=bind_root_handler(root_parser, run),
        context_policy="wrapper",
        allow_batch=False,
        allow_preview=False,
        _mutating_command=False,
    )
