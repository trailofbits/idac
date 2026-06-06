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
from .context import merge_parent_context, require_timeout_if_needed
from .errors import CliUserError
from .execute import execute_parsed, reject_unsupported_forwarded_context
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


def _reject_handlerless_command(parsed: argparse.Namespace) -> None:
    if getattr(parsed, "run", None) is not None:
        return
    selected_parser = parsed._selected_parser
    message = selected_parser.format_help().strip() or "missing subcommand"
    raise BatchParseError(message, exit_code=2)


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


def _lint_missing_input_paths(parsed: argparse.Namespace) -> list[str]:
    missing: list[str] = []
    output_keys = {"out", "out_file", "out_dir"}
    for key, value in vars(parsed).items():
        if key in output_keys or not isinstance(value, Path):
            continue
        if not value.exists():
            missing.append(f"{key} path does not exist: {value}")
    return missing


def _lint_local_selector_warning(parsed: argparse.Namespace, *, after_type_or_reanalysis: bool) -> str | None:
    parsed_map = vars(parsed)
    if parsed_map.get("function_command") != "locals":
        return None
    if parsed_map.get("locals_command") not in {"rename", "retype", "update"}:
        return None
    if parsed_map.get("local_id") or parsed_map.get("index") is not None:
        return None
    selector = str(parsed_map.get("selector") or "").strip()
    if not selector:
        return None
    if selector.isdigit() or "@" in selector:
        return None
    if after_type_or_reanalysis:
        return "name-only local selector after type/prototype/reanalysis work; prefer --local-id or --index"
    return "name-only local selector; prefer --local-id or --index for batch updates"


def _lint_changes_local_layout(parsed: argparse.Namespace) -> bool:
    parsed_map = vars(parsed)
    if parsed_map.get("misc_command") == "reanalyze":
        return True
    if parsed_map.get("type_command") == "declare":
        return True
    return parsed_map.get("function_command") == "prototype" and parsed_map.get("prototype_command") == "set"


def _lint_command_local_errors(parsed: argparse.Namespace) -> list[str]:
    parsed_map = vars(parsed)
    try:
        if parsed_map.get("command") == "disasm":
            from .commands import top_level

            top_level.disasm_request(parsed)
        elif parsed_map.get("type_command") == "list":
            from .commands import type_commands

            type_commands._type_list_guard(parsed)
        elif parsed_map.get("function_command") == "locals":
            from .commands import function as function_commands
            from .commands.common import local_rename_params, local_retype_params, local_update_params

            locals_command = parsed_map.get("locals_command")
            if locals_command == "rename":
                local_rename_params(parsed)
            elif locals_command == "retype":
                local_retype_params(parsed)
            elif locals_command == "update":
                local_update_params(parsed)
            elif locals_command == "apply":
                function_commands._locals_apply_plan_params(parsed)
        elif parsed_map.get("function_command") == "prototype":
            from .commands import function as function_commands

            if parsed_map.get("prototype_command") == "set":
                function_commands._prototype_set_params(parsed)
    except CliUserError as exc:
        return [str(exc) or exc.__class__.__name__]
    return []


def _lint_preview_wrapped_command(
    *,
    root_parser: argparse.ArgumentParser,
    preview_args: argparse.Namespace,
    batch_dir: Path,
) -> tuple[argparse.Namespace, list[str]]:
    tokens = list(getattr(preview_args, "command_tokens", None) or [])
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    if not tokens:
        raise CliUserError("preview requires a command to wrap")

    wrapped = _parse_batch_args(root_parser, tokens)
    wrapped_map = vars(wrapped)
    if wrapped_map.get("_hidden_command", False) or not wrapped_map.get("allow_preview", True):
        raise CliUserError("command is not available in preview mode")
    if wrapped_map.get("command") == "preview":
        raise CliUserError("nested preview is not supported")
    _reject_handlerless_command(wrapped)

    merge_parent_context(wrapped, preview_args)
    reject_unsupported_forwarded_context(wrapped._selected_parser, wrapped)
    require_timeout_if_needed(wrapped)
    resolve_relative_paths(wrapped, base_dir=batch_dir)
    line_errors = _lint_missing_input_paths(wrapped)
    if not line_errors:
        line_errors.extend(_lint_command_local_errors(wrapped))
    return wrapped, line_errors


def _lint_batch(
    *,
    root_parser: argparse.ArgumentParser,
    batch_path: Path,
    out_path: Path | None,
    parent_args: argparse.Namespace,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    batch_dir = batch_path.parent.resolve(strict=False)
    after_type_or_reanalysis = False
    for line_number, stripped in _command_lines(batch_path):
        try:
            try:
                argv = _argv_from_batch_line(stripped)
            except ValueError as exc:
                raise BatchParseError(str(exc), exit_code=2) from exc
            if not argv:
                raise CliUserError("empty command")
            parsed = _parse_batch_args(root_parser, argv)
            parsed_map = vars(parsed)
            if parsed_map.get("_hidden_command", False) or not parsed_map.get("allow_batch", True):
                raise CliUserError("command is not available in batch mode")
            _reject_handlerless_command(parsed)
            merge_parent_context(parsed, parent_args)
            reject_unsupported_forwarded_context(parsed._selected_parser, parsed)
            if parsed_map.get("command") == "preview":
                lint_target, line_errors = _lint_preview_wrapped_command(
                    root_parser=root_parser,
                    preview_args=parsed,
                    batch_dir=batch_dir,
                )
            else:
                lint_target = parsed
                require_timeout_if_needed(parsed)
                resolve_relative_paths(parsed, base_dir=batch_dir)
                line_errors = _lint_missing_input_paths(parsed)
                if bool(parsed_map.get("_mutating_command", False)) and out_path is None:
                    line_errors.append("mutating batch command requires wrapper --out")
                if not line_errors:
                    line_errors.extend(_lint_command_local_errors(parsed))
            warning = _lint_local_selector_warning(lint_target, after_type_or_reanalysis=after_type_or_reanalysis)
            if warning is not None:
                warnings.append({"line": line_number, "command": stripped, "message": warning})
            if parsed_map.get("command") != "preview" and _lint_changes_local_layout(parsed):
                after_type_or_reanalysis = True
            if line_errors:
                for message in line_errors:
                    errors.append({"line": line_number, "command": stripped, "message": message})
                rows.append(
                    _line_record(
                        line=line_number,
                        command=stripped,
                        status="failed",
                        exit_code=1,
                        stderr="; ".join(line_errors),
                        timing_ms=0.0,
                    )
                )
                continue
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="ok",
                    exit_code=0,
                    result={"lint": "ok"},
                    timing_ms=0.0,
                )
            )
        except BatchParseError as exc:
            message = str(exc)
            errors.append({"line": line_number, "command": stripped, "message": message})
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="failed",
                    exit_code=exc.exit_code,
                    stderr=message,
                    timing_ms=0.0,
                )
            )
        except CliUserError as exc:
            message = str(exc) or exc.__class__.__name__
            errors.append({"line": line_number, "command": stripped, "message": message})
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="failed",
                    exit_code=1,
                    stderr=message,
                    timing_ms=0.0,
                )
            )
    return {
        "ok": not errors,
        "mode": "lint",
        "batch_file": str(batch_path),
        "commands_total": len(rows),
        "commands_linted": sum(1 for row in rows if row["exit_code"] == 0),
        "errors_total": len(errors),
        "warnings_total": len(warnings),
        "errors": errors,
        "warnings": warnings,
        "results": rows,
    }


def failure_lines(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    lint_errors = payload.get("errors")
    if isinstance(lint_errors, list) and lint_errors:
        lines: list[str] = []
        for item in lint_errors:
            if not isinstance(item, dict):
                continue
            lines.append(f"batch line {item.get('line', '?')}: {item.get('command', '<unknown>')}")
            lines.append(f"  {item.get('message', 'lint failed')}")
        return lines
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
    if args.lint:
        payload = _lint_batch(root_parser=root_parser, batch_path=batch_path, out_path=args.out, parent_args=args)
        artifacts: list[dict[str, Any]] = []
        if args.out is not None:
            fmt = json_or_jsonl_from_path(args.out, default="json")
            path = Path(args.out)
            value = payload["results"] if fmt == "jsonl" else payload
            output = write_output_result(value, fmt=fmt, out_path=path, stem="batch")
            if output.artifact is not None:
                artifacts.append(output.artifact)
        return CommandResult(
            render_op="batch",
            value=payload,
            exit_code=0 if payload["ok"] else 1,
            stderr_lines=failure_lines(payload),
            artifacts=artifacts,
        )
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
    parser.add_argument("--lint", action="store_true", help="Parse and validate batch commands without executing them")
    parser.set_defaults(
        run=bind_root_handler(root_parser, run),
        context_policy="wrapper",
        allow_batch=False,
        allow_preview=False,
        _mutating_command=False,
    )
