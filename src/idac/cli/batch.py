from __future__ import annotations

import argparse
import contextlib
import io
import json
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..nexus import NexusSessionError
from ..output import write_output_result
from .argparse_utils import add_command, add_context_options, bind_root_handler
from .context import merge_parent_context, require_timeout_if_needed
from .errors import CliUserError
from .execute import execute_parsed, reject_unsupported_forwarded_context
from .path_resolution import reject_output_aliases, resolve_relative_paths
from .preview import normalize_wrapped_command_tokens
from .renderers import TEXT_RENDERERS
from .result import CommandResult
from .serialize import emit_result, json_or_jsonl_from_path

_LOCAL_SELECTOR_OPERATIONS = frozenset({"local_rename", "local_retype", "local_update"})
_LOCAL_LAYOUT_INVALIDATORS = frozenset({"proto_set", "reanalyze", "type_declare"})


class BatchParseError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class PreparedBatchLine:
    line_number: int
    command: str
    parsed: argparse.Namespace | BatchParseError | CliUserError
    wrapped: argparse.Namespace | BatchParseError | None = None


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
        output = (stdout_buffer.getvalue(), stderr_buffer.getvalue())
        message = "\n".join(part.strip() for part in output if part.strip()) or "parse failed"
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
        raise BatchParseError(message, exit_code=exit_code) from exc


def _reject_handlerless_command(parsed: argparse.Namespace) -> None:
    if getattr(parsed, "run", None) is not None:
        return
    selected_parser = parsed._selected_parser
    message = selected_parser.format_help().strip() or "missing subcommand"
    raise BatchParseError(message, exit_code=2)


def _execute_batch_args(parsed: argparse.Namespace) -> CommandResult:
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            return execute_parsed(parsed)
    except SystemExit as exc:
        output = (stdout_buffer.getvalue(), stderr_buffer.getvalue())
        message = "\n".join(part.strip() for part in output if part.strip()) or "command exited"
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
        raise BatchParseError(message, exit_code=exit_code) from exc


def _prepare_batch_lines(root_parser: argparse.ArgumentParser, batch_path: Path) -> list[PreparedBatchLine]:
    prepared: list[PreparedBatchLine] = []
    for line_number, raw_line in enumerate(batch_path.read_text(encoding="utf-8").splitlines(), start=1):
        command = raw_line.strip()
        if not command or command.startswith("#"):
            continue
        try:
            argv = shlex.split(command, comments=True, posix=True)
        except ValueError as exc:
            prepared.append(PreparedBatchLine(line_number, command, BatchParseError(str(exc), exit_code=2)))
            continue
        if argv[:1] == ["idac"]:
            argv = argv[1:]
        if not argv:
            prepared.append(PreparedBatchLine(line_number, command, CliUserError("empty command")))
            continue
        try:
            parsed = _parse_batch_args(root_parser, argv)
        except BatchParseError as exc:
            prepared.append(PreparedBatchLine(line_number, command, exc))
            continue

        line = PreparedBatchLine(line_number, command, parsed)
        if vars(parsed).get("command") == "preview":
            wrapped_tokens = normalize_wrapped_command_tokens(vars(parsed).get("command_tokens"))
            if wrapped_tokens:
                try:
                    line.wrapped = _parse_batch_args(root_parser, wrapped_tokens)
                    parsed._wrapped_args = line.wrapped
                except BatchParseError as exc:
                    line.wrapped = exc
        prepared.append(line)
    return prepared


def _reject_mutating_batch_without_out(
    *,
    command_lines: list[PreparedBatchLine],
    out_path: Path | None,
) -> None:
    if out_path is not None:
        return
    for line in command_lines:
        if not isinstance(line.parsed, argparse.Namespace):
            continue
        if bool(vars(line.parsed).get("_mutating_command", False)):
            raise CliUserError(
                "mutating batch commands require `--out <path.json|path.jsonl>` so the ordered "
                f"result log is preserved before changes run; first mutating line is "
                f"{line.line_number}: {line.command}"
            )


def _prepare_batch_command(line: PreparedBatchLine, parent_args: argparse.Namespace) -> argparse.Namespace:
    if isinstance(line.parsed, BatchParseError | CliUserError):
        raise line.parsed
    parsed = line.parsed
    parsed_map = vars(parsed)
    if not parsed_map.get("allow_batch", False):
        raise CliUserError("command is not available in batch mode")
    _reject_handlerless_command(parsed)
    if bool(parsed_map.get("_mutating_command", False)) and parsed_map.get("out") is not None:
        raise CliUserError(
            "mutating batch child commands cannot set --out; use the batch wrapper --out for mutation logging"
        )
    if parsed_map.get("command") == "preview":
        if isinstance(line.wrapped, BatchParseError):
            raise line.wrapped
        wrapped_map = vars(line.wrapped) if isinstance(line.wrapped, argparse.Namespace) else {}
        if bool(wrapped_map.get("_mutating_command", False)) and wrapped_map.get("out") is not None:
            raise CliUserError(
                "mutating commands wrapped by batch preview cannot set --out; "
                "put --out on preview before the wrapped command"
            )
    merge_parent_context(parsed, parent_args)

    batch_path = Path(parent_args.batch_file)
    resolve_relative_paths(parsed, base_dir=batch_path.parent.resolve(strict=False))
    context_value = parsed_map.get("context")
    protected_outputs = [
        ("batch file", batch_path),
        ("Nexus context", Path(context_value) if context_value is not None else None),
        ("batch wrapper output", parent_args.out),
    ]
    for output_key in ("out", "out_file"):
        child_output = parsed_map.get(output_key)
        if child_output is not None:
            reject_output_aliases(
                Path(child_output),
                protected_outputs,
                option_label=f"child --{output_key.replace('_', '-')}",
            )
    return parsed


def _batch_input_paths(
    command_lines: list[PreparedBatchLine],
    *,
    batch_dir: Path,
) -> list[tuple[str, Path | None]]:
    """Collect child input files before the wrapper journal can overwrite them."""

    protected: list[tuple[str, Path | None]] = []
    for line in command_lines:
        if not isinstance(line.parsed, argparse.Namespace):
            continue
        parsed_commands = [line.parsed]
        if isinstance(line.wrapped, argparse.Namespace):
            parsed_commands.append(line.wrapped)
        for command_args in parsed_commands:
            resolve_relative_paths(command_args, base_dir=batch_dir)
            for key in command_args._input_path_attrs:
                value = getattr(command_args, key, None)
                if isinstance(value, Path):
                    protected.append((f"line {line.line_number} --{key.replace('_', '-')} input", value))
    return protected


def _lint_missing_input_paths(parsed: argparse.Namespace) -> list[str]:
    missing: list[str] = []
    for key in parsed._input_path_attrs:
        value = getattr(parsed, key, None)
        if isinstance(value, Path) and not value.exists():
            missing.append(f"{key} path does not exist: {value}")
    return missing


def _lint_local_selector_warning(parsed: argparse.Namespace, *, after_type_or_reanalysis: bool) -> str | None:
    parsed_map = vars(parsed)
    binding = parsed_map.get("_operation_binding")
    if getattr(binding, "operation", None) not in _LOCAL_SELECTOR_OPERATIONS:
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


def _lint_command_local_errors(parsed: argparse.Namespace) -> list[str]:
    try:
        binding = getattr(parsed, "_operation_binding", None)
        build_request = getattr(binding, "build_request", None)
        if build_request is not None:
            build_request(parsed)
        validator = parsed._request_validator
        if validator is not None:
            validator(parsed)
    except CliUserError as exc:
        return [str(exc) or exc.__class__.__name__]
    return []


def _lint_preview_wrapped_command(
    *,
    line: PreparedBatchLine,
    batch_dir: Path,
) -> tuple[argparse.Namespace, list[str]]:
    if isinstance(line.wrapped, BatchParseError):
        raise line.wrapped
    if not isinstance(line.wrapped, argparse.Namespace):
        raise CliUserError("preview requires a command to wrap")

    assert isinstance(line.parsed, argparse.Namespace)
    wrapped = line.wrapped
    wrapped_map = vars(wrapped)
    if not wrapped_map.get("allow_preview", False):
        raise CliUserError("command is not available in preview mode")
    _reject_handlerless_command(wrapped)

    merge_parent_context(wrapped, line.parsed)
    reject_unsupported_forwarded_context(wrapped._selected_parser, wrapped)
    require_timeout_if_needed(wrapped)
    resolve_relative_paths(wrapped, base_dir=batch_dir)
    line_errors = _lint_missing_input_paths(wrapped)
    if not line_errors:
        line_errors.extend(_lint_command_local_errors(wrapped))
    return wrapped, line_errors


def _lint_batch(
    *,
    command_lines: list[PreparedBatchLine],
    batch_path: Path,
    out_path: Path | None,
    parent_args: argparse.Namespace,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    batch_dir = batch_path.parent.resolve(strict=False)
    after_type_or_reanalysis = False
    for line in command_lines:
        line_number = line.line_number
        stripped = line.command
        try:
            parsed = _prepare_batch_command(line, parent_args)
            parsed_map = vars(parsed)
            reject_unsupported_forwarded_context(parsed._selected_parser, parsed)
            if parsed_map.get("command") == "preview":
                lint_target, line_errors = _lint_preview_wrapped_command(
                    line=line,
                    batch_dir=batch_dir,
                )
            else:
                lint_target = parsed
                require_timeout_if_needed(parsed)
                line_errors = _lint_missing_input_paths(parsed)
                if bool(parsed_map.get("_mutating_command", False)) and out_path is None:
                    line_errors.append("mutating batch command requires wrapper --out")
                if not line_errors:
                    line_errors.extend(_lint_command_local_errors(parsed))
            warning = _lint_local_selector_warning(lint_target, after_type_or_reanalysis=after_type_or_reanalysis)
            if warning is not None:
                warnings.append({"line": line_number, "command": stripped, "message": warning})
            binding = parsed_map.get("_operation_binding")
            if getattr(binding, "operation", None) in _LOCAL_LAYOUT_INVALIDATORS:
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
        except (BatchParseError, CliUserError) as exc:
            message = str(exc) or exc.__class__.__name__
            errors.append({"line": line_number, "command": stripped, "message": message})
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="failed",
                    exit_code=int(getattr(exc, "exit_code", 1)),
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
    lines: list[str] = []
    finalization = payload.get("finalization")
    if isinstance(finalization, dict) and finalization.get("status") in {"failed", "interrupted"}:
        message = str(finalization.get("error") or "database persistence or session close failed").strip()
        if finalization.get("status") == "interrupted":
            lines.append(f"batch interrupted: {message}")
        else:
            lines.append(f"batch finalization failed: {message}")
        notes = finalization.get("notes")
        if isinstance(notes, list):
            lines.extend(f"batch finalization detail: {note}" for note in notes if str(note).strip())

        for key, fallback, failure_prefix, detail_prefix in (
            (
                "session_finalization",
                "database persistence or session close failed",
                "batch session finalization also failed",
                "batch session finalization detail",
            ),
            (
                "output_finalization",
                "writing the terminal batch result failed",
                "writing the terminal batch result also failed",
                None,
            ),
            (
                "checkpoint_finalization",
                "writing a batch checkpoint failed",
                "writing the batch checkpoint also failed",
                None,
            ),
        ):
            detail = finalization.get(key)
            if not isinstance(detail, dict) or detail.get("status") != "failed":
                continue
            message = str(detail.get("error") or fallback).strip()
            lines.append(f"{failure_prefix}: {message}")
            notes = detail.get("notes")
            if detail_prefix is not None and isinstance(notes, list):
                lines.extend(f"{detail_prefix}: {note}" for note in notes if str(note).strip())

    rows = payload.get("results")
    if not isinstance(rows, list):
        return lines
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


def _batch_payload(
    rows: list[dict[str, Any]],
    *,
    batch_path: Path,
    finalization: dict[str, Any],
) -> dict[str, Any]:
    commands_ok = all(row["exit_code"] == 0 for row in rows)
    return {
        "ok": commands_ok and finalization.get("status") == "ok",
        "batch_file": str(batch_path),
        "commands_total": len(rows),
        "commands_succeeded": sum(1 for row in rows if row["exit_code"] == 0),
        "commands_failed": sum(1 for row in rows if row["exit_code"] != 0),
        "finalization": finalization,
        "results": rows,
    }


def _write_batch_payload(
    payload: dict[str, Any],
    *,
    out_path: Path | None,
) -> list[dict[str, Any]]:
    if out_path is None:
        return []
    fmt = json_or_jsonl_from_path(out_path)
    if fmt == "jsonl":
        value = list(payload["results"])
        value.append(
            {
                "record_type": "batch_finalization",
                **payload["finalization"],
                "ok": payload["ok"],
            }
        )
    else:
        value = payload
    output = write_output_result(value, fmt=fmt, out_path=Path(out_path), stem="batch")
    return [] if output.artifact is None else [output.artifact]


def run(args: argparse.Namespace, *, root_parser: argparse.ArgumentParser) -> CommandResult:
    rows: list[dict[str, Any]] = []
    batch_path = Path(args.batch_file)
    batch_dir = batch_path.parent.resolve(strict=False)
    command_lines = _prepare_batch_lines(root_parser, batch_path)
    context_value = vars(args).get("context")
    reject_output_aliases(
        args.out,
        [
            ("batch file", batch_path),
            ("Nexus context", Path(context_value) if context_value is not None else None),
            *_batch_input_paths(command_lines, batch_dir=batch_dir),
        ],
        option_label="batch --out",
    )
    if args.lint:
        payload = _lint_batch(
            command_lines=command_lines,
            batch_path=batch_path,
            out_path=args.out,
            parent_args=args,
        )
        artifacts: list[dict[str, Any]] = []
        if args.out is not None:
            fmt = json_or_jsonl_from_path(args.out)
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
    _reject_mutating_batch_without_out(command_lines=command_lines, out_path=args.out)
    terminal_error: BaseException | None = None
    terminal_stage: str | None = None
    checkpoint_error: BaseException | None = None
    initial_checkpoint = _batch_payload(
        rows,
        batch_path=batch_path,
        finalization={"status": "pending"},
    )
    try:
        _write_batch_payload(initial_checkpoint, out_path=args.out)
    except (Exception, KeyboardInterrupt) as exc:
        terminal_error = exc
        terminal_stage = "batch_initialization"
        command_lines = []

    for line in command_lines:
        line_number = line.line_number
        stripped = line.command
        started = time.perf_counter()
        rows_before = len(rows)
        try:
            parsed = _prepare_batch_command(line, args)
            parsed._relative_path_base_dir = batch_dir
            parsed._batch_mode = True
            result = _execute_batch_args(parsed)
            record = _line_record(
                line=line_number,
                command=stripped,
                status="ok" if result.exit_code == 0 else "failed",
                exit_code=result.exit_code,
                stderr=_render_child_failure(result) if result.exit_code != 0 else None,
                result=result.value,
                timing_ms=(time.perf_counter() - started) * 1000.0,
                artifacts=list(result.artifacts),
            )
            # Record the row before serializing a read-only child's own --out
            # file, so a write failure cannot erase the fact that it ran.
            rows.append(record)
            try:
                record["artifacts"] = _serialize_child_if_needed(result, parsed)
            except OSError as exc:
                record["status"] = "failed"
                if record["exit_code"] == 0:
                    record["exit_code"] = 1
                output_message = f"command ran but writing its --out file failed: {exc}"
                existing_message = str(record.get("stderr") or "").strip()
                record["stderr"] = f"{existing_message}\n{output_message}" if existing_message else output_message
            except KeyboardInterrupt as exc:
                terminal_error = exc
                terminal_stage = "child_output"
                record["status"] = "interrupted"
                record["exit_code"] = 130
                output_message = "command ran but writing its --out file was interrupted"
                existing_message = str(record.get("stderr") or "").strip()
                record["stderr"] = f"{existing_message}\n{output_message}" if existing_message else output_message
            except Exception as exc:
                terminal_error = exc
                terminal_stage = "child_output"
                record["status"] = "failed"
                if record["exit_code"] == 0:
                    record["exit_code"] = 1
                detail = str(exc).strip() or exc.__class__.__name__
                output_message = f"command ran but rendering or writing its --out file failed: {detail}"
                existing_message = str(record.get("stderr") or "").strip()
                record["stderr"] = f"{existing_message}\n{output_message}" if existing_message else output_message
            if record["exit_code"] != 0 and args.fail_fast:
                break
        except (BatchParseError, NexusSessionError, CliUserError) as exc:
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="failed",
                    exit_code=int(getattr(exc, "exit_code", 1)),
                    stderr=str(exc) or exc.__class__.__name__,
                    timing_ms=(time.perf_counter() - started) * 1000.0,
                )
            )
            if args.fail_fast:
                break
        except KeyboardInterrupt as exc:
            terminal_error = exc
            terminal_stage = "batch_execution"
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="interrupted",
                    exit_code=130,
                    stderr="interrupted by user",
                    timing_ms=(time.perf_counter() - started) * 1000.0,
                )
            )
        except Exception as exc:
            terminal_error = exc
            terminal_stage = "batch_execution"
            message = str(exc).strip() or exc.__class__.__name__
            rows.append(
                _line_record(
                    line=line_number,
                    command=stripped,
                    status="failed",
                    exit_code=1,
                    stderr=f"unexpected {exc.__class__.__name__}: {message}",
                    timing_ms=(time.perf_counter() - started) * 1000.0,
                )
            )
        finally:
            # Checkpoint after every line so an interrupted mutating batch leaves
            # an ordered record of which commands ran. Stop if the journal can no
            # longer be updated; continuing would create unlogged mutations.
            if len(rows) != rows_before:
                try:
                    checkpoint = _batch_payload(
                        rows,
                        batch_path=batch_path,
                        finalization={"status": "pending"},
                    )
                    _write_batch_payload(checkpoint, out_path=args.out)
                except (Exception, KeyboardInterrupt) as exc:
                    checkpoint_error = exc
                    if terminal_error is None:
                        terminal_error = exc
                        terminal_stage = "batch_checkpoint"
        if terminal_error is not None:
            break

    close_error: BaseException | None = None
    session = getattr(args, "_nexus_session", None)
    if session is not None:
        try:
            session.close()
        except BaseException as exc:
            close_error = exc
            if isinstance(exc, KeyboardInterrupt) and terminal_error is None:
                terminal_error = exc
                terminal_stage = "database_save_or_session_close"

    close_failure: dict[str, Any] | None = None
    if close_error is not None:
        close_failure = {
            "status": "failed",
            "stage": "database_save_or_session_close",
            "persistence": "unconfirmed",
            "error_kind": (
                close_error.kind if isinstance(close_error, NexusSessionError) else close_error.__class__.__name__
            ),
            "error": str(close_error).strip() or close_error.__class__.__name__,
        }
        raw_notes = getattr(close_error, "__notes__", None)
        if isinstance(raw_notes, list):
            notes = [str(note).strip() for note in raw_notes if str(note).strip()]
            if notes:
                close_failure["notes"] = notes

    finalization: dict[str, Any]
    if terminal_error is not None:
        interrupted = isinstance(terminal_error, KeyboardInterrupt)
        error_message = str(terminal_error).strip()
        if not error_message:
            error_message = "interrupted by user" if interrupted else terminal_error.__class__.__name__
        finalization = {
            "status": "interrupted" if interrupted else "failed",
            "stage": terminal_stage or "batch_execution",
            "error_kind": "keyboard_interrupt" if interrupted else terminal_error.__class__.__name__,
            "error": error_message,
            "session_finalization": {"status": "ok"},
        }
        if close_failure is not None:
            finalization["persistence"] = "unconfirmed"
            finalization["session_finalization"] = close_failure
    elif close_failure is not None:
        finalization = close_failure
    else:
        finalization = {"status": "ok"}

    if checkpoint_error is not None and checkpoint_error is not terminal_error:
        finalization["checkpoint_finalization"] = {
            "status": "failed",
            "stage": "batch_checkpoint",
            "error_kind": checkpoint_error.__class__.__name__,
            "error": str(checkpoint_error).strip() or checkpoint_error.__class__.__name__,
        }

    payload = _batch_payload(rows, batch_path=batch_path, finalization=finalization)
    artifacts: list[dict[str, Any]] = []
    try:
        artifacts = _write_batch_payload(payload, out_path=args.out)
    except (Exception, KeyboardInterrupt) as exc:
        output_failure = {
            "status": "failed",
            "stage": "batch_output",
            "error_kind": "output_write_failed",
            "exception_type": exc.__class__.__name__,
            "error": str(exc) or exc.__class__.__name__,
        }
        if isinstance(exc, KeyboardInterrupt) and terminal_error is None:
            terminal_error = exc
            terminal_stage = "batch_output"
            prior_finalization = finalization
            finalization = {
                "status": "interrupted",
                "stage": "batch_output",
                "error_kind": "keyboard_interrupt",
                "error": "interrupted by user",
                "session_finalization": (
                    {"status": "ok"} if prior_finalization["status"] == "ok" else prior_finalization
                ),
            }
        elif finalization["status"] == "ok":
            finalization = {
                "status": "failed",
                "stage": "batch_output",
                "error_kind": "output_write_failed",
                "error": output_failure["error"],
                "session_finalization": {"status": "ok"},
            }
        else:
            finalization["output_finalization"] = output_failure
        payload = _batch_payload(rows, batch_path=batch_path, finalization=finalization)

    exit_code = 130 if isinstance(terminal_error, KeyboardInterrupt) else (0 if payload["ok"] else 1)
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
  - mutating children cannot set --out; use the batch wrapper artifact for mutation logging
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
        allow_batch=False,
        allow_preview=False,
    )
