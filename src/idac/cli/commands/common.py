from __future__ import annotations

import argparse
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from ...operations import MUTATING_OPERATIONS
from ..argparse_utils import read_decl_or_type_text, read_decl_text_if_present
from ..errors import CliUserError
from ..result import CommandResult

_INFERRED_LOCAL_ID_RE = re.compile(
    # Stable local ids from `function locals list --json` encode storage plus a versioned slot identifier.
    r"^(?:stack\([^)]*\)|reg\([^)]*\)|regpair\([^)]*\)|unknown)@(?:0x[0-9a-fA-F]+|\d+)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OperationBinding:
    operation: str | None = None
    parameter_attrs: tuple[tuple[str, str], ...] = ()
    params_builder: Callable[[argparse.Namespace], dict[str, Any]] | None = None
    request_builder: Callable[[argparse.Namespace], tuple[str, dict[str, Any]]] | None = None

    def build_request(self, args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
        if self.request_builder is not None:
            if self.operation is not None or self.params_builder is not None or self.parameter_attrs:
                raise RuntimeError("dynamic operation binding has conflicting request metadata")
            return self.request_builder(args)
        if self.operation is None:
            raise RuntimeError("operation binding is missing an operation name")
        if self.params_builder is not None and self.parameter_attrs:
            raise RuntimeError(f"operation {self.operation} has conflicting parameter bindings")
        params = (
            self.params_builder(args)
            if self.params_builder is not None
            else {parameter: getattr(args, attribute) for parameter, attribute in self.parameter_attrs}
        )
        return self.operation, params


@dataclass(frozen=True)
class LocalCommandBinding:
    render_op: str
    command: Callable[..., Any]
    positional_attrs: tuple[str, ...] = ()
    keyword_attrs: tuple[tuple[str, str], ...] = ()


def bind_operation(parser: argparse.ArgumentParser, binding: OperationBinding) -> None:
    parser.set_defaults(
        _operation_binding=binding,
        _mutating_command=binding.operation in MUTATING_OPERATIONS if binding.operation is not None else False,
    )


def command_result(
    render_op: str,
    value: Any,
    *,
    exit_code: int = 0,
    stderr_lines: list[str] | None = None,
) -> CommandResult:
    return CommandResult(
        render_op=render_op,
        value=value,
        exit_code=exit_code,
        stderr_lines=list(stderr_lines or []),
    )


def send_op(
    args: argparse.Namespace,
    *,
    op: str,
    params: dict[str, Any],
    render_op: str | None = None,
    preview: bool | None = None,
) -> CommandResult:
    payload = dict(params)
    operation_mutates = op in MUTATING_OPERATIONS
    if bool(args._mutating_command) != operation_mutates:
        raise RuntimeError(f"CLI mutation metadata is inconsistent for operation {op}")
    preview_requested = bool(args._preview_wrapper and operation_mutates) if preview is None else preview
    session = getattr(args, "_nexus_session", None)
    if session is None:
        raise CliUserError(f"{args._selected_parser.prog} requires a Nexus context")
    value = session.execute_operation(
        op,
        payload,
        preview=preview_requested,
        operation_label=f"idac: {args._selected_parser.prog.removeprefix('idac ').strip()}",
    )
    return command_result(render_op or op, value)


def run_bound_operation(args: argparse.Namespace) -> CommandResult:
    binding = getattr(args, "_operation_binding", None)
    if not isinstance(binding, OperationBinding):
        raise RuntimeError("operation command is missing its parser binding")
    operation, params = binding.build_request(args)
    return send_op(args, op=operation, params=params)


def run_bound_local_command(args: argparse.Namespace) -> CommandResult:
    binding = getattr(args, "_local_command_binding", None)
    if not isinstance(binding, LocalCommandBinding):
        raise RuntimeError("local command is missing its parser binding")
    positional = [getattr(args, attribute) for attribute in binding.positional_attrs]
    keywords = {parameter: getattr(args, attribute) for parameter, attribute in binding.keyword_attrs}
    return command_result(binding.render_op, binding.command(*positional, **keywords))


def parse_alias_list(values: list[str] | None) -> list[dict[str, str]]:
    aliases: list[dict[str, str]] = []
    for value in values or []:
        text = str(value).strip()
        if "=" not in text:
            raise CliUserError(f"invalid alias `{text}`; expected OLD=NEW")
        source, destination = (part.strip() for part in text.split("=", 1))
        if not source or not destination:
            raise CliUserError(f"invalid alias `{text}`; expected OLD=NEW")
        aliases.append({"from": source, "to": destination})
    return aliases


def _parse_cli_int_text(value: Any, *, label: str, minimum: int | None = None) -> int:
    try:
        parsed = int(str(value).strip(), 0)
    except ValueError as exc:
        raise CliUserError(f"{label} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise CliUserError(f"{label} must be greater than or equal to {minimum}")
    return parsed


def parse_bookmark_slot(value: Any) -> int:
    return _parse_cli_int_text(value, label="bookmark slot", minimum=0)


def _infer_local_selector(token: str) -> tuple[str, Any]:
    text = str(token).strip()
    if re.fullmatch(r"-?\d+", text):
        return "index", _parse_cli_int_text(text, label="local index", minimum=0)
    if _INFERRED_LOCAL_ID_RE.match(text):
        return "local_id", text
    return "old_name", text


def _local_selector_params(
    args: argparse.Namespace,
    *,
    name_param: Literal["old_name", "local_name"],
) -> dict[str, Any]:
    if args.local_id and args.index is not None:
        raise CliUserError("--local-id and --index are mutually exclusive")
    selector_text = str(args.selector or "").strip()
    if (args.local_id or args.index is not None) and selector_text:
        raise CliUserError("do not combine a positional selector with --local-id or --index")
    if args.local_id:
        return {"local_id": str(args.local_id)}
    if args.index is not None:
        return {"index": _parse_cli_int_text(args.index, label="local index", minimum=0)}
    if not selector_text:
        raise CliUserError("local selector is required via selector, --local-id, or --index")
    selector_kind, selector_value = _infer_local_selector(selector_text)
    if selector_kind == "old_name":
        return {name_param: str(selector_value)}
    if selector_kind == "local_id":
        return {"local_id": str(selector_value)}
    return {"index": int(selector_value)}


def local_rename_params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {"identifier": str(args.function), "new_name": str(args.new_name)}
    params.update(_local_selector_params(args, name_param="old_name"))
    return params


def local_retype_params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {"identifier": str(args.function), "decl": read_decl_or_type_text(args)}
    params.update(_local_selector_params(args, name_param="local_name"))
    return params


def local_update_params(args: argparse.Namespace) -> dict[str, Any]:
    new_name = str(args.rename or "").strip() or None
    decl = read_decl_text_if_present(args)
    if new_name is None and decl is None:
        raise CliUserError("at least one of --rename or declaration input is required")
    params: dict[str, Any] = {"identifier": str(args.function)}
    params.update(_local_selector_params(args, name_param="local_name"))
    if new_name is not None:
        params["new_name"] = new_name
    if decl is not None:
        params["decl"] = decl
    return params
