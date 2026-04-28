from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from typing import Any, Literal

from ...ops.helpers.params import parse_aliases, parse_int_text
from ...transport import send_request
from ...transport.schema import RequestEnvelope
from ..argparse_utils import read_decl_or_type_text, read_decl_text_if_present
from ..errors import CliUserError
from ..result import CommandResult

_INFERRED_LOCAL_ID_RE = re.compile(
    # Stable local ids from `function locals list --json` encode storage plus a versioned slot identifier.
    r"^(?:stack\([^)]*\)|reg\([^)]*\)|regpair\([^)]*\)|unknown)@(?:0x[0-9a-fA-F]+|\d+)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LocalSelector:
    param_name: Literal["old_name", "local_name", "local_id", "index"]
    value: str | int

    def apply(self, params: dict[str, Any]) -> None:
        params[self.param_name] = self.value


@dataclass(frozen=True)
class LocalRenameRequest:
    identifier: str
    selector: LocalSelector
    new_name: str

    def to_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {"identifier": self.identifier, "new_name": self.new_name}
        self.selector.apply(params)
        return params


@dataclass(frozen=True)
class LocalRetypeRequest:
    identifier: str
    selector: LocalSelector
    decl: str

    def to_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {"identifier": self.identifier, "decl": self.decl}
        self.selector.apply(params)
        return params


@dataclass(frozen=True)
class LocalUpdateRequest:
    identifier: str
    selector: LocalSelector
    new_name: str | None
    decl: str | None

    def to_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {"identifier": self.identifier}
        self.selector.apply(params)
        if self.new_name is not None:
            params["new_name"] = self.new_name
        if self.decl is not None:
            params["decl"] = self.decl
        return params

    def has_changes(self) -> bool:
        return self.new_name is not None or self.decl is not None


def command_result(
    render_op: str,
    value: Any,
    *,
    exit_code: int = 0,
    warnings: list[str] | None = None,
    stderr_lines: list[str] | None = None,
) -> CommandResult:
    return CommandResult(
        render_op=render_op,
        value=value,
        exit_code=exit_code,
        warnings=list(warnings or []),
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
    preview_requested = bool(args._preview_wrapper and args._mutating_command) if preview is None else preview
    if preview_requested:
        payload["preview"] = True
    response = send_request(
        RequestEnvelope(
            op=op,
            params=payload,
            backend=args.backend,
            target=args.target,
            database=args.database,
            timeout=getattr(args, "timeout", None),
        )
    )
    if not response.get("ok"):
        raise CliUserError(str(response.get("error") or "request failed"))
    warnings = [str(item) for item in (response.get("warnings") or []) if str(item)]
    return command_result(render_op or op, response.get("result"), warnings=warnings)


def parse_alias_list(values: list[str] | None) -> list[dict[str, str]]:
    try:
        return parse_aliases(values or [])
    except ValueError as exc:
        raise CliUserError(str(exc)) from exc


def _parse_cli_int_text(value: Any, *, label: str, minimum: int | None = None) -> int:
    try:
        return parse_int_text(value, label=label, minimum=minimum)
    except ValueError as exc:
        raise CliUserError(str(exc)) from exc


def parse_bookmark_slot(value: Any) -> int:
    return _parse_cli_int_text(value, label="bookmark slot", minimum=0)


def _looks_like_local_id_selector(token: str) -> bool:
    return bool(_INFERRED_LOCAL_ID_RE.match(token.strip()))


def _infer_local_selector(token: str) -> tuple[str, Any]:
    text = str(token).strip()
    if re.fullmatch(r"-?\d+", text):
        return "index", _parse_cli_int_text(text, label="local index", minimum=0)
    if _looks_like_local_id_selector(text):
        return "local_id", text
    return "old_name", text


def _local_selector_from_args(
    args: argparse.Namespace,
    *,
    name_param: Literal["old_name", "local_name"],
    require_selector: bool,
) -> LocalSelector:
    if args.local_id and args.index is not None:
        raise CliUserError("--local-id and --index are mutually exclusive")
    selector_text = str(args.selector or "").strip()
    if (args.local_id or args.index is not None) and selector_text:
        raise CliUserError("do not combine a positional selector with --local-id or --index")
    if args.local_id:
        return LocalSelector("local_id", str(args.local_id))
    if args.index is not None:
        return LocalSelector("index", _parse_cli_int_text(args.index, label="local index", minimum=0))
    if not selector_text:
        if require_selector:
            raise CliUserError("local selector is required via selector, --local-id, or --index")
        raise CliUserError("missing local selector")
    selector_kind, selector_value = _infer_local_selector(selector_text)
    if selector_kind == "old_name":
        return LocalSelector(name_param, str(selector_value))
    if selector_kind == "local_id":
        return LocalSelector("local_id", str(selector_value))
    return LocalSelector("index", int(selector_value))


def _local_rename_request(args: argparse.Namespace) -> LocalRenameRequest:
    return LocalRenameRequest(
        identifier=str(args.function),
        selector=_local_selector_from_args(args, name_param="old_name", require_selector=True),
        new_name=str(args.new_name),
    )


def _local_retype_request(args: argparse.Namespace) -> LocalRetypeRequest:
    return LocalRetypeRequest(
        identifier=str(args.function),
        selector=_local_selector_from_args(args, name_param="local_name", require_selector=True),
        decl=read_decl_or_type_text(args),
    )


def _local_update_request(args: argparse.Namespace) -> LocalUpdateRequest:
    request = LocalUpdateRequest(
        identifier=str(args.function),
        selector=_local_selector_from_args(args, name_param="local_name", require_selector=True),
        new_name=str(args.rename or "").strip() or None,
        decl=read_decl_text_if_present(args),
    )
    if not request.has_changes():
        raise CliUserError("at least one of --rename or declaration input is required")
    return request


def local_rename_params(args: argparse.Namespace) -> dict[str, Any]:
    return _local_rename_request(args).to_params()


def local_retype_params(args: argparse.Namespace) -> dict[str, Any]:
    return _local_retype_request(args).to_params()


def local_update_params(args: argparse.Namespace) -> dict[str, Any]:
    return _local_update_request(args).to_params()
