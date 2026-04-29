from __future__ import annotations

import argparse
import re
from typing import Any, Literal

from ...ops.helpers.params import parse_aliases, parse_int_text
from ...transport import send_request
from ...transport.schema import RequestEnvelope
from ..argparse_utils import read_decl_or_type_text, read_decl_text_if_present
from ..errors import CliUserError
from ..invocation import Invocation
from ..result import CommandResult

_INFERRED_LOCAL_ID_RE = re.compile(
    # Stable local ids from `function locals list --json` encode storage plus a versioned slot identifier.
    r"^(?:stack\([^)]*\)|reg\([^)]*\)|regpair\([^)]*\)|unknown)@(?:0x[0-9a-fA-F]+|\d+)$",
    re.IGNORECASE,
)


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
    invocation = getattr(args, "_invocation", None)
    if not isinstance(invocation, Invocation):
        raise CliUserError("internal error: command was not parsed through parse_invocation")
    return send_invocation_op(invocation, op=op, params=params, render_op=render_op, preview=preview)


def send_invocation_op(
    invocation: Invocation,
    *,
    op: str,
    params: dict[str, Any],
    render_op: str | None = None,
    preview: bool | None = None,
) -> CommandResult:
    preview_requested = (invocation.preview and invocation.spec.mutating) if preview is None else preview
    return _send_backend_op(invocation.args, op=op, params=params, render_op=render_op, preview=preview_requested)


def _send_backend_op(
    args: argparse.Namespace,
    *,
    op: str,
    params: dict[str, Any],
    render_op: str | None,
    preview: bool,
) -> CommandResult:
    payload = dict(params)
    if preview:
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


def local_selector_params(
    args: argparse.Namespace,
    *,
    name_param: Literal["old_name", "local_name"],
    require_selector: bool,
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
        if require_selector:
            raise CliUserError("local selector is required via selector, --local-id, or --index")
        raise CliUserError("missing local selector")
    selector_kind, selector_value = _infer_local_selector(selector_text)
    if selector_kind == "old_name":
        return {name_param: str(selector_value)}
    if selector_kind == "local_id":
        return {"local_id": str(selector_value)}
    return {"index": int(selector_value)}


def local_rename_params(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "identifier": str(args.function),
        "new_name": str(args.new_name),
        **local_selector_params(args, name_param="old_name", require_selector=True),
    }


def local_retype_params(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "identifier": str(args.function),
        "decl": read_decl_or_type_text(args),
        **local_selector_params(args, name_param="local_name", require_selector=True),
    }


def local_update_params(args: argparse.Namespace) -> dict[str, Any]:
    new_name = str(args.rename or "").strip() or None
    decl = read_decl_text_if_present(args)
    if new_name is None and decl is None:
        raise CliUserError("at least one of --rename or declaration input is required")
    params: dict[str, Any] = {
        "identifier": str(args.function),
        **local_selector_params(args, name_param="local_name", require_selector=True),
    }
    if new_name is not None:
        params["new_name"] = new_name
    if decl is not None:
        params["decl"] = decl
    return params
