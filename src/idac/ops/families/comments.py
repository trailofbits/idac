from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from ..base import Op
from ..helpers.params import require_str
from ..preview import PreviewSpec
from ..runtime import IdaOperationError, IdaRuntime

CommentScope = Literal["line", "function", "anterior", "posterior"]


@dataclass(frozen=True)
class CommentLookup:
    identifier: str
    scope: CommentScope
    repeatable: bool


@dataclass(frozen=True)
class CommentChange:
    identifier: str
    text: str
    scope: CommentScope
    repeatable: bool


def _normalize_comment_text(text: str | None) -> str | None:
    return None if text in (None, "") else str(text)


def _parse_scope(params: Mapping[str, Any]) -> CommentScope:
    scope = str(params.get("scope") or "line").strip().lower()
    if scope not in {"line", "function", "anterior", "posterior"}:
        raise IdaOperationError(f"unsupported comment scope: {scope}")
    return scope  # type: ignore[return-value]


def _parse_repeatable(params: Mapping[str, Any], *, scope: CommentScope) -> bool:
    repeatable = bool(params.get("repeatable"))
    if repeatable and scope in {"anterior", "posterior"}:
        raise IdaOperationError("repeatable comments are only supported for line or function scope")
    return repeatable


def _function_for_comment(runtime: IdaRuntime, ea: int):
    func = runtime.ida_funcs.get_func(ea)
    if func is None:
        raise IdaOperationError(f"no function contains address {hex(ea)}")
    return func


def _extra_anchor(runtime: IdaRuntime, scope: CommentScope) -> int:
    ida_lines = runtime.mod("ida_lines")
    if scope == "anterior":
        return ida_lines.E_PREV
    if scope == "posterior":
        return ida_lines.E_NEXT
    raise IdaOperationError(f"extra comments are unsupported for scope: {scope}")


def _read_extra_comment(runtime: IdaRuntime, ea: int, *, scope: CommentScope) -> str | None:
    ida_lines = runtime.mod("ida_lines")
    index = _extra_anchor(runtime, scope)
    lines: list[str] = []
    while True:
        line = ida_lines.get_extra_cmt(ea, index)
        if line is None:
            break
        lines.append(str(line))
        index += 1
    return _normalize_comment_text(None if not lines else "\n".join(lines))


def _extra_comment_lines(text: str | None) -> list[str]:
    rendered = "" if text is None else str(text)
    return [] if rendered == "" else rendered.splitlines()


def _set_extra_comment_lines(runtime: IdaRuntime, ea: int, *, scope: CommentScope, lines: list[str]) -> None:
    ida_lines = runtime.mod("ida_lines")
    anchor = _extra_anchor(runtime, scope)
    ida_lines.delete_extra_cmts(ea, anchor)
    for index, line in enumerate(lines):
        if not ida_lines.update_extra_cmt(ea, anchor + index, line):
            raise IdaOperationError(f"failed to set {scope} comment at {hex(ea)}")


def _write_extra_comment(runtime: IdaRuntime, ea: int, *, scope: CommentScope, text: str | None) -> None:
    before = _read_extra_comment(runtime, ea, scope=scope)
    before_lines = _extra_comment_lines(before)
    new_lines = _extra_comment_lines(text)
    try:
        _set_extra_comment_lines(runtime, ea, scope=scope, lines=new_lines)
    except Exception as exc:
        try:
            _set_extra_comment_lines(runtime, ea, scope=scope, lines=before_lines)
        except Exception as restore_exc:
            raise IdaOperationError(
                f"failed to restore {scope} comment at {hex(ea)} after update failure"
            ) from restore_exc
        raise IdaOperationError(f"failed to set {scope} comment at {hex(ea)}") from exc


def _comment_payload(
    *,
    address: str,
    scope: CommentScope,
    repeatable: bool,
    comment: str | None,
    changed: bool | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "address": address,
        "scope": scope,
        "repeatable": repeatable,
        "comment": comment,
    }
    if changed is not None:
        payload["changed"] = changed
    return payload


def _read_comment(runtime: IdaRuntime, request: CommentLookup | CommentChange) -> dict[str, object]:
    ida_bytes = runtime.mod("ida_bytes")
    ea = runtime.resolve_address(request.identifier)
    if request.scope == "line":
        comment = _normalize_comment_text(ida_bytes.get_cmt(ea, request.repeatable))
        return _comment_payload(address=hex(ea), scope=request.scope, repeatable=request.repeatable, comment=comment)
    if request.scope == "function":
        func = _function_for_comment(runtime, ea)
        comment = _normalize_comment_text(runtime.ida_funcs.get_func_cmt(func, request.repeatable))
        return _comment_payload(
            address=hex(func.start_ea),
            scope=request.scope,
            repeatable=request.repeatable,
            comment=comment,
        )
    return _comment_payload(
        address=hex(ea),
        scope=request.scope,
        repeatable=False,
        comment=_read_extra_comment(runtime, ea, scope=request.scope),
    )


def _write_comment(runtime: IdaRuntime, request: CommentChange, *, text: str) -> dict[str, object]:
    ida_bytes = runtime.mod("ida_bytes")
    ea = runtime.resolve_address(request.identifier)
    if request.scope == "line":
        if not ida_bytes.set_cmt(ea, text, request.repeatable):
            raise IdaOperationError(f"failed to set comment at {hex(ea)}")
        return _comment_payload(
            address=hex(ea),
            scope=request.scope,
            repeatable=request.repeatable,
            comment=_normalize_comment_text(ida_bytes.get_cmt(ea, request.repeatable)),
            changed=True,
        )
    if request.scope == "function":
        func = _function_for_comment(runtime, ea)
        if not runtime.ida_funcs.set_func_cmt(func, text, request.repeatable):
            raise IdaOperationError(f"failed to set function comment at {hex(func.start_ea)}")
        return _comment_payload(
            address=hex(func.start_ea),
            scope=request.scope,
            repeatable=request.repeatable,
            comment=_normalize_comment_text(runtime.ida_funcs.get_func_cmt(func, request.repeatable)),
            changed=True,
        )
    _write_extra_comment(runtime, ea, scope=request.scope, text=text)
    return _comment_payload(
        address=hex(ea),
        scope=request.scope,
        repeatable=False,
        comment=_read_extra_comment(runtime, ea, scope=request.scope),
        changed=True,
    )


def _parse_lookup(params: Mapping[str, Any]) -> CommentLookup:
    identifier = require_str(params.get("address"), field="address")
    scope = _parse_scope(params)
    return CommentLookup(identifier=identifier, scope=scope, repeatable=_parse_repeatable(params, scope=scope))


def _parse_change(params: Mapping[str, Any]) -> CommentChange:
    request = _parse_lookup(params)
    return CommentChange(
        identifier=request.identifier,
        text=str(params.get("text") or ""),
        scope=request.scope,
        repeatable=request.repeatable,
    )


def _set_comment(runtime: IdaRuntime, request: CommentChange) -> dict[str, object]:
    return _write_comment(runtime, request, text=request.text)


def _delete_comment(runtime: IdaRuntime, request: CommentLookup) -> dict[str, object]:
    return _write_comment(
        runtime,
        CommentChange(
            identifier=request.identifier,
            text="",
            scope=request.scope,
            repeatable=request.repeatable,
        ),
        text="",
    )


def _run_comment_get(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _read_comment(runtime, _parse_lookup(params))


def _run_comment_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _set_comment(runtime, _parse_change(params))


def _run_comment_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _delete_comment(runtime, _parse_lookup(params))


def _capture_comment_set(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _read_comment(runtime, _parse_change(params))


def _capture_comment_delete(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    return _read_comment(runtime, _parse_lookup(params))


def _restore_comment_change(
    runtime: IdaRuntime,
    params: Mapping[str, Any],
    before: dict[str, object],
    result: Any,
) -> None:
    del params, result
    _write_comment(
        runtime,
        CommentChange(
            identifier=_address_from_before(before),
            text="" if before.get("comment") is None else str(before.get("comment")),
            scope=before["scope"],  # type: ignore[arg-type]
            repeatable=bool(before.get("repeatable")),
        ),
        text="" if before.get("comment") is None else str(before.get("comment")),
    )


def _address_from_before(before: dict[str, object]) -> str:
    address = before.get("address")
    if not isinstance(address, str) or not address:
        raise IdaOperationError("internal error: comment preview missing address")
    return address


COMMENT_OPS: dict[str, Op] = {
    "comment_get": Op(run=_run_comment_get),
    "comment_set": Op(
        run=_run_comment_set,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_comment_set,
            capture_after=_capture_comment_set,
            rollback=_restore_comment_change,
        ),
    ),
    "comment_delete": Op(
        run=_run_comment_delete,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_capture_comment_delete,
            capture_after=_capture_comment_delete,
            rollback=_restore_comment_change,
        ),
    ),
}


__all__ = [
    "COMMENT_OPS",
    "CommentChange",
    "CommentLookup",
]
