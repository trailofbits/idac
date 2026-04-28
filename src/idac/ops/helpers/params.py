from __future__ import annotations

from typing import Any

from ..runtime import IdaOperationError


def parse_int_text(
    value: Any,
    *,
    label: str,
    minimum: int | None = None,
) -> int:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{label} is required")
    try:
        parsed = int(text, 0)
    except ValueError as exc:
        raise ValueError(f"{label} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{label} must be greater than or equal to {minimum}")
    return parsed


def param_int(
    params: dict[str, Any],
    key: str,
    *,
    label: str | None = None,
    minimum: int | None = None,
) -> int:
    name = key if label is None else label
    try:
        return parse_int_text(params.get(key), label=name, minimum=minimum)
    except ValueError as exc:
        raise IdaOperationError(str(exc)) from exc


def optional_param_int(
    params: dict[str, Any],
    key: str,
    *,
    label: str | None = None,
    minimum: int | None = None,
) -> int | None:
    value = params.get(key)
    if value in (None, ""):
        return None
    return param_int(params, key, label=label, minimum=minimum)


def require_str(value: Any, *, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise IdaOperationError(f"{field} is required")
    return text


def optional_str(value: Any) -> str | None:
    return str(value or "").strip() or None


def parse_aliases(raw_aliases: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in raw_aliases or []:
        if isinstance(item, dict):
            src = str(item.get("from") or "").strip()
            dst = str(item.get("to") or "").strip()
            raw = f"{src}={dst}" if src or dst else ""
        else:
            raw = str(item).strip()
            src = dst = ""
            if "=" in raw:
                src, dst = (part.strip() for part in raw.split("=", 1))
        if not src or not dst:
            text = raw or str(item)
            raise ValueError(f"invalid alias `{text}`; expected OLD=NEW")
        rows.append({"from": src, "to": dst})
    return rows


__all__ = [
    "optional_param_int",
    "optional_str",
    "param_int",
    "parse_aliases",
    "parse_int_text",
    "require_str",
]
