from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..metadata import WIRE_PROTOCOL_VERSION


@dataclass
class RequestEnvelope:
    op: str
    params: dict[str, Any] = field(default_factory=dict)
    backend: str = "gui"
    target: str | None = None
    database: str | None = None
    timeout: float | None = None


def response_ok(
    result: Any,
    *,
    backend: str,
    warnings: list[str] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    return {
        "version": WIRE_PROTOCOL_VERSION,
        "id": request_id,
        "ok": True,
        "result": result,
        "error": None,
        "error_kind": None,
        "backend": backend,
        "warnings": list(warnings or []),
    }


def response_error(
    message: str,
    *,
    backend: str | None = None,
    request_id: str | None = None,
    error_kind: str | None = None,
) -> dict[str, Any]:
    return {
        "version": WIRE_PROTOCOL_VERSION,
        "id": request_id,
        "ok": False,
        "result": None,
        "error": message,
        "error_kind": error_kind,
        "backend": backend,
        "warnings": [],
    }


__all__ = ["RequestEnvelope", "response_error", "response_ok"]
