"""Protocol and contract definitions for the IDA GUI bridge scaffold."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from idac.metadata import BRIDGE_PLUGIN_NAME, WIRE_PROTOCOL_VERSION
from idac.ops.manifest import SUPPORTED_OPERATIONS
from idac.paths import (
    bridge_registry_filename as registry_filename,
)
from idac.paths import (
    bridge_registry_path as registry_path,
)
from idac.paths import (
    bridge_socket_filename as socket_filename,
)
from idac.paths import (
    bridge_socket_path as socket_path,
)
from idac.paths import (
    ida_user_dir,
    runtime_dir,
)

PLUGIN_NAME = BRIDGE_PLUGIN_NAME


class BridgeError(Exception):
    """Base error type for bridge request handling."""


class EnvelopeParseError(BridgeError):
    """Raised when a request envelope cannot be parsed or validated."""


class UnsupportedOperationError(BridgeError):
    """Raised when an operation exists in contract but has no implementation."""


@dataclass(frozen=True)
class BridgeRequest:
    """Normalized request envelope shape used internally by the bridge."""

    request_id: str
    operation: str
    params: dict[str, Any]
    target: Optional[str] = None


def parse_request_envelope(payload: Any) -> BridgeRequest:
    """Parse a raw payload into a normalized request envelope."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")

    if isinstance(payload, str):
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise EnvelopeParseError(f"invalid JSON payload: {exc.msg}") from exc
    elif isinstance(payload, dict):
        data = payload
    else:
        raise EnvelopeParseError(f"unsupported payload type: {type(payload).__name__}")

    version = data.get("version")
    request_id = data.get("id")
    operation = data.get("op")
    params = data.get("params", {})
    target = data.get("target")

    if version != WIRE_PROTOCOL_VERSION:
        raise EnvelopeParseError(f"unsupported protocol version: expected {WIRE_PROTOCOL_VERSION}, got {version!r}")
    if not request_id:
        raise EnvelopeParseError("missing request id ('id')")
    if not operation:
        raise EnvelopeParseError("missing operation ('op')")
    if not isinstance(params, dict):
        raise EnvelopeParseError("params must be a JSON object")

    return BridgeRequest(
        request_id=str(request_id),
        operation=str(operation),
        params=params,
        target=None if target in (None, "") else str(target),
    )


__all__ = [
    "PLUGIN_NAME",
    "SUPPORTED_OPERATIONS",
    "BridgeError",
    "BridgeRequest",
    "EnvelopeParseError",
    "UnsupportedOperationError",
    "ida_user_dir",
    "parse_request_envelope",
    "registry_filename",
    "registry_path",
    "runtime_dir",
    "socket_filename",
    "socket_path",
]
