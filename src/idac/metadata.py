from __future__ import annotations

from typing import Any, Optional

from .version import VERSION

BRIDGE_PLUGIN_NAME = "idac_bridge"
BRIDGE_REGISTRY_PREFIX = "idac-bridge"
BRIDGE_SOCKET_PREFIX = "idac-bridge"
IDALIB_DAEMON_NAME = "idac-idalib"
IDALIB_REGISTRY_PREFIX = "idac-idalib"
IDALIB_SOCKET_PREFIX = "idac-idalib"
BRIDGE_RUNTIME_DIRNAME = "idac"
SKILL_NAME = "idac"
WIRE_PROTOCOL_VERSION = 1
GUI_BACKEND_NAME = "gui"
IDALIB_BACKEND_NAME = "idalib"


def bridge_registry_payload(
    *,
    pid: int,
    socket_path: str,
    started_at: Optional[str],
) -> dict[str, Any]:
    return {
        "pid": pid,
        "socket_path": socket_path,
        "plugin_name": BRIDGE_PLUGIN_NAME,
        "plugin_version": VERSION,
        "started_at": started_at,
        "backend": GUI_BACKEND_NAME,
    }


def idalib_registry_payload(
    *,
    pid: int,
    socket_path: str,
    started_at: Optional[str],
    database_path: Optional[str],
) -> dict[str, Any]:
    return {
        "pid": pid,
        "socket_path": socket_path,
        "server_name": IDALIB_DAEMON_NAME,
        "started_at": started_at,
        "database_path": database_path,
        "backend": IDALIB_BACKEND_NAME,
    }
