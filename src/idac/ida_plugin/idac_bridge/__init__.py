"""IDA GUI bridge scaffold package for idac."""

from .protocol import (
    PLUGIN_NAME,
    SUPPORTED_OPERATIONS,
    registry_path,
    socket_path,
)

__all__ = [
    "PLUGIN_NAME",
    "SUPPORTED_OPERATIONS",
    "BridgeService",
    "IdacBridge",
    "build_default_registry",
    "current_target_info",
    "registry_path",
    "socket_path",
]


def __getattr__(name: str):
    if name in {"BridgeService", "IdacBridge"}:
        from .bridge import BridgeService, IdacBridge

        return {
            "BridgeService": BridgeService,
            "IdacBridge": IdacBridge,
        }[name]
    if name in {"build_default_registry", "current_target_info"}:
        from .handlers import build_default_registry, current_target_info

        return {
            "build_default_registry": build_default_registry,
            "current_target_info": current_target_info,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
