from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace

from idac.metadata import BRIDGE_PLUGIN_NAME as EXPECTED_PLUGIN_NAME
from idac.ops.manifest import SUPPORTED_OPERATIONS as EXPECTED_SUPPORTED_OPERATIONS


def _pop_bridge_modules() -> dict[str, object]:
    saved: dict[str, object] = {}
    for name in list(sys.modules):
        if name.startswith("idac.ida_plugin.idac_bridge") or name in {"ida_kernwin", "idaapi"}:
            saved[name] = sys.modules.pop(name)
    return saved


def _restore_bridge_modules(saved: dict[str, object]) -> None:
    for name in list(sys.modules):
        if name.startswith("idac.ida_plugin.idac_bridge") or name in {"ida_kernwin", "idaapi"}:
            sys.modules.pop(name, None)
    sys.modules.update(saved)


def test_plugin_package_import_is_ida_safe(monkeypatch) -> None:
    saved_modules = _pop_bridge_modules()
    monkeypatch.delenv("IDAUSR", raising=False)

    try:
        module = importlib.import_module("idac.ida_plugin.idac_bridge")

        assert module.PLUGIN_NAME == EXPECTED_PLUGIN_NAME
        assert module.SUPPORTED_OPERATIONS == EXPECTED_SUPPORTED_OPERATIONS
        assert module.registry_path().name.startswith("idac-bridge-")
        assert module.socket_path().name.startswith("idac-bridge-")
        assert "idac.ida_plugin.idac_bridge.bridge" not in sys.modules
        assert "idac.ida_plugin.idac_bridge.handlers" not in sys.modules
        assert "ida_kernwin" not in sys.modules
        assert "idaapi" not in sys.modules
    finally:
        _restore_bridge_modules(saved_modules)


def test_plugin_package_imports_bridge_module_only_on_attribute_access() -> None:
    saved_modules = _pop_bridge_modules()
    sys.modules["ida_kernwin"] = SimpleNamespace(
        MFF_WRITE=1,
        execute_sync=lambda fn, _flags: fn(),
        msg=lambda _text: None,
    )

    try:
        module = importlib.import_module("idac.ida_plugin.idac_bridge")

        assert "idac.ida_plugin.idac_bridge.bridge" not in sys.modules
        bridge_service = module.BridgeService

        assert bridge_service.__name__ == "BridgeService"
        assert "idac.ida_plugin.idac_bridge.bridge" in sys.modules
    finally:
        _restore_bridge_modules(saved_modules)
