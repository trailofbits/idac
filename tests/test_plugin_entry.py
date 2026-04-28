from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

from idac.version import VERSION


def _import_plugin_entry(monkeypatch):
    sys.modules.pop("idac.ida_plugin.idac_bridge_plugin", None)
    messages: list[str] = []
    signal_calls: list[tuple[object, object]] = []

    class FakeFormBase:
        class ChkGroupControl:
            def __init__(self, names):
                self.names = names

        def __init__(self, _form_text, controls):
            self._controls = controls
            self.loggingFlags = SimpleNamespace(value=0)

        def Compile(self):
            return self, None

        def Execute(self):
            return 1

        def Free(self):
            return None

    monkeypatch.setitem(
        sys.modules,
        "idaapi",
        SimpleNamespace(
            plugin_t=object,
            PLUGIN_FIX=1,
            PLUGIN_KEEP=2,
            msg=lambda text: messages.append(text),
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        SimpleNamespace(
            MFF_WRITE=1,
            execute_sync=lambda fn, _flags: fn(),
            Form=FakeFormBase,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "signal",
        SimpleNamespace(
            SIGPIPE=object(),
            SIG_IGN=object(),
            signal=lambda sig, handler: signal_calls.append((sig, handler)),
        ),
    )
    module = importlib.import_module("idac.ida_plugin.idac_bridge_plugin")
    return module, messages, signal_calls


def test_plugin_init_reports_bridge_status(monkeypatch) -> None:
    module, messages, _signal_calls = _import_plugin_entry(monkeypatch)

    class FakeBridgeService:
        request_logging_enabled = False
        response_logging_enabled = False

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

    monkeypatch.setattr(module, "BridgeService", FakeBridgeService)
    monkeypatch.setattr(module.os, "getpid", lambda: 4321)
    monkeypatch.setattr(module, "socket_path", lambda pid: Path(f"/tmp/idac-bridge-{pid}.sock"))
    monkeypatch.setattr(module, "registry_path", lambda pid: Path(f"/tmp/idac-bridge-{pid}.json"))

    plugin = module.IdacBridgePlugin()

    assert plugin.init() == module.idaapi.PLUGIN_KEEP

    plugin._emit_status()

    assert messages == [
        f"[idac] idac bridge v{VERSION} loaded\n"
        f"[idac] GUI bridge running (v{VERSION}): "
        "pid=4321, socket=/tmp/idac-bridge-4321.sock, "
        "registry=/tmp/idac-bridge-4321.json\n",
        f"[idac] idac bridge v{VERSION} loaded\n"
        f"[idac] GUI bridge running (v{VERSION}): "
        "pid=4321, socket=/tmp/idac-bridge-4321.sock, "
        "registry=/tmp/idac-bridge-4321.json\n",
    ]


def test_plugin_run_opens_dialog_applies_flags_and_emits_status(monkeypatch) -> None:
    module, messages, _signal_calls = _import_plugin_entry(monkeypatch)
    executed: list[int] = []
    freed: list[bool] = []

    class FakeDialog:
        def __init__(self):
            self.loggingFlags = SimpleNamespace(value=0)

        def Compile(self):
            return self, None

        def Execute(self):
            executed.append(self.loggingFlags.value)
            self.loggingFlags.value = module.REQUEST_LOG_FLAG | module.RESPONSE_LOG_FLAG
            return 1

        def Free(self):
            freed.append(True)

    class FakeBridgeService:
        def __init__(self) -> None:
            self.request_logging_enabled = True
            self.response_logging_enabled = False

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

        def set_request_logging_enabled(self, enabled: bool) -> bool:
            self.request_logging_enabled = enabled
            return enabled

        def set_response_logging_enabled(self, enabled: bool) -> bool:
            self.response_logging_enabled = enabled
            return enabled

    monkeypatch.setattr(module, "_BridgeLoggingForm", FakeDialog)
    monkeypatch.setattr(module, "BridgeService", FakeBridgeService)
    monkeypatch.setattr(module.os, "getpid", lambda: 5555)
    monkeypatch.setattr(module, "socket_path", lambda pid: Path(f"/tmp/idac-bridge-{pid}.sock"))
    monkeypatch.setattr(module, "registry_path", lambda pid: Path(f"/tmp/idac-bridge-{pid}.json"))

    plugin = module.IdacBridgePlugin()
    assert plugin.init() == module.idaapi.PLUGIN_KEEP

    plugin.run(0)

    assert executed == [module.REQUEST_LOG_FLAG]
    assert freed == [True]
    assert plugin._service is not None
    assert plugin._service.request_logging_enabled is True
    assert plugin._service.response_logging_enabled is True
    assert messages[-1] == (
        f"[idac] idac bridge v{VERSION} loaded\n"
        f"[idac] GUI bridge running (v{VERSION}): "
        "pid=5555, socket=/tmp/idac-bridge-5555.sock, "
        "registry=/tmp/idac-bridge-5555.json\n"
    )


def test_plugin_entry_ignores_sigpipe_when_available(monkeypatch) -> None:
    module, _messages, signal_calls = _import_plugin_entry(monkeypatch)

    assert signal_calls == [(module.signal.SIGPIPE, module.signal.SIG_IGN)]
