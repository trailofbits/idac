from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from idac.metadata import WIRE_PROTOCOL_VERSION
from idac.ops.runtime import IdaOperationError
from idac.version import VERSION


def _import_bridge_module(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "src"))
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        SimpleNamespace(MFF_WRITE=1, execute_sync=lambda fn, _flags: fn()),
    )
    try:
        sys.modules.pop("idac.ida_plugin.idac_bridge.bridge", None)
        return importlib.import_module("idac.ida_plugin.idac_bridge.bridge")
    finally:
        sys.path.pop(0)


def _import_handlers_module(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "src"))
    try:
        sys.modules.pop("idac.ida_plugin.idac_bridge.handlers", None)
        return importlib.import_module("idac.ida_plugin.idac_bridge.handlers")
    finally:
        sys.path.pop(0)


def _import_plugin_module(monkeypatch, *, bridge_service):
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "src"))
    messages: list[str] = []
    monkeypatch.setitem(
        sys.modules,
        "idaapi",
        SimpleNamespace(
            plugin_t=type("plugin_t", (), {}),
            PLUGIN_FIX=1,
            PLUGIN_HIDE=16,
            PLUGIN_KEEP=2,
            PLUGIN_SKIP=3,
            msg=lambda text: messages.append(text),
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        SimpleNamespace(MFF_WRITE=1, execute_sync=lambda fn, _flags: fn()),
    )
    monkeypatch.setitem(
        sys.modules,
        "idac_bridge.bridge",
        SimpleNamespace(BridgeService=bridge_service),
    )
    monkeypatch.setitem(
        sys.modules,
        "idac_bridge.protocol",
        SimpleNamespace(
            registry_path=lambda pid: Path(f"/tmp/{pid}.json"),
            socket_path=lambda pid: Path(f"/tmp/{pid}.sock"),
        ),
    )
    sys.modules.pop("idac.ida_plugin.idac_bridge_plugin", None)
    try:
        module = importlib.import_module("idac.ida_plugin.idac_bridge_plugin")
        return module, messages
    finally:
        sys.path.pop(0)


def test_bridge_translates_expected_operation_failures(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    bridge = bridge_module.IdacBridge(
        handlers={"database_info": lambda _params: (_ for _ in ()).throw(IdaOperationError("bad op"))}
    )

    response = bridge.handle_request({"version": WIRE_PROTOCOL_VERSION, "id": "1", "op": "database_info", "params": {}})

    assert response["ok"] is False
    assert response["error"] == "bad op"
    assert response["version"] == WIRE_PROTOCOL_VERSION
    assert response["id"] == "1"
    assert response["warnings"] == []
    assert response["result"] is None


def test_bridge_dispatches_custom_handlers(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    seen: list[tuple[str, str | None, dict[str, object]]] = []

    bridge = bridge_module.IdacBridge(
        handlers={"database_info": lambda params: seen.append(("database_info", "active", params)) or {"ok": True}}
    )
    response = bridge.handle_request(
        {
            "version": WIRE_PROTOCOL_VERSION,
            "id": "1",
            "op": "database_info",
            "params": {"ping": "pong"},
            "target": "active",
        }
    )

    assert response["ok"] is True
    assert response["result"] == {"ok": True}
    assert seen == [("database_info", "active", {"ping": "pong"})]


def test_bridge_surfaces_unexpected_dispatch_exceptions(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    bridge = bridge_module.IdacBridge(
        handlers={"database_info": lambda _params: (_ for _ in ()).throw(TypeError("boom"))}
    )

    response = bridge.handle_request({"version": WIRE_PROTOCOL_VERSION, "id": "1", "op": "database_info", "params": {}})

    assert response["ok"] is False
    assert response["error"] == "boom"
    assert response["version"] == WIRE_PROTOCOL_VERSION
    assert response["id"] == "1"
    assert response["warnings"] == []
    assert response["result"] is None


def test_bridge_logs_unexpected_dispatch_exceptions(monkeypatch, capsys) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    bridge = bridge_module.IdacBridge(
        handlers={"database_info": lambda _params: (_ for _ in ()).throw(TypeError("boom"))}
    )

    bridge.handle_request({"version": WIRE_PROTOCOL_VERSION, "id": "1", "op": "database_info", "params": {}})

    assert "GUI bridge request raised an internal error" in capsys.readouterr().err


def test_bridge_respects_explicit_validate_target_override(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    seen: list[str | None] = []

    monkeypatch.setattr(
        bridge_module,
        "build_default_registry",
        lambda: (
            {"database_info": lambda _params: {"ok": True}},
            lambda target: (_ for _ in ()).throw(AssertionError(f"default validator used: {target}")),
        ),
    )

    bridge = bridge_module.IdacBridge(validate_target=lambda target: seen.append(target))
    response = bridge.handle_request(
        {
            "version": WIRE_PROTOCOL_VERSION,
            "id": "1",
            "op": "database_info",
            "params": {},
            "target": "active",
        }
    )

    assert response["ok"] is True
    assert response["result"] == {"ok": True}
    assert seen == ["active"]


def test_build_default_registry_returns_handlers_and_validator(monkeypatch) -> None:
    handlers_module = _import_handlers_module(monkeypatch)

    monkeypatch.setattr(handlers_module, "SUPPORTED_OPERATIONS", ("database_info", "list_targets"))
    monkeypatch.setattr(
        handlers_module,
        "build_operation_registry",
        lambda _runtime, *, list_targets=None: {
            "database_info": lambda params: {"params": params},
            "list_targets": list_targets,
        },
    )

    handlers, validate_target = handlers_module.build_default_registry()

    assert tuple(sorted(handlers.keys())) == ("database_info", "list_targets")
    assert handlers["database_info"]({"ping": "pong"}) == {"params": {"ping": "pong"}}
    assert handlers["list_targets"]({}) == [
        {
            "target_id": "active",
            "selector": "active",
            "filename": "",
            "module": "",
            "active": True,
        }
    ]
    assert validate_target("active") is None


def test_bridge_service_writes_registry_atomically(monkeypatch, tmp_path: Path) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    pid = 1234
    registry = tmp_path / f"idac-bridge-{pid}.json"
    sock_path = tmp_path / f"idac-bridge-{pid}.sock"

    monkeypatch.setattr(bridge_module.os, "getpid", lambda: pid)
    monkeypatch.setattr(bridge_module, "registry_path", lambda _pid: registry)

    service = bridge_module.BridgeService()
    service._write_registry(sock_path)

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["pid"] == pid
    assert payload["socket_path"] == str(sock_path)
    assert payload["instance_id"]
    assert payload["state"] == "stopped"
    assert list(tmp_path.glob(f"{registry.name}.*.tmp")) == []


def test_bridge_service_logs_requests_and_responses_when_enabled(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    logs: list[str] = []

    class FakeBridge:
        def handle_request(self, raw: bytes) -> dict[str, object]:
            assert raw == b'{"version": 1, "id": "1", "op": "database_info", "params": {}}\n'
            return {"ok": True, "backend": "gui", "result": {"ping": "pong"}}

    service = bridge_module.BridgeService(bridge=FakeBridge())
    service._state = "ready"
    service._dispatcher = SimpleNamespace(
        call_with_metrics=lambda _name, fn: (
            fn(),
            bridge_module.DispatchMetrics(
                queue_depth_at_enqueue=0,
                queue_wait_seconds=0.0,
                run_seconds=0.0,
            ),
        )
    )
    monkeypatch.setattr(bridge_module, "_bridge_log", lambda message, *, exc=None: logs.append(message))

    service.set_request_logging_enabled(True)
    service.set_response_logging_enabled(True)
    response = service.dispatch_request(b'{"version": 1, "id": "1", "op": "database_info", "params": {}}\n')

    assert response == {"ok": True, "backend": "gui", "result": {"ping": "pong"}}
    assert logs == [
        'GUI bridge request: {"id": "1", "op": "database_info", "params": {}, "version": 1}',
        'GUI bridge response: {"backend": "gui", "ok": true, "result": {"ping": "pong"}}',
        "GUI bridge timings: id=1, op=database_info, queue_depth=0, queue_wait=0.000s, run=0.000s",
    ]


def test_bridge_service_returns_busy_error_when_dispatcher_is_full(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)

    service = bridge_module.BridgeService()
    service._state = "ready"
    service._dispatcher = SimpleNamespace(
        call_with_metrics=lambda _name, _fn: (_ for _ in ()).throw(
            bridge_module.DispatcherBusyError("idac-gui dispatcher queue is full (16/16)")
        )
    )

    response = service.dispatch_request(b'{"version": 1, "id": "req-1", "op": "database_info", "params": {}}\n')

    assert response["ok"] is False
    assert response["id"] == "req-1"
    assert response["error_kind"] == "busy"
    assert "queue is full" in str(response["error"])


def test_bridge_service_returns_draining_error_before_dispatch(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)

    service = bridge_module.BridgeService()
    service._state = "draining"

    response = service.dispatch_request(b'{"version": 1, "id": "req-2", "op": "database_info", "params": {}}\n')

    assert response["ok"] is False
    assert response["id"] == "req-2"
    assert response["error_kind"] == "draining"
    assert response["error"] == "IDA GUI bridge is draining"


def test_bridge_service_returns_startup_error_before_dispatch(monkeypatch) -> None:
    bridge_module = _import_bridge_module(monkeypatch)

    service = bridge_module.BridgeService()
    service._state = "starting"

    response = service.dispatch_request(b'{"version": 1, "id": "req-3", "op": "database_info", "params": {}}\n')

    assert response["ok"] is False
    assert response["id"] == "req-3"
    assert response["error_kind"] == "startup_incomplete"
    assert response["error"] == "IDA GUI bridge is still starting"


def test_bridge_service_lifecycle_writes_start_ready_and_draining_states(monkeypatch, tmp_path: Path) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    pid = 4242
    runtime = tmp_path / "runtime"
    registry = runtime / "bridge.json"
    sock = Path(f"/tmp/idac-bridge-lifecycle-{os.getpid()}.sock")
    states: list[str] = []

    monkeypatch.setattr(bridge_module.os, "getpid", lambda: pid)
    monkeypatch.setattr(bridge_module, "runtime_dir", lambda: runtime)
    monkeypatch.setattr(bridge_module, "registry_path", lambda _pid: registry)
    monkeypatch.setattr(bridge_module, "socket_path", lambda _pid: sock)
    real_write_registry = bridge_module.BridgeService._write_registry

    def recording_write_registry(self, sock_path):
        states.append(self._state)
        return real_write_registry(self, sock_path)

    monkeypatch.setattr(bridge_module.BridgeService, "_write_registry", recording_write_registry)

    service = bridge_module.BridgeService(
        bridge=bridge_module.IdacBridge(
            handlers={"list_targets": lambda _params: []},
            validate_target=lambda _target: None,
        )
    )
    service.start()
    try:
        assert service.status_snapshot()["state"] == "ready"
    finally:
        service.stop()
        sock.unlink(missing_ok=True)

    assert states == ["starting", "ready", "draining"]


def test_plugin_logs_startup_failures(monkeypatch) -> None:
    class ExplodingService:
        def start(self) -> None:
            raise RuntimeError("boom")

    plugin_module, messages = _import_plugin_module(monkeypatch, bridge_service=ExplodingService)
    plugin = plugin_module.IdacBridgePlugin()

    result = plugin.init()

    assert result == 3
    assert any("GUI bridge failed to start" in message for message in messages)


def test_plugin_logs_version_and_status_on_init(monkeypatch) -> None:
    class WorkingService:
        def start(self) -> None:
            return None

    plugin_module, messages = _import_plugin_module(monkeypatch, bridge_service=WorkingService)
    monkeypatch.setattr(plugin_module.os, "getpid", lambda: 4242)
    plugin = plugin_module.IdacBridgePlugin()

    result = plugin.init()

    assert result == 2
    assert any(f"idac bridge v{VERSION} loaded" in message for message in messages)
    assert any(f"GUI bridge running (v{VERSION}): pid=4242" in message for message in messages)
    assert any("/tmp/4242.sock" in message for message in messages)
    assert any("/tmp/4242.json" in message for message in messages)
