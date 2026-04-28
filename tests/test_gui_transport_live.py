from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from idac.transport import gui
from idac.transport.schema import RequestEnvelope


def _import_bridge_module(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "src"))
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        SimpleNamespace(MFF_WRITE=1, execute_sync=lambda fn, _flags: fn(), msg=lambda _text: None),
    )
    try:
        return importlib.import_module("idac.ida_plugin.idac_bridge.bridge")
    finally:
        sys.path.pop(0)


@pytest.mark.gui_live
def test_gui_transport_round_trip_over_real_unix_socket(monkeypatch, tmp_path: Path) -> None:
    bridge_module = _import_bridge_module(monkeypatch)
    runtime = tmp_path / "runtime"
    pid = 4242
    registry = runtime / f"idac-bridge-{pid}.json"
    sock = runtime / f"idac-bridge-{pid}.sock"

    monkeypatch.setattr(bridge_module.os, "getpid", lambda: pid)
    monkeypatch.setattr(bridge_module, "runtime_dir", lambda: runtime)
    monkeypatch.setattr(bridge_module, "registry_path", lambda _pid: registry)
    monkeypatch.setattr(bridge_module, "socket_path", lambda _pid: sock)

    service = bridge_module.BridgeService(
        bridge=bridge_module.IdacBridge(
            handlers={
                "list_targets": lambda _params: [
                    {
                        "target_id": "active",
                        "selector": "tiny",
                        "filename": "/tmp/tiny.i64",
                        "module": "tiny",
                        "active": True,
                    }
                ],
                "database_info": lambda params: {
                    "module": "tiny",
                    "target": "active",
                    "params": params,
                },
                "bookmark_get": lambda params: {
                    "bookmarks": [
                        {
                            "slot": 0,
                            "present": True,
                            "address": "0x100000460",
                            "comment": "entry point",
                        }
                    ],
                    "count": 1,
                    "target": "active",
                    "params": params,
                },
            },
            validate_target=lambda target: (
                None
                if target in (None, "", "active")
                else (_ for _ in ()).throw(AssertionError(f"unexpected target: {target}"))
            ),
        )
    )
    service.start()
    try:
        monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
        monkeypatch.setattr(gui, "pid_is_live", lambda candidate: candidate == pid)

        rows = gui.list_targets(require_matching_version=True)
        assert len(rows) == 1
        assert rows[0]["instance_pid"] == pid
        assert rows[0]["target_id"] == f"{pid}:active"
        assert rows[0]["module"] == "tiny"

        instance = gui.list_instances()[0]
        assert instance.instance_id
        assert instance.state == "ready"
        assert instance.started_at

        status_response = gui._send_request_to_instance(
            instance,
            RequestEnvelope(
                op="bridge_status",
                params={},
                backend="gui",
                timeout=2.0,
            ),
        )

        assert status_response["ok"] is True
        assert status_response["backend"] == "gui"
        assert status_response["result"]["pid"] == pid
        assert status_response["result"]["state"] == "ready"
        assert status_response["result"]["instance_id"] == instance.instance_id

        response = gui._send_request_to_instance(
            instance,
            RequestEnvelope(
                op="database_info",
                params={"ping": "pong"},
                backend="gui",
                target="active",
                timeout=2.0,
            ),
        )

        assert response["ok"] is True
        assert response["backend"] == "gui"
        assert response["result"] == {
            "module": "tiny",
            "target": "active",
            "params": {"ping": "pong"},
        }

        bookmark_response = gui._send_request_to_instance(
            instance,
            RequestEnvelope(
                op="bookmark_get",
                params={},
                backend="gui",
                target="active",
                timeout=2.0,
            ),
        )

        assert bookmark_response["ok"] is True
        assert bookmark_response["backend"] == "gui"
        assert bookmark_response["result"] == {
            "bookmarks": [
                {
                    "slot": 0,
                    "present": True,
                    "address": "0x100000460",
                    "comment": "entry point",
                }
            ],
            "count": 1,
            "target": "active",
            "params": {},
        }
    finally:
        service.stop()
