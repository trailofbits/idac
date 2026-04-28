from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

from idac.transport import common, gui
from idac.transport.schema import RequestEnvelope
from idac.version import VERSION


def _write_instance(tmp_path: Path, pid: int, *, module: str) -> Path:
    socket_path = tmp_path / f"idac-bridge-{pid}.sock"
    socket_path.write_text("", encoding="utf-8")
    registry_path = tmp_path / f"idac-bridge-{pid}.json"
    registry_path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(socket_path),
                "plugin_name": "idac_bridge",
                "plugin_version": VERSION,
                "instance_id": f"instance-{pid}",
                "started_at": "2026-04-04T00:00:00Z",
                "state": "ready",
                "module": module,
            }
        ),
        encoding="utf-8",
    )
    return registry_path


def _status_payload(instance: gui.BridgeInstance) -> dict[str, object]:
    return {
        "pid": instance.pid,
        "socket_path": str(instance.socket_path),
        "instance_id": instance.instance_id or f"instance-{instance.pid}",
        "state": "ready",
        "plugin_name": "idac_bridge",
        "plugin_version": instance.plugin_version,
        "started_at": instance.started_at,
        "queue_depth": 0,
        "queue_capacity": 16,
    }


def _install_fake_instances(monkeypatch, tmp_path: Path, modules: dict[int, str]) -> None:
    registries = [_write_instance(tmp_path, pid, module=module) for pid, module in modules.items()]
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: registries)
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid in modules)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        if request.op == "bridge_status":
            return {"ok": True, "result": _status_payload(instance)}
        assert request.op == "list_targets"
        module = modules[instance.pid]
        return {
            "ok": True,
            "result": [
                {
                    "target_id": "active",
                    "selector": module,
                    "filename": f"/tmp/{module}.i64",
                    "module": module,
                    "active": True,
                }
            ],
        }

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)


def test_list_targets_aggregates_gui_instances(monkeypatch, tmp_path: Path) -> None:
    _install_fake_instances(monkeypatch, tmp_path, {14741: "tiny.stripped", 14679: "tiny"})

    rows = gui.list_targets()

    assert [row["instance_pid"] for row in rows] == [14679, 14741]
    assert [row["module"] for row in rows] == ["tiny", "tiny.stripped"]
    assert rows[0]["target_id"] == "14679:active"
    assert rows[1]["target_id"] == "14741:active"
    assert rows[0]["selector"] == "pid:14679"
    assert rows[1]["selector"] == "pid:14741"


def test_choose_instance_requires_explicit_pid_when_multiple(monkeypatch, tmp_path: Path) -> None:
    _install_fake_instances(monkeypatch, tmp_path, {14679: "tiny", 14741: "tiny.stripped"})

    try:
        gui.choose_instance(None)
    except RuntimeError as exc:
        assert "pass -c pid:<pid>" in str(exc)
    else:  # pragma: no cover - defensive failure branch.
        raise AssertionError("expected multiple instance selection failure")


def test_choose_instance_reports_more_specific_selector_when_ambiguous(monkeypatch, tmp_path: Path) -> None:
    _install_fake_instances(monkeypatch, tmp_path, {14679: "tiny", 14741: "tiny"})

    with pytest.raises(RuntimeError, match="more specific selector"):
        gui.choose_instance("tiny")


def test_choose_instance_accepts_pid_selector(monkeypatch, tmp_path: Path) -> None:
    _install_fake_instances(monkeypatch, tmp_path, {14679: "tiny", 14741: "tiny.stripped"})

    instance, target = gui.choose_instance("pid:14741")

    assert instance.pid == 14741
    assert target == "active"


def test_choose_instance_accepts_global_target_id(monkeypatch, tmp_path: Path) -> None:
    _install_fake_instances(monkeypatch, tmp_path, {14679: "tiny", 14741: "tiny.stripped"})

    instance, target = gui.choose_instance("14679:active")

    assert instance.pid == 14679
    assert target == "active"


def test_choose_instance_accepts_local_selector(monkeypatch, tmp_path: Path) -> None:
    _install_fake_instances(monkeypatch, tmp_path, {14679: "tiny", 14741: "tiny.stripped"})

    instance, target = gui.choose_instance("tiny.stripped")

    assert instance.pid == 14741
    assert target == "active"


def test_choose_instance_pid_selector_skips_unrelated_bridge_probes(monkeypatch, tmp_path: Path) -> None:
    registries = [
        _write_instance(tmp_path, 14679, module="tiny"),
        _write_instance(tmp_path, 14741, module="tiny.stripped"),
    ]
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: registries)
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid in {14679, 14741})
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)
    seen: list[tuple[int, str]] = []

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        seen.append((instance.pid, request.op))
        if instance.pid == 14679:
            raise AssertionError("unrelated instance should not be probed")
        if request.op == "bridge_status":
            return {"ok": True, "result": _status_payload(instance)}
        raise AssertionError(f"unexpected op: {request.op}")

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    instance, target = gui.choose_instance("pid:14741")

    assert instance.pid == 14741
    assert target == "active"
    assert seen == [(14741, "bridge_status")]


def test_list_targets_skips_and_purges_stale_instances(monkeypatch, tmp_path: Path) -> None:
    good_registry = _write_instance(tmp_path, 14679, module="tiny")
    stale_registry = _write_instance(tmp_path, 14741, module="tiny.stripped")
    modules = {14679: "tiny", 14741: "tiny.stripped"}

    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [good_registry, stale_registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid in modules)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        if request.op == "bridge_status":
            return {"ok": True, "result": _status_payload(instance)}
        assert request.op == "list_targets"
        if instance.pid == 14741:
            raise gui.StaleBridgeInstanceError("stale socket")
        return {
            "ok": True,
            "result": [
                {
                    "target_id": "active",
                    "selector": "tiny",
                    "filename": "/tmp/tiny.i64",
                    "module": "tiny",
                    "active": True,
                }
            ],
        }

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    warnings: list[str] = []
    rows = gui.list_targets(warnings=warnings)

    assert [row["instance_pid"] for row in rows] == [14679]
    assert not stale_registry.exists()
    assert any("bridge socket stopped responding" in warning for warning in warnings)


def test_list_targets_surfaces_live_bridge_failures(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        if request.op == "bridge_status":
            return {"ok": True, "result": _status_payload(instance)}
        assert request.op == "list_targets"
        raise RuntimeError("malformed JSON")

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    with pytest.raises(RuntimeError, match="malformed JSON"):
        gui.list_targets()

    assert registry.exists()


def test_list_instances_purges_registry_when_bridge_identity_changes(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    socket_path = tmp_path / "idac-bridge-14679.sock"
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        payload = _status_payload(instance)
        payload["instance_id"] = "restarted"
        return {"ok": True, "result": payload}

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    warnings: list[str] = []
    rows = gui.list_instances(warnings=warnings)

    assert rows == []
    assert not registry.exists()
    assert socket_path.exists()
    assert any("bridge identity changed" in warning for warning in warnings)


def test_list_instances_skips_starting_bridge_with_warning(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        return {
            "ok": False,
            "error": "IDA GUI bridge is still starting",
            "error_kind": "startup_incomplete",
        }

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    warnings: list[str] = []
    rows = gui.list_instances(warnings=warnings)

    assert rows == []
    assert registry.exists()
    assert any("still starting" in warning for warning in warnings)


def test_list_instances_skips_draining_bridge_with_warning(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        return {
            "ok": False,
            "error": "IDA GUI bridge is draining",
            "error_kind": "draining",
        }

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    warnings: list[str] = []
    rows = gui.list_instances(warnings=warnings)

    assert rows == []
    assert registry.exists()
    assert any("is draining" in warning for warning in warnings)


def test_list_instances_warns_on_malformed_bridge_status_payload(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        return {"ok": True, "result": {"instance_id": "broken"}}

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    warnings: list[str] = []
    rows = gui.list_instances(warnings=warnings)

    assert rows == []
    assert registry.exists()
    assert any("missing required identity fields" in warning for warning in warnings)


def test_list_instances_forwards_requested_probe_timeout(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)
    observed_timeouts: list[float | None] = []

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        observed_timeouts.append(request.timeout)
        return {"ok": True, "result": _status_payload(instance)}

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    rows_without_timeout = gui.list_instances()
    rows_with_timeout = gui.list_instances(timeout=12.5)

    assert len(rows_without_timeout) == 1
    assert len(rows_with_timeout) == 1
    assert observed_timeouts == [None, 12.5]


def test_list_instances_keeps_legacy_bridge_without_bridge_status(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        return {"ok": False, "error": "unknown operation 'bridge_status'"}

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    rows = gui.list_instances()

    assert [row.pid for row in rows] == [14679]
    assert rows[0].plugin_version == VERSION


def test_validate_instance_status_rejects_started_at_mismatch(tmp_path: Path) -> None:
    instance = gui.BridgeInstance(
        pid=14679,
        socket_path=tmp_path / "idac-bridge-14679.sock",
        registry_path=tmp_path / "idac-bridge-14679.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at="2026-04-04T00:00:00Z",
        instance_id="instance-14679",
    )

    with pytest.raises(gui.StaleBridgeInstanceError, match="start time changed"):
        gui._validate_instance_status(
            instance,
            {
                "pid": 14679,
                "socket_path": str(instance.socket_path),
                "instance_id": "instance-14679",
                "started_at": "2026-04-04T00:00:01Z",
            },
        )


def test_load_instance_keeps_unreadable_registry_files(tmp_path: Path) -> None:
    registry = tmp_path / "idac-bridge-1234.json"
    registry.write_text('{"pid": 1234}', encoding="utf-8")

    assert gui._load_instance(registry) is None
    assert registry.exists()


def test_load_instance_reports_warning_for_unreadable_registry(tmp_path: Path) -> None:
    registry = tmp_path / "idac-bridge-1234.json"
    registry.write_text('{"pid": 1234}', encoding="utf-8")
    warnings: list[str] = []

    assert gui._load_instance(registry, warnings=warnings) is None
    assert warnings
    assert "ignored unreadable or malformed GUI bridge registry" in warnings[0]


def test_load_instance_purges_gui_registry_for_live_idalib_worker(monkeypatch, tmp_path: Path) -> None:
    socket_path = tmp_path / gui.bridge_socket_filename(22536)
    socket_path.write_text("", encoding="utf-8")
    registry = tmp_path / "idac-bridge-22536.json"
    registry.write_text(
        json.dumps(
            {
                "pid": 22536,
                "socket_path": str(socket_path),
                "plugin_name": "idac_bridge",
                "plugin_version": VERSION,
            }
        ),
        encoding="utf-8",
    )
    warnings: list[str] = []
    monkeypatch.setattr(gui, "user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 22536)
    monkeypatch.setattr(
        gui,
        "_pid_non_gui_bridge_reason",
        lambda pid: "process is running the idalib worker, not an IDA GUI session",
    )

    assert gui._load_instance(registry, warnings=warnings) is None
    assert not registry.exists()
    assert not socket_path.exists()
    assert any("idalib worker" in warning for warning in warnings)


def test_load_instance_keeps_untrusted_socket_path_when_purging_registry(monkeypatch, tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    outside_socket = tmp_path / "outside.sock"
    outside_socket.write_text("", encoding="utf-8")
    registry = runtime_dir / "idac-bridge-22536.json"
    registry.write_text(
        json.dumps(
            {
                "pid": 22536,
                "socket_path": str(outside_socket),
                "plugin_name": "idac_bridge",
                "plugin_version": VERSION,
            }
        ),
        encoding="utf-8",
    )
    warnings: list[str] = []
    monkeypatch.setattr(gui, "user_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: False)

    assert gui._load_instance(registry, warnings=warnings) is None
    assert not registry.exists()
    assert outside_socket.exists()
    assert any("process is not running" in warning for warning in warnings)


def test_choose_instance_reports_runtime_dir_and_discovery_diagnostics(monkeypatch, tmp_path: Path) -> None:
    registry = tmp_path / "idac-bridge-1234.json"
    registry.write_text("{not-json}", encoding="utf-8")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "user_runtime_dir", lambda: tmp_path / "runtime")

    with pytest.raises(RuntimeError, match=r"runtime_dir=.*runtime"):
        gui.choose_instance(None, warnings=[])


def test_decode_response_rejects_malformed_json() -> None:
    with pytest.raises(RuntimeError, match="malformed JSON"):
        gui._decode_response([b"{not-json}"])


def test_send_request_retries_transient_socket_errors(monkeypatch, tmp_path: Path) -> None:
    instance = gui.BridgeInstance(
        pid=1234,
        socket_path=tmp_path / "idac-bridge-1234.sock",
        registry_path=tmp_path / "idac-bridge-1234.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )
    attempts = {"count": 0}

    def fake_socket_request(_socket_path, _encoded, *, timeout):
        assert timeout == 1.25
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise OSError(errno.ECONNREFUSED, "refused")
        return [json.dumps({"ok": True, "result": []}).encode("utf-8")]

    monkeypatch.setattr(gui, "_socket_request", fake_socket_request)

    response = gui._send_request_to_instance(
        instance,
        RequestEnvelope(op="database_info", backend="gui", timeout=1.25),
    )

    assert response["ok"] is True
    assert attempts["count"] == 3


def test_send_request_keeps_refused_live_socket_as_runtime_error(monkeypatch, tmp_path: Path) -> None:
    instance = gui.BridgeInstance(
        pid=1234,
        socket_path=tmp_path / "idac-bridge-1234.sock",
        registry_path=tmp_path / "idac-bridge-1234.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )
    instance.socket_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 1234)

    def fake_socket_request(_socket_path, _encoded, *, timeout):
        assert timeout == 1.25
        raise OSError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(gui, "_socket_request", fake_socket_request)

    with pytest.raises(RuntimeError, match=r"Connection refused|refused"):
        gui._send_request_to_instance(
            instance,
            RequestEnvelope(op="database_info", backend="gui", timeout=1.25),
        )


def test_send_request_surfaces_permission_denied_without_retry(monkeypatch, tmp_path: Path) -> None:
    instance = gui.BridgeInstance(
        pid=1234,
        socket_path=tmp_path / "idac-bridge-1234.sock",
        registry_path=tmp_path / "idac-bridge-1234.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )
    instance.socket_path.write_text("", encoding="utf-8")
    attempts = {"count": 0}

    def fake_socket_request(_socket_path, _encoded, *, timeout):
        assert timeout == 1.25
        attempts["count"] += 1
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(gui, "_socket_request", fake_socket_request)
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: True)

    with pytest.raises(RuntimeError, match=r"Permission denied|Errno 13"):
        gui._send_request_to_instance(
            instance,
            RequestEnvelope(op="database_info", backend="gui", timeout=1.25),
        )

    assert attempts["count"] == 1


def test_send_request_uses_blocking_socket_by_default(monkeypatch, tmp_path: Path) -> None:
    instance = gui.BridgeInstance(
        pid=1234,
        socket_path=tmp_path / "idac-bridge-1234.sock",
        registry_path=tmp_path / "idac-bridge-1234.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )

    def fake_socket_request(_socket_path, _encoded, *, timeout):
        assert timeout is None
        return [json.dumps({"ok": True, "result": []}).encode("utf-8")]

    monkeypatch.setattr(gui, "_socket_request", fake_socket_request)

    response = gui._send_request_to_instance(
        instance,
        RequestEnvelope(op="database_info", backend="gui"),
    )

    assert response["ok"] is True


def test_pid_is_live_treats_permission_denied_as_live(monkeypatch) -> None:
    def fake_kill(_pid: int, _signal: int) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(common.os, "kill", fake_kill)

    assert common.pid_is_live(1234) is True


def test_send_request_classifies_refused_dead_socket_as_stale(monkeypatch, tmp_path: Path) -> None:
    instance = gui.BridgeInstance(
        pid=1234,
        socket_path=tmp_path / "idac-bridge-1234.sock",
        registry_path=tmp_path / "idac-bridge-1234.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: False)

    def fake_socket_request(_socket_path, _encoded, *, timeout):
        assert timeout == 1.25
        raise OSError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(gui, "_socket_request", fake_socket_request)

    with pytest.raises(gui.StaleBridgeInstanceError, match=r"Connection refused|refused"):
        gui._send_request_to_instance(
            instance,
            RequestEnvelope(op="database_info", backend="gui", timeout=1.25),
        )


def test_list_targets_rejects_version_mismatch_when_requested(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        payload = _status_payload(instance)
        payload["plugin_version"] = "0.0.0"
        return {"ok": True, "result": payload}

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    with pytest.raises(RuntimeError, match="version mismatch"):
        gui.list_targets(require_matching_version=True)


def test_list_targets_preserves_legacy_version_mismatch_reporting(monkeypatch, tmp_path: Path) -> None:
    registry = _write_instance(tmp_path, 14679, module="tiny")
    payload = json.loads(registry.read_text(encoding="utf-8"))
    payload["plugin_version"] = "0.0.0"
    registry.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(gui, "pid_is_live", lambda pid: pid == 14679)
    monkeypatch.setattr(gui, "_pid_non_gui_bridge_reason", lambda pid: None)

    def fake_send(instance: gui.BridgeInstance, request, *, connect_retries: int = 4):
        assert request.op == "bridge_status"
        return {"ok": False, "error": "unknown operation 'bridge_status'"}

    monkeypatch.setattr(gui, "_send_request_to_instance", fake_send)

    with pytest.raises(RuntimeError, match=r"plugin=0\.0\.0, cli="):
        gui.list_targets(require_matching_version=True)
