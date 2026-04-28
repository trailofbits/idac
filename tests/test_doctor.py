from __future__ import annotations

import json
import shutil
from pathlib import Path

from idac import doctor
from idac.metadata import (
    BRIDGE_PLUGIN_NAME,
    GUI_BACKEND_NAME,
    IDALIB_BACKEND_NAME,
    bridge_registry_payload,
    idalib_registry_payload,
)
from idac.version import VERSION


def test_doctor_reports_gui_install_and_running_instances(monkeypatch, tmp_path: Path) -> None:
    source_dir = tmp_path / "plugin-src"
    source_dir.mkdir()
    bootstrap_source = tmp_path / "idac_bridge_plugin.py"
    bootstrap_source.write_text("# bootstrap\n", encoding="utf-8")
    runtime_package_source = tmp_path / "idac-src"
    runtime_package_source.mkdir()
    (runtime_package_source / "__init__.py").write_text("# idac\n", encoding="utf-8")

    install_dir = tmp_path / "plugins" / "idac_bridge"
    install_dir.parent.mkdir(parents=True)
    install_dir.symlink_to(source_dir, target_is_directory=True)

    install_bootstrap = tmp_path / "plugins" / "idac_bridge_plugin.py"
    install_bootstrap.symlink_to(bootstrap_source)
    install_runtime_package = tmp_path / "plugins" / "idac"
    install_runtime_package.symlink_to(runtime_package_source, target_is_directory=True)

    instance = doctor.gui.BridgeInstance(
        pid=4321,
        socket_path=tmp_path / "idac-bridge-4321.sock",
        registry_path=tmp_path / "idac-bridge-4321.json",
        plugin_name=BRIDGE_PLUGIN_NAME,
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )

    monkeypatch.setattr(doctor, "plugin_source_dir", lambda: source_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_source_path", lambda: bootstrap_source)
    monkeypatch.setattr(doctor, "plugin_runtime_package_source_dir", lambda: runtime_package_source)
    monkeypatch.setattr(doctor, "plugin_install_dir", lambda: install_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_install_path", lambda: install_bootstrap)
    monkeypatch.setattr(doctor, "plugin_runtime_package_install_dir", lambda: install_runtime_package)
    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: tmp_path / "runtime")
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [instance.registry_path])
    monkeypatch.setattr(doctor.gui, "list_instances", lambda: [instance])
    monkeypatch.setattr(
        doctor.gui,
        "list_targets",
        lambda timeout=None, warnings=None: [
            {
                "target_id": "4321:active",
                "selector": "pid:4321",
                "module": "tiny",
                "instance_pid": 4321,
                "active": True,
            }
        ],
    )

    result = doctor.run_doctor(backend="gui", timeout=1.0)

    assert result["healthy"] is True
    assert result["status"] == "ok"
    assert any(item["name"] == "bridge_targets" and item["status"] == "ok" for item in result["checks"])


def test_doctor_warns_for_runtime_package_drift_when_bridge_is_live(monkeypatch, tmp_path: Path) -> None:
    source_dir = tmp_path / "plugin-src"
    source_dir.mkdir()
    bootstrap_source = tmp_path / "idac_bridge_plugin.py"
    bootstrap_source.write_text("# bootstrap\n", encoding="utf-8")
    runtime_package_source = tmp_path / "idac-src"
    runtime_package_source.mkdir()
    (runtime_package_source / "__init__.py").write_text("# idac\n", encoding="utf-8")

    install_dir = tmp_path / "plugins" / "idac_bridge"
    install_dir.parent.mkdir(parents=True)
    install_dir.symlink_to(source_dir, target_is_directory=True)

    install_bootstrap = tmp_path / "plugins" / "idac_bridge_plugin.py"
    install_bootstrap.symlink_to(bootstrap_source)
    install_runtime_package = tmp_path / "plugins" / "idac"
    install_runtime_package.symlink_to(tmp_path / "missing-runtime-package", target_is_directory=True)

    instance = doctor.gui.BridgeInstance(
        pid=4321,
        socket_path=tmp_path / "idac-bridge-4321.sock",
        registry_path=tmp_path / "idac-bridge-4321.json",
        plugin_name=BRIDGE_PLUGIN_NAME,
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )

    monkeypatch.setattr(doctor, "plugin_source_dir", lambda: source_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_source_path", lambda: bootstrap_source)
    monkeypatch.setattr(doctor, "plugin_runtime_package_source_dir", lambda: runtime_package_source)
    monkeypatch.setattr(doctor, "plugin_install_dir", lambda: install_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_install_path", lambda: install_bootstrap)
    monkeypatch.setattr(doctor, "plugin_runtime_package_install_dir", lambda: install_runtime_package)
    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: tmp_path / "runtime")
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [instance.registry_path])
    monkeypatch.setattr(doctor.gui, "list_instances", lambda: [instance])
    monkeypatch.setattr(
        doctor.gui,
        "list_targets",
        lambda timeout=None, warnings=None: [
            {
                "target_id": "4321:active",
                "selector": "pid:4321",
                "module": "tiny",
                "instance_pid": 4321,
                "active": True,
            }
        ],
    )

    result = doctor.run_doctor(backend="gui", timeout=1.0)

    assert result["healthy"] is True
    assert result["status"] == "warn"
    runtime_package = next(item for item in result["checks"] if item["name"] == "plugin_runtime_package")
    assert runtime_package["status"] == "warn"
    assert "does not block the current running GUI bridge" in runtime_package["summary"]
    bridge_targets = next(item for item in result["checks"] if item["name"] == "bridge_targets")
    assert bridge_targets["status"] == "ok"


def test_doctor_accepts_copy_install_layout(monkeypatch, tmp_path: Path) -> None:
    source_dir = tmp_path / "plugin-src"
    source_dir.mkdir()
    (source_dir / "__init__.py").write_text("# package\n", encoding="utf-8")
    bootstrap_source = tmp_path / "idac_bridge_plugin.py"
    bootstrap_source.write_text("# bootstrap\n", encoding="utf-8")
    runtime_package_source = tmp_path / "idac-src"
    runtime_package_source.mkdir()
    (runtime_package_source / "__init__.py").write_text("# idac\n", encoding="utf-8")

    install_dir = tmp_path / "plugins" / "idac_bridge"
    shutil.copytree(source_dir, install_dir)
    install_bootstrap = tmp_path / "plugins" / "idac_bridge_plugin.py"
    shutil.copy2(bootstrap_source, install_bootstrap)
    install_runtime_package = tmp_path / "plugins" / "idac"
    shutil.copytree(runtime_package_source, install_runtime_package)

    monkeypatch.setattr(doctor, "plugin_source_dir", lambda: source_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_source_path", lambda: bootstrap_source)
    monkeypatch.setattr(doctor, "plugin_runtime_package_source_dir", lambda: runtime_package_source)
    monkeypatch.setattr(doctor, "plugin_install_dir", lambda: install_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_install_path", lambda: install_bootstrap)
    monkeypatch.setattr(doctor, "plugin_runtime_package_install_dir", lambda: install_runtime_package)
    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: tmp_path / "runtime")
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [])
    monkeypatch.setattr(doctor.gui, "list_instances", lambda: [])
    monkeypatch.setattr(doctor.gui, "list_targets", lambda timeout=None, warnings=None: [])

    result = doctor.run_doctor(backend="gui", timeout=1.0)

    statuses = {(item["name"], item["status"]) for item in result["checks"]}
    assert ("plugin_package", "ok") in statuses
    assert ("plugin_bootstrap", "ok") in statuses
    assert ("plugin_runtime_package", "ok") in statuses


def test_doctor_warns_after_purging_refused_bridge_registry(monkeypatch, tmp_path: Path) -> None:
    source_dir = tmp_path / "plugin-src"
    source_dir.mkdir()
    bootstrap_source = tmp_path / "idac_bridge_plugin.py"
    bootstrap_source.write_text("# bootstrap\n", encoding="utf-8")
    runtime_package_source = tmp_path / "idac-src"
    runtime_package_source.mkdir()
    (runtime_package_source / "__init__.py").write_text("# idac\n", encoding="utf-8")

    install_dir = tmp_path / "plugins" / "idac_bridge"
    install_dir.parent.mkdir(parents=True)
    install_dir.symlink_to(source_dir, target_is_directory=True)

    install_bootstrap = tmp_path / "plugins" / "idac_bridge_plugin.py"
    install_bootstrap.symlink_to(bootstrap_source)
    install_runtime_package = tmp_path / "plugins" / "idac"
    install_runtime_package.symlink_to(runtime_package_source, target_is_directory=True)

    registry = tmp_path / "idac-bridge-4321.json"
    socket_path = tmp_path / "idac-bridge-4321.sock"
    socket_path.write_text("", encoding="utf-8")
    registry.write_text(
        json.dumps(
            {
                "pid": 4321,
                "socket_path": str(socket_path),
                "plugin_name": BRIDGE_PLUGIN_NAME,
                "plugin_version": VERSION,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(doctor, "plugin_source_dir", lambda: source_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_source_path", lambda: bootstrap_source)
    monkeypatch.setattr(doctor, "plugin_runtime_package_source_dir", lambda: runtime_package_source)
    monkeypatch.setattr(doctor, "plugin_install_dir", lambda: install_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_install_path", lambda: install_bootstrap)
    monkeypatch.setattr(doctor, "plugin_runtime_package_install_dir", lambda: install_runtime_package)
    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: tmp_path / "runtime")
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(doctor.gui, "bridge_registry_paths", lambda: [registry])
    monkeypatch.setattr(doctor, "pid_is_live", lambda pid: pid == 4321)
    monkeypatch.setattr(
        doctor.gui,
        "_send_request_to_instance",
        lambda *args, **kwargs: (_ for _ in ()).throw(doctor.gui.StaleBridgeInstanceError("refused bridge socket")),
    )

    result = doctor.run_doctor(backend="gui", timeout=1.0)

    assert result["healthy"] is True
    assert result["status"] == "warn"
    bridge_targets = next(item for item in result["checks"] if item["name"] == "bridge_targets")
    assert bridge_targets["status"] == "warn"
    assert bridge_targets["summary"] == "no running GUI bridge instances found"
    discovery = next(item for item in result["checks"] if item["name"] == "bridge_discovery")
    assert discovery["status"] == "warn"
    assert discovery["details"]["warnings"]
    assert not any(item["name"] == "bridge_version" for item in result["checks"])
    assert not registry.exists()


def test_bridge_registry_payload_uses_current_version() -> None:
    payload = bridge_registry_payload(pid=7, socket_path="/tmp/idac.sock", started_at="now")

    assert payload["plugin_name"] == BRIDGE_PLUGIN_NAME
    assert payload["plugin_version"] == VERSION
    assert payload["backend"] == GUI_BACKEND_NAME


def test_idalib_registry_payload_includes_backend_marker() -> None:
    payload = idalib_registry_payload(
        pid=8,
        socket_path="/tmp/idac-idalib.sock",
        started_at="now",
        database_path="/tmp/sample.i64",
    )

    assert payload["backend"] == IDALIB_BACKEND_NAME
    assert payload["database_path"] == "/tmp/sample.i64"


def test_doctor_reports_missing_idalib_install(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "_candidate_ida_dirs", lambda: [Path("/missing/ida")])

    def fail_bootstrap():
        raise RuntimeError("missing idapro")

    monkeypatch.setattr(doctor, "_bootstrap_idapro", fail_bootstrap)

    result = doctor.run_doctor(backend="idalib")

    assert result["healthy"] is False
    assert result["status"] == "error"
    names = {item["name"] for item in result["checks"]}
    assert "install_dirs" in names
    assert "idapro_import" in names


def test_doctor_cleanup_removes_stale_registry_and_orphan_socket(monkeypatch, tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    live_socket = runtime_dir / "idac-bridge-4321.sock"
    live_socket.write_text("", encoding="utf-8")
    live_registry = runtime_dir / "idac-bridge-4321.json"
    live_registry.write_text(
        json.dumps(
            {
                "pid": 4321,
                "socket_path": str(live_socket),
            }
        ),
        encoding="utf-8",
    )

    stale_socket = runtime_dir / "idac-bridge-9876.sock"
    stale_socket.write_text("", encoding="utf-8")
    stale_registry = runtime_dir / "idac-bridge-9876.json"
    stale_registry.write_text(
        json.dumps(
            {
                "pid": 9876,
                "socket_path": str(stale_socket),
            }
        ),
        encoding="utf-8",
    )

    orphan_socket = runtime_dir / "idac-bridge-5555.sock"
    orphan_socket.write_text("", encoding="utf-8")

    live_idalib_socket = runtime_dir / "idac-idalib-7777.sock"
    live_idalib_socket.write_text("", encoding="utf-8")
    live_idalib_registry = runtime_dir / "idac-idalib-7777.json"
    live_idalib_registry.write_text(
        json.dumps(
            {
                "pid": 7777,
                "socket_path": str(live_idalib_socket),
                "database_path": "/tmp/live.i64",
            }
        ),
        encoding="utf-8",
    )

    stale_idalib_socket = runtime_dir / "idac-idalib-8888.sock"
    stale_idalib_socket.write_text("", encoding="utf-8")
    stale_idalib_registry = runtime_dir / "idac-idalib-8888.json"
    stale_idalib_registry.write_text(
        json.dumps(
            {
                "pid": 8888,
                "socket_path": str(stale_idalib_socket),
                "database_path": "/tmp/stale.i64",
            }
        ),
        encoding="utf-8",
    )

    orphan_idalib_socket = runtime_dir / "idac-idalib-9999.sock"
    orphan_idalib_socket.write_text("", encoding="utf-8")

    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [live_registry, stale_registry])
    monkeypatch.setattr(
        doctor,
        "idalib_registry_paths",
        lambda: [live_idalib_registry, stale_idalib_registry],
    )
    monkeypatch.setattr(doctor, "pid_is_live", lambda pid: pid in {4321, 7777})

    result = doctor.run_doctor_cleanup()

    assert result["removed_count"] == 6
    assert result["kept_count"] == 2
    assert live_registry.exists()
    assert live_socket.exists()
    assert live_idalib_registry.exists()
    assert live_idalib_socket.exists()
    assert not stale_registry.exists()
    assert not stale_socket.exists()
    assert not orphan_socket.exists()
    assert not stale_idalib_registry.exists()
    assert not stale_idalib_socket.exists()
    assert not orphan_idalib_socket.exists()


def test_doctor_cleanup_removes_malformed_registry(monkeypatch, tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    bad_registry = runtime_dir / "idac-bridge-1111.json"
    bad_registry.write_text("{not-json}", encoding="utf-8")
    bad_idalib_registry = runtime_dir / "idac-idalib-2222.json"
    bad_idalib_registry.write_text("{not-json}", encoding="utf-8")

    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [bad_registry])
    monkeypatch.setattr(doctor, "idalib_registry_paths", lambda: [bad_idalib_registry])
    monkeypatch.setattr(doctor, "pid_is_live", lambda pid: False)

    result = doctor.run_doctor_cleanup()

    assert result["removed_count"] == 2
    assert not bad_registry.exists()
    assert not bad_idalib_registry.exists()


def test_doctor_cleanup_removes_gui_artifacts_for_live_idalib_pid_reuse(monkeypatch, tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    gui_socket = runtime_dir / "idac-bridge-22536.sock"
    gui_socket.write_text("", encoding="utf-8")
    gui_registry = runtime_dir / "idac-bridge-22536.json"
    gui_registry.write_text(
        json.dumps(
            {
                "pid": 22536,
                "socket_path": str(gui_socket),
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: runtime_dir)
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [gui_registry])
    monkeypatch.setattr(doctor, "idalib_registry_paths", lambda: [])
    monkeypatch.setattr(doctor, "pid_is_live", lambda pid: pid == 22536)
    monkeypatch.setattr(
        doctor.gui,
        "_pid_non_gui_bridge_reason",
        lambda pid: "process is running the idalib worker, not an IDA GUI session",
    )

    result = doctor.run_doctor_cleanup()

    assert result["removed_count"] == 2
    assert result["kept_count"] == 0
    assert not gui_registry.exists()
    assert not gui_socket.exists()
