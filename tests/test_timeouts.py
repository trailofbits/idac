from __future__ import annotations

import socket
from pathlib import Path

import pytest

from idac.cli import build_parser
from idac.metadata import WIRE_PROTOCOL_VERSION
from idac.transport import BackendError, idalib, send_request
from idac.transport.gui import BridgeInstance, GuiBackend
from idac.transport.idalib import IdaLibBackend, IdaLibInstance
from idac.transport.schema import RequestEnvelope
from idac.version import VERSION


def test_cli_rejects_non_positive_timeout() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["database", "show", "-c", "db:db.i64", "--timeout", "0"])

    with pytest.raises(SystemExit):
        parser.parse_args(["database", "show", "-c", "db:db.i64", "--timeout", "-1"])


def test_strings_command_requires_timeout(capsys) -> None:
    from idac.cli import main

    exit_code = main(["search", "strings", "tiny", "--segment", "__TEXT", "-c", "db:db.i64"])

    assert exit_code == 1
    assert "`idac search strings` requires --timeout" in capsys.readouterr().err


def test_search_bytes_command_requires_timeout(capsys) -> None:
    from idac.cli import main

    exit_code = main(["search", "bytes", "74 69 6e 79", "--segment", "__TEXT", "-c", "db:db.i64"])

    assert exit_code == 1
    assert "`idac search bytes` requires --timeout" in capsys.readouterr().err


def test_required_timeout_commands_fail_before_gui_autodiscovery(monkeypatch, capsys) -> None:
    from idac.cli import main

    def fail_if_called(*args, **kwargs):
        raise AssertionError("GUI autodiscovery should not run before timeout validation")

    monkeypatch.setattr("idac.cli2.context.list_gui_instances", fail_if_called)

    exit_code = main(["search", "bytes", "74 69 6e 79", "--segment", "__TEXT"])

    assert exit_code == 1
    assert "`idac search bytes` requires --timeout" in capsys.readouterr().err


def test_required_timeout_commands_forward_timeout_to_gui_autodiscovery(monkeypatch, capsys) -> None:
    from idac.cli import main

    seen: dict[str, object] = {}
    discovered = [object()]

    def fake_list_gui_instances(*, timeout=None, warnings=None):
        seen["timeout"] = timeout
        seen["warnings"] = warnings
        return list(discovered)

    def fake_list_gui_discovered_instances(*, warnings=None):
        seen["discovery_warnings"] = warnings
        return list(discovered)

    def fake_send_request(request):
        seen["request_timeout"] = request.timeout
        seen["request_backend"] = request.backend
        return {"ok": True, "result": {"pattern": request.params["pattern"], "results": []}, "warnings": []}

    monkeypatch.setattr("idac.cli2.context.list_gui_discovered_instances", fake_list_gui_discovered_instances)
    monkeypatch.setattr("idac.cli2.context.list_gui_instances", fake_list_gui_instances)
    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["search", "bytes", "74 69 6e 79", "--segment", "__TEXT", "--timeout", "2.5", "--format", "json"])

    assert exit_code == 0
    assert seen == {
        "discovery_warnings": [],
        "timeout": 2.5,
        "warnings": [],
        "request_timeout": 2.5,
        "request_backend": "gui",
    }
    assert capsys.readouterr().err == ""


def test_required_timeout_commands_report_gui_autodiscovery_timeout(monkeypatch, capsys) -> None:
    from idac.cli import main

    monkeypatch.setattr("idac.cli2.context.list_gui_discovered_instances", lambda warnings=None: [object()])

    def fake_list_gui_instances(*, timeout=None, warnings=None):
        assert timeout == 2.5
        assert warnings is not None
        warnings.append("Failed to contact IDA GUI bridge pid 1234 at /tmp/idac-bridge-1234.sock: timed out")
        return []

    monkeypatch.setattr("idac.cli2.context.list_gui_instances", fake_list_gui_instances)

    exit_code = main(["search", "bytes", "74 69 6e 79", "--segment", "__TEXT", "--timeout", "2.5"])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "IDA GUI autodiscovery timed out" in err
    assert "increase --timeout" in err
    assert "timed out" in err


def test_required_timeout_commands_do_not_auto_select_after_timeout_pruned_discovery(monkeypatch, capsys) -> None:
    from idac.cli import main

    monkeypatch.setattr("idac.cli2.context.list_gui_discovered_instances", lambda warnings=None: [object(), object()])

    def fake_list_gui_instances(*, timeout=None, warnings=None):
        assert timeout == 2.5
        assert warnings is not None
        warnings.append("Failed to contact IDA GUI bridge pid 2222 at /tmp/idac-bridge-2222.sock: timed out")
        return [object()]

    def fail_send_request(request):
        raise AssertionError("command should not auto-select a GUI target after timeout-pruned discovery")

    monkeypatch.setattr("idac.cli2.context.list_gui_instances", fake_list_gui_instances)
    monkeypatch.setattr("idac.cli2.commands.common.send_request", fail_send_request)

    exit_code = main(["search", "bytes", "74 69 6e 79", "--segment", "__TEXT", "--timeout", "2.5"])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "autodiscovery is ambiguous" in err
    assert "pass an explicit context" in err
    assert "timed out" in err


def test_gui_backend_rejects_missing_timeout_for_strings() -> None:
    with pytest.raises(ValueError, match=r"operation `strings` requires a request timeout"):
        GuiBackend().send(RequestEnvelope(op="strings", backend="gui"))


def test_idalib_backend_rejects_missing_timeout_for_search_bytes() -> None:
    with pytest.raises(ValueError, match=r"operation `search_bytes` requires a request timeout"):
        IdaLibBackend().send(RequestEnvelope(op="search_bytes", backend="idalib", database="fixture.i64"))


def test_idalib_backend_forwards_timeout(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "idac-idalib-1234.sock",
        registry_path=tmp_path / "idac-idalib-1234.json",
        database_path=str(tmp_path / "fixture.i64"),
        started_at=None,
        meta={},
    )

    def fake_socket_request(socket_path, payload, *, timeout):
        seen["socket_path"] = socket_path
        seen["timeout"] = timeout
        seen["payload"] = payload
        return {
            "version": WIRE_PROTOCOL_VERSION,
            "id": None,
            "ok": True,
            "result": None,
            "error": None,
            "backend": "idalib",
            "warnings": [],
        }

    monkeypatch.setattr(
        "idac.transport.idalib._ensure_instance_for_database",
        lambda database_path, *, timeout, run_auto_analysis, start_if_missing: (instance, True),
    )
    monkeypatch.setattr("idac.transport.idalib._socket_request", fake_socket_request)

    response = IdaLibBackend().send(
        RequestEnvelope(op="database_info", backend="idalib", database="fixture.i64", timeout=1.5)
    )

    assert seen["socket_path"] == instance.socket_path
    assert seen["timeout"] == 1.5
    assert seen["payload"] == {"version": 1, "op": "database_info", "params": {}}
    assert response["ok"] is True


def test_idalib_backend_uses_blocking_socket_by_default(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "idac-idalib-1234.sock",
        registry_path=tmp_path / "idac-idalib-1234.json",
        database_path=str(tmp_path / "fixture.i64"),
        started_at=None,
        meta={},
    )

    def fake_socket_request(socket_path, payload, *, timeout):
        seen["socket_path"] = socket_path
        seen["timeout"] = timeout
        seen["payload"] = payload
        return {
            "version": WIRE_PROTOCOL_VERSION,
            "id": None,
            "ok": True,
            "result": None,
            "error": None,
            "backend": "idalib",
            "warnings": [],
        }

    monkeypatch.setattr(
        "idac.transport.idalib._ensure_instance_for_database",
        lambda database_path, *, timeout, run_auto_analysis, start_if_missing: (instance, True),
    )
    monkeypatch.setattr("idac.transport.idalib._socket_request", fake_socket_request)

    response = IdaLibBackend().send(RequestEnvelope(op="database_info", backend="idalib", database="fixture.i64"))

    assert seen["socket_path"] == instance.socket_path
    assert seen["timeout"] is None
    assert seen["payload"] == {"version": 1, "op": "database_info", "params": {}}
    assert response["ok"] is True


def test_idalib_existing_instance_probe_honors_blocking_mode(monkeypatch, tmp_path: Path) -> None:
    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "idac-idalib-1234.sock",
        registry_path=tmp_path / "idac-idalib-1234.json",
        database_path=str(tmp_path / "fixture.i64"),
        started_at=None,
        meta={},
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(idalib, "_find_instance_for_database", lambda database_path: instance)

    def fake_probe(instance_arg, *, timeout, purge_on_failure=True):
        assert instance_arg is instance
        seen["timeout"] = timeout
        seen["purge_on_failure"] = purge_on_failure
        return True

    monkeypatch.setattr(idalib, "_probe_instance", fake_probe)

    found, already_open = idalib._ensure_instance_for_database(
        str(tmp_path / "fixture.i64"),
        timeout=None,
        run_auto_analysis=True,
        start_if_missing=True,
    )

    assert found is instance
    assert already_open is True
    assert seen == {"timeout": None, "purge_on_failure": True}


def test_idalib_probe_timeout_does_not_purge_instance_files(monkeypatch, tmp_path: Path) -> None:
    registry_path = tmp_path / "idac-idalib-1234.json"
    socket_path = tmp_path / "idac-idalib-1234.sock"
    registry_path.write_text("{}", encoding="utf-8")
    socket_path.write_text("", encoding="utf-8")
    instance = IdaLibInstance(
        pid=1234,
        socket_path=socket_path,
        registry_path=registry_path,
        database_path=str(tmp_path / "fixture.i64"),
        started_at=None,
        meta={},
    )

    def fake_socket_request(socket_path_arg, payload, *, timeout):
        raise socket.timeout()

    monkeypatch.setattr(idalib, "_socket_request", fake_socket_request)

    with pytest.raises(socket.timeout):
        idalib._probe_instance(instance, timeout=0.25)

    assert registry_path.exists()
    assert socket_path.exists()


def test_idalib_daemon_startup_uses_nonblocking_stderr_log(monkeypatch, tmp_path: Path) -> None:
    class FakeStderrLog:
        closed = False

        def seek(self, _offset):
            raise AssertionError("startup log should not be read after successful startup")

        def read(self):
            raise AssertionError("startup log should not be read after successful startup")

        def close(self):
            self.closed = True

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            self.close()
            return False

    class FakeProc:
        pid = 1234

        def poll(self):
            return None

    database_path = str(tmp_path / "fixture.i64")
    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "idac-idalib-1234.sock",
        registry_path=tmp_path / "idac-idalib-1234.json",
        database_path=database_path,
        started_at=None,
        meta={},
    )
    stderr_log = FakeStderrLog()
    seen: dict[str, object] = {}

    def fake_popen(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["stderr"] = kwargs["stderr"]
        return FakeProc()

    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib.tempfile, "TemporaryFile", lambda *args, **kwargs: stderr_log)
    monkeypatch.setattr(idalib.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(idalib, "idalib_registry_path", lambda pid: tmp_path / f"idac-idalib-{pid}.json")
    monkeypatch.setattr(idalib, "_instance_from_registry", lambda path: instance)
    monkeypatch.setattr(idalib, "_probe_instance", lambda instance_arg, *, timeout, purge_on_failure: True)

    started = idalib._start_daemon_for_database(database_path, probe_timeout=0.25, run_auto_analysis=True)

    assert started is instance
    assert seen["stderr"] is stderr_log
    assert stderr_log.closed is True


def test_idalib_backend_reports_timeout(monkeypatch, tmp_path: Path) -> None:
    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "idac-idalib-1234.sock",
        registry_path=tmp_path / "idac-idalib-1234.json",
        database_path=str(tmp_path / "fixture.i64"),
        started_at=None,
        meta={},
    )

    def fake_socket_request(socket_path, payload, *, timeout):
        raise socket.timeout()

    monkeypatch.setattr(
        "idac.transport.idalib._ensure_instance_for_database",
        lambda database_path, *, timeout, run_auto_analysis, start_if_missing: (instance, True),
    )
    monkeypatch.setattr("idac.transport.idalib._socket_request", fake_socket_request)

    with pytest.raises(RuntimeError, match=r"idalib request timed out after 0.25s: database_info"):
        IdaLibBackend().send(
            RequestEnvelope(op="database_info", backend="idalib", database="fixture.i64", timeout=0.25)
        )


def test_gui_target_list_forwards_timeout(monkeypatch, tmp_path) -> None:
    instance = BridgeInstance(
        pid=1234,
        socket_path=tmp_path / "idac-bridge-1234.sock",
        registry_path=tmp_path / "idac-bridge-1234.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )
    seen: list[float | None] = []

    monkeypatch.setattr("idac.transport.gui.list_instances", lambda timeout=None, warnings=None: [instance])

    def fake_send(instance_arg, request, *, connect_retries=4):
        assert instance_arg is instance
        seen.append(request.timeout)
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

    monkeypatch.setattr("idac.transport.gui._send_request_to_instance", fake_send)

    response = GuiBackend().send(RequestEnvelope(op="list_targets", backend="gui", timeout=2.75))

    assert response["ok"] is True
    assert seen == [2.75]


def test_gui_target_list_uses_blocking_requests_by_default(monkeypatch, tmp_path) -> None:
    instance = BridgeInstance(
        pid=1234,
        socket_path=tmp_path / "idac-bridge-1234.sock",
        registry_path=tmp_path / "idac-bridge-1234.json",
        plugin_name="idac_bridge",
        plugin_version=VERSION,
        started_at=None,
        meta={},
    )
    seen: list[float | None] = []

    monkeypatch.setattr("idac.transport.gui.list_instances", lambda timeout=None, warnings=None: [instance])

    def fake_send(instance_arg, request, *, connect_retries=4):
        assert instance_arg is instance
        seen.append(request.timeout)
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

    monkeypatch.setattr("idac.transport.gui._send_request_to_instance", fake_send)

    response = GuiBackend().send(RequestEnvelope(op="list_targets", backend="gui"))

    assert response["ok"] is True
    assert seen == [None]


def test_gui_backend_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        GuiBackend().send(RequestEnvelope(op="list_targets", backend="gui", timeout=0))


def test_send_request_wraps_backend_runtime_errors(monkeypatch) -> None:
    class FakeBackend:
        def send(self, request):
            raise RuntimeError(f"boom: {request.op}")

    monkeypatch.setattr("idac.transport.get_backend", lambda name: FakeBackend())

    with pytest.raises(BackendError, match=r"boom: database_info"):
        send_request(RequestEnvelope(op="database_info", backend="gui"))
