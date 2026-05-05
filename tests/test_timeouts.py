from __future__ import annotations

import os
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
    monkeypatch.setattr("idac.cli2.context.list_idalib_instances", lambda: [])
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
    monkeypatch.setattr("idac.cli2.context.list_idalib_instances", lambda: [])

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
    monkeypatch.setattr("idac.cli2.context.list_idalib_instances", lambda: [])

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


def test_idalib_new_instance_startup_uses_request_timeout(monkeypatch, tmp_path: Path) -> None:
    database_path = str(tmp_path / "fixture.i64")
    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "idac-idalib-1234.sock",
        registry_path=tmp_path / "idac-idalib-1234.json",
        database_path=database_path,
        started_at=None,
        meta={},
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(idalib, "_find_instance_for_database", lambda database_path_arg: None)

    def fake_start_daemon(database_path_arg, *, startup_timeout, run_auto_analysis):
        seen["database_path"] = database_path_arg
        seen["startup_timeout"] = startup_timeout
        seen["run_auto_analysis"] = run_auto_analysis
        return instance

    monkeypatch.setattr(idalib, "_start_daemon_for_database", fake_start_daemon)

    found, already_open = idalib._ensure_instance_for_database(
        database_path,
        timeout=120.0,
        run_auto_analysis=False,
        start_if_missing=True,
    )

    assert found is instance
    assert already_open is False
    assert seen == {
        "database_path": database_path,
        "startup_timeout": 120.0,
        "run_auto_analysis": False,
    }


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


def test_idalib_daemon_startup_uses_readiness_pipe(monkeypatch, tmp_path: Path) -> None:
    class FakeProc:
        pid = 1234

    database_path = str(tmp_path / "fixture.i64")
    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "idac-idalib-1234.sock",
        registry_path=tmp_path / "idac-idalib-1234.json",
        database_path=database_path,
        started_at=None,
        meta={},
    )
    proc = FakeProc()
    seen: dict[str, object] = {}

    def fake_popen(cmd, **kwargs):
        ready_fd = int(cmd[cmd.index("--ready-fd") + 1])
        seen["cmd"] = cmd
        seen["pass_fds"] = kwargs["pass_fds"]
        seen["ready_fd"] = ready_fd
        assert ready_fd in kwargs["pass_fds"]
        return proc

    def fake_read_ready_payload(read_fd, *, timeout):
        seen["read_fd"] = read_fd
        seen["timeout"] = timeout
        with pytest.raises(OSError):
            os.write(int(seen["ready_fd"]), b"parent closed this fd")
        os.close(read_fd)
        return {"ok": True}

    def fail_if_called(*args, **kwargs):
        raise AssertionError("startup readiness should not probe sockets")

    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(idalib, "idalib_registry_path", lambda pid: tmp_path / f"idac-idalib-{pid}.json")
    monkeypatch.setattr(idalib, "_read_ready_payload", fake_read_ready_payload)
    monkeypatch.setattr(idalib, "_instance_from_registry", lambda path: instance)
    monkeypatch.setattr(idalib, "_probe_instance", fail_if_called)

    started = idalib._start_daemon_for_database(
        database_path,
        startup_timeout=120.0,
        run_auto_analysis=True,
    )

    assert started is instance
    assert seen["timeout"] == 120.0
    assert "--ready-fd" in seen["cmd"]


def test_idalib_daemon_startup_retries_silent_first_import_exit(monkeypatch, tmp_path: Path) -> None:
    class FakeProc:
        def __init__(self, pid: int) -> None:
            self.pid = pid
            self.wait_timeouts: list[float] = []

        def wait(self, *, timeout):
            self.wait_timeouts.append(timeout)
            return 1

    database_path = str(tmp_path / "tiny")
    instance = IdaLibInstance(
        pid=2346,
        socket_path=tmp_path / "idac-idalib-2346.sock",
        registry_path=tmp_path / "idac-idalib-2346.json",
        database_path=database_path,
        started_at=None,
        meta={},
    )
    procs: list[FakeProc] = []
    read_attempts = 0

    def fake_popen(cmd, **kwargs):
        proc = FakeProc(2345 + len(procs))
        procs.append(proc)
        return proc

    def fake_read_ready_payload(read_fd, *, timeout):
        nonlocal read_attempts
        read_attempts += 1
        os.close(read_fd)
        if read_attempts == 1:
            raise EOFError("idalib daemon exited before reporting readiness")
        return {"ok": True}

    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(idalib, "idalib_registry_path", lambda pid: tmp_path / f"idac-idalib-{pid}.json")
    monkeypatch.setattr(idalib, "_read_ready_payload", fake_read_ready_payload)
    monkeypatch.setattr(idalib, "_instance_from_registry", lambda path: instance)

    started = idalib._start_daemon_for_database(
        database_path,
        startup_timeout=120.0,
        run_auto_analysis=True,
    )

    assert started is instance
    assert read_attempts == 2
    assert [proc.pid for proc in procs] == [2345, 2346]
    assert procs[0].wait_timeouts == [0.5]


def test_idalib_daemon_startup_timeout_terminates_worker(monkeypatch, tmp_path: Path) -> None:
    class FakeProc:
        pid = 1234

        def __init__(self) -> None:
            self.terminated = False
            self.killed = False
            self.wait_timeouts: list[float] = []

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

        def wait(self, *, timeout):
            self.wait_timeouts.append(timeout)
            return 1

    proc = FakeProc()
    database_path = str(tmp_path / "fixture.i64")
    seen: dict[str, object] = {}

    def fake_read_ready_payload(read_fd, *, timeout):
        seen["timeout"] = timeout
        os.close(read_fd)
        raise socket.timeout()

    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib.subprocess, "Popen", lambda *args, **kwargs: proc)
    monkeypatch.setattr(idalib, "idalib_registry_path", lambda pid: tmp_path / f"idac-idalib-{pid}.json")
    monkeypatch.setattr(idalib, "_read_ready_payload", fake_read_ready_payload)

    with pytest.raises(RuntimeError, match="timed out after 120s waiting for idalib daemon"):
        idalib._start_daemon_for_database(
            database_path,
            startup_timeout=120.0,
            run_auto_analysis=True,
        )

    assert seen["timeout"] == 120.0
    assert proc.terminated is True
    assert proc.killed is False
    assert proc.wait_timeouts == [5.0]


def test_idalib_daemon_startup_reads_stderr_when_worker_exits_before_readiness(monkeypatch, tmp_path: Path) -> None:
    class FakeStderrLog:
        closed = False

        def seek(self, _offset):
            pass

        def read(self):
            return "startup failed"

        def close(self):
            self.closed = True

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            self.close()
            return False

    class FakeProc:
        pid = 1234

        def wait(self, *, timeout):
            return 1

    database_path = str(tmp_path / "fixture.i64")
    stderr_log = FakeStderrLog()

    def fake_popen(cmd, **kwargs):
        return FakeProc()

    def fake_read_ready_payload(read_fd, *, timeout):
        os.close(read_fd)
        raise EOFError("closed")

    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib.tempfile, "TemporaryFile", lambda *args, **kwargs: stderr_log)
    monkeypatch.setattr(idalib.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(idalib, "idalib_registry_path", lambda pid: tmp_path / f"idac-idalib-{pid}.json")
    monkeypatch.setattr(idalib, "_read_ready_payload", fake_read_ready_payload)

    with pytest.raises(RuntimeError, match="startup failed"):
        idalib._start_daemon_for_database(database_path, startup_timeout=0.25, run_auto_analysis=True)

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
