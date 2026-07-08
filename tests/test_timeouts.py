from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
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

    def fake_probe(instance_arg, *, timeout):
        assert instance_arg is instance
        seen["timeout"] = timeout
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
    assert seen == {"timeout": None}


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


def test_idalib_probe_timeout_treats_busy_daemon_as_reachable_without_resend(monkeypatch) -> None:
    # Real _socket_request against a real Unix socket. The server accepts and
    # reads each request but never replies, so the probe times out. A daemon
    # that accepts the connection is alive-but-busy: the probe must return True
    # (reachable), never purge, and never resend. The server keeps draining so a
    # buggy resend would be counted.
    monkeypatch.setattr(idalib, "IDALIB_PROBE_TIMEOUT_CAP", 0.25)
    with tempfile.TemporaryDirectory(prefix="idac-timeout-", dir="/tmp") as tmp:
        tmp_path = Path(tmp)
        registry_path = tmp_path / "idac-idalib-1.json"
        registry_path.write_text("{}", encoding="utf-8")
        socket_path = tmp_path / "idac-idalib-1.sock"

        stop = threading.Event()
        received: list[bytes] = []
        held: list[socket.socket] = []
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(8)
        server.settimeout(0.05)

        def serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                held.append(conn)
                conn.settimeout(1.0)
                chunks: list[bytes] = []
                try:
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        chunks.append(data)
                except (TimeoutError, OSError):
                    pass
                if chunks:
                    received.append(b"".join(chunks))
                # Deliberately do not reply or close: the client blocks in recv
                # until its own timeout fires.

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        instance = IdaLibInstance(
            pid=os.getpid(),
            socket_path=socket_path,
            registry_path=registry_path,
            database_path=str(tmp_path / "fixture.i64"),
            started_at=None,
            meta={},
        )
        try:
            # Blocking mode (timeout=None) must still be bounded by the probe cap
            # and return "reachable" rather than hang.
            assert idalib._probe_instance(instance, timeout=None) is True
        finally:
            stop.set()
            thread.join(timeout=5.0)
            for conn in held:
                conn.close()
            server.close()

        assert registry_path.exists()
        assert socket_path.exists()
        assert len(received) == 1
        assert json.loads(received[0])["op"] == "daemon_status"


def test_idalib_socket_request_does_not_resend_after_connection_reset() -> None:
    # The H2 hazard: the server reads the (possibly mutating) request, then
    # aborts the connection with RST. _socket_request must surface an error
    # without re-sending, because the daemon may already be executing it.
    with tempfile.TemporaryDirectory(prefix="idac-timeout-", dir="/tmp") as tmp:
        socket_path = Path(tmp) / "idac-idalib-rst.sock"
        stop = threading.Event()
        received: list[bytes] = []
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(8)
        server.settimeout(0.05)

        def serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                with conn:
                    chunks: list[bytes] = []
                    try:
                        while True:
                            data = conn.recv(65536)
                            if not data:
                                break
                            chunks.append(data)
                    except OSError:
                        pass
                    if chunks:
                        received.append(b"".join(chunks))
                    # Force an RST rather than a clean close: SO_LINGER with a
                    # zero timeout makes close() send a reset.
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with pytest.raises(RuntimeError):
                idalib._socket_request(
                    socket_path,
                    {"version": WIRE_PROTOCOL_VERSION, "op": "python_exec", "params": {"code": "mutate()"}},
                    timeout=1.0,
                )
        finally:
            stop.set()
            thread.join(timeout=5.0)
            server.close()

        assert len(received) == 1


def _refused_socket_instance(tmp_path: Path, pid: int) -> IdaLibInstance:
    registry_path = tmp_path / "idac-idalib-2.json"
    registry_path.write_text("{}", encoding="utf-8")
    socket_path = tmp_path / "idac-idalib-2.sock"
    # Bind then close so the socket file exists with no listener behind it.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.close()
    return IdaLibInstance(
        pid=pid,
        socket_path=socket_path,
        registry_path=registry_path,
        database_path=str(tmp_path / "fixture.i64"),
        started_at=None,
        meta={},
    )


def test_idalib_probe_refused_with_live_worker_pid_does_not_purge_instance_files(monkeypatch) -> None:
    # A live pid whose command line is the idalib worker, but whose socket
    # refuses the connection: a daemon shutting down or wedged. Its files must
    # survive so no second daemon opens the same database.
    monkeypatch.setattr(
        idalib,
        "pid_command_line",
        lambda pid: f"{sys.executable} -m idac.transport.idalib_server --database x.i64",
    )
    with tempfile.TemporaryDirectory(prefix="idac-timeout-", dir="/tmp") as tmp:
        tmp_path = Path(tmp)
        instance = _refused_socket_instance(tmp_path, os.getpid())

        with pytest.raises(RuntimeError, match="is not answering on its socket"):
            idalib._probe_instance(instance, timeout=0.25)

        assert instance.registry_path.exists()
        assert instance.socket_path.exists()


def test_idalib_probe_failure_with_recycled_foreign_pid_purges_instance_files(monkeypatch) -> None:
    # A live pid whose command line is NOT the idalib worker: the original
    # daemon died and its pid was recycled. Purge so a fresh daemon can start,
    # rather than wedging the database forever.
    monkeypatch.setattr(idalib, "pid_command_line", lambda pid: "/usr/bin/some-unrelated-process")
    with tempfile.TemporaryDirectory(prefix="idac-timeout-", dir="/tmp") as tmp:
        tmp_path = Path(tmp)
        instance = _refused_socket_instance(tmp_path, os.getpid())

        assert idalib._probe_instance(instance, timeout=0.25) is False

        assert not instance.registry_path.exists()
        assert not instance.socket_path.exists()


def test_idalib_probe_failure_with_dead_pid_purges_instance_files() -> None:
    with tempfile.TemporaryDirectory(prefix="idac-timeout-", dir="/tmp") as tmp:
        tmp_path = Path(tmp)
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        instance = _refused_socket_instance(tmp_path, proc.pid)

        assert idalib._probe_instance(instance, timeout=0.25) is False

        assert not instance.registry_path.exists()
        assert not instance.socket_path.exists()


def test_idalib_db_close_warns_when_daemon_died_uncleanly(monkeypatch, tmp_path: Path) -> None:
    # A registry survives for the database but no live daemon answers: the daemon
    # died without a clean close, so unsaved changes may be lost. db_close must
    # flag this rather than silently report a clean already-closed.
    database = str(tmp_path / "fixture.i64")
    registry_path = tmp_path / "idac-idalib-999999.json"
    registry_path.write_text(
        json.dumps({"pid": 999999, "socket_path": str(tmp_path / "x.sock"), "database_path": database}),
        encoding="utf-8",
    )
    monkeypatch.setattr(idalib, "idalib_registry_paths", lambda: [registry_path])
    monkeypatch.setattr(idalib, "list_instances", lambda: [])

    response = IdaLibBackend().send(RequestEnvelope(op="db_close", backend="idalib", database=database))

    assert response["ok"] is True
    assert response["result"]["already_closed"] is True
    assert response["result"]["unclean"] is True
    assert response["warnings"]
    assert "without a clean close" in response["warnings"][0]


def test_idalib_db_close_without_registry_is_clean_already_closed(monkeypatch, tmp_path: Path) -> None:
    database = str(tmp_path / "fixture.i64")
    monkeypatch.setattr(idalib, "idalib_registry_paths", lambda: [])
    monkeypatch.setattr(idalib, "list_instances", lambda: [])

    response = IdaLibBackend().send(RequestEnvelope(op="db_close", backend="idalib", database=database))

    assert response["ok"] is True
    assert response["result"]["already_closed"] is True
    assert "unclean" not in response["result"]
    assert response["warnings"] == []


def test_idalib_database_start_lock_is_exclusive(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib, "idalib_open_lock_path", lambda db: tmp_path / "open.lock")
    database = str(tmp_path / "fixture.i64")

    order: list[str] = []
    holding = threading.Event()
    release = threading.Event()
    second_acquired = threading.Event()

    def hold_first() -> None:
        with idalib._database_start_lock(database):
            order.append("first-acquired")
            holding.set()
            release.wait(timeout=5.0)
            order.append("first-releasing")

    def acquire_second() -> None:
        with idalib._database_start_lock(database):
            order.append("second-acquired")
            second_acquired.set()

    first = threading.Thread(target=hold_first)
    first.start()
    assert holding.wait(timeout=5.0)

    second = threading.Thread(target=acquire_second)
    second.start()
    # The second acquisition must block while the first holds the lock.
    assert not second_acquired.wait(timeout=0.3)
    release.set()
    assert second_acquired.wait(timeout=5.0)

    first.join(timeout=5.0)
    second.join(timeout=5.0)
    assert order == ["first-acquired", "first-releasing", "second-acquired"]


def test_idalib_ensure_instance_rechecks_under_lock_and_skips_double_start(monkeypatch, tmp_path: Path) -> None:
    # A daemon started by a racing process between the first lookup and the lock
    # must be reused, not double-started (which would fail with rc=4).
    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib, "idalib_open_lock_path", lambda db: tmp_path / "open.lock")
    database = str(tmp_path / "fixture.i64")
    instance = IdaLibInstance(
        pid=1234,
        socket_path=tmp_path / "s.sock",
        registry_path=tmp_path / "r.json",
        database_path=idalib.normalize_database_path(database),
        started_at=None,
        meta={},
    )

    finds = [None, instance]
    monkeypatch.setattr(idalib, "_find_instance_for_database", lambda db: finds.pop(0))
    monkeypatch.setattr(idalib, "_probe_instance", lambda inst, *, timeout: True)

    def no_start(*args, **kwargs):
        raise AssertionError("a second daemon must not be started under the lock")

    monkeypatch.setattr(idalib, "_start_daemon_for_database", no_start)

    found, already_open = idalib._ensure_instance_for_database(
        database,
        timeout=None,
        run_auto_analysis=True,
        start_if_missing=True,
    )

    assert found is instance
    assert already_open is True
    assert finds == []


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
        raise TimeoutError()

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


def test_idalib_daemon_startup_terminates_worker_on_keyboard_interrupt(monkeypatch, tmp_path: Path) -> None:
    # Ctrl-C during the readiness wait (KeyboardInterrupt is a BaseException,
    # not Exception) must still reap the spawned daemon so it does not linger
    # holding the database lock.
    class FakeProc:
        pid = 1234

        def __init__(self) -> None:
            self.terminated = False
            self.wait_timeouts: list[float] = []

        def terminate(self):
            self.terminated = True

        def wait(self, *, timeout):
            self.wait_timeouts.append(timeout)
            return 1

    proc = FakeProc()
    database_path = str(tmp_path / "fixture.i64")

    def fake_read_ready_payload(read_fd, *, timeout):
        os.close(read_fd)
        raise KeyboardInterrupt

    monkeypatch.setattr(idalib, "ensure_user_runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(idalib.subprocess, "Popen", lambda *args, **kwargs: proc)
    monkeypatch.setattr(idalib, "idalib_registry_path", lambda pid: tmp_path / f"idac-idalib-{pid}.json")
    monkeypatch.setattr(idalib, "_read_ready_payload", fake_read_ready_payload)

    with pytest.raises(KeyboardInterrupt):
        idalib._start_daemon_for_database(
            database_path,
            startup_timeout=120.0,
            run_auto_analysis=True,
        )

    assert proc.terminated is True


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
        raise TimeoutError()

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
