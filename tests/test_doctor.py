from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from idac import doctor


@pytest.fixture(autouse=True)
def agent_client_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep doctor tests independent of clients installed on the developer's machine."""

    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("hcli.lib.ida.find_current_ida_version", lambda: "9.4")
    return tmp_path


def _instance(record_id: str = "gui-123") -> SimpleNamespace:
    return SimpleNamespace(
        record_id=record_id,
        backend="gui",
        pid=123,
        port=4567,
        _token="secret",
        version=6,
        idb_path="/tmp/demo.i64",
        exe_path="/tmp/demo",
        managed=False,
        started_at=1234.5,
    )


def _discovered(state: str = "ready", *, record_id: str = "gui-123") -> SimpleNamespace:
    return SimpleNamespace(
        instance=_instance(record_id),
        state=SimpleNamespace(value=state),
        detail=None if state == "ready" else "unsupported protocol version 7; expected 6",
        registry_file="/private/registry.json",
    )


def _versions(distribution: str) -> str:
    return doctor.importlib.metadata.version(distribution)


def _hcli_success(command, **kwargs):
    payload = {
        "plugins": [
            {
                "name": "ida-nexus",
                "version": _versions("ida-nexus"),
                "installed": True,
                "kind": "installed",
            }
        ]
    }
    return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")


def _remote_environment(_instance, _timeout):
    return {
        "ida_nexus": _versions("ida-nexus"),
        "ida_domain": _versions("ida-domain"),
        "ida": "9.4",
        "python": "3.11.9",
    }


def test_doctor_reports_a_healthy_nexus_stack() -> None:
    def run_hcli(command, **kwargs):
        assert kwargs["timeout"] == 2.5
        return _hcli_success(command, **kwargs)

    def discover(timeout):
        assert timeout == 2.5
        return [_discovered()]

    def probe(instance, timeout):
        assert instance.record_id == "gui-123"
        assert timeout == 2.5
        return _remote_environment(instance, timeout)

    result = doctor.run_doctor(
        timeout=2.5,
        version_getter=_versions,
        runner=run_hcli,
        discover_databases_fn=discover,
        remote_probe_fn=probe,
    )

    assert result["healthy"] is True
    assert result["status"] == "ok"
    statuses = {(item["component"], item["name"]): item["status"] for item in result["checks"]}
    expected = {
        ("runtime", "python"): "ok",
        ("runtime", "ida_nexus"): "ok",
        ("runtime", "ida_domain"): "ok",
        ("runtime", "ida_hcli"): "ok",
        ("runtime", "ida"): "ok",
        ("gui", "plugin"): "ok",
        ("nexus", "discovery"): "ok",
        ("nexus", "remote_environment"): "ok",
    }
    assert expected.items() <= statuses.items()


@pytest.mark.parametrize("version,supported", [("9.3", False), ("9.4", True), ("10.0", True)])
def test_doctor_checks_local_ida_without_a_running_database(monkeypatch, version: str, supported: bool) -> None:
    monkeypatch.setattr("hcli.lib.ida.find_current_ida_version", lambda: version)
    result = doctor.run_doctor(runner=_hcli_success, discover_databases_fn=lambda _timeout: [])
    check = next(item for item in result["checks"] if (item["component"], item["name"]) == ("runtime", "ida"))
    assert check["status"] == ("ok" if supported else "error")
    assert check["details"]["installed"] == version
    assert result["healthy"] is supported
    if not supported:
        assert "requires IDA 9.4 or newer" in check["summary"]


@pytest.mark.parametrize("version", [None, "invalid"])
def test_doctor_reports_unavailable_local_ida_version(monkeypatch, version) -> None:
    def detect():
        if version is None:
            raise RuntimeError("no IDA installation configured")
        return version

    monkeypatch.setattr("hcli.lib.ida.find_current_ida_version", detect)
    result = doctor.run_doctor(runner=_hcli_success, discover_databases_fn=lambda _timeout: [])
    check = next(item for item in result["checks"] if (item["component"], item["name"]) == ("runtime", "ida"))
    assert check["status"] == "error"
    assert "could not determine" in check["summary"]
    assert result["healthy"] is False


@pytest.mark.parametrize("client", ["codex", "claude"])
@pytest.mark.parametrize("matching", [True, False])
def test_doctor_compares_installed_skill_and_cli_versions(agent_client_path: Path, client: str, matching: bool) -> None:
    executable = agent_client_path / client
    executable.touch(mode=0o755)
    cli_version = _versions("idac")
    installed = cli_version if matching else "0.1.0"
    identity_key = "pluginId" if client == "codex" else "id"
    entries = [
        {identity_key: "other@marketplace", "version": "0.1.0"},
        {identity_key: "idac@marketplace", "version": installed, "enabled": True},
    ]
    payload = (
        {"installed": entries, "available": [{"pluginId": "idac@unused", "version": "0.0.1"}]}
        if client == "codex"
        else entries
    )

    def run(command, **kwargs):
        if command[0] == client:
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        return _hcli_success(command, **kwargs)

    result = doctor.run_doctor(
        runner=run,
        discover_databases_fn=lambda _timeout: [_discovered()],
        remote_probe_fn=_remote_environment,
    )

    assert result["healthy"] is True
    assert result["status"] == ("ok" if matching else "warn")
    agent_checks = [item for item in result["checks"] if item["component"] == "agent"]
    assert len(agent_checks) == 1
    check = agent_checks[0]
    assert check["status"] == ("ok" if matching else "warn")
    assert check["details"]["installed"] == installed
    assert check["details"]["expected"] == cli_version
    assert installed in check["summary"]
    assert cli_version in check["summary"]


@pytest.mark.parametrize("inventory", ["empty", "malformed", "failed", "timeout"])
def test_doctor_keeps_optional_skill_inventory_failures_nonfatal(agent_client_path: Path, inventory: str) -> None:
    executable = agent_client_path / "codex"
    executable.touch(mode=0o755)

    def run(command, **kwargs):
        if command[0] != "codex":
            return _hcli_success(command, **kwargs)
        if inventory == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        if inventory == "failed":
            return subprocess.CompletedProcess(command, 1, "", "plugin list failed")
        stdout = json.dumps({"installed": []}) if inventory == "empty" else "not JSON"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    result = doctor.run_doctor(
        runner=run,
        discover_databases_fn=lambda _timeout: [_discovered()],
        remote_probe_fn=_remote_environment,
    )

    assert result["healthy"] is True
    if inventory == "empty":
        assert result["status"] == "ok"
    else:
        check = next(item for item in result["checks"] if item["component"] == "agent")
        assert check["status"] == "warn"
        assert "could not check" in check["summary"]


@pytest.mark.parametrize("timeout,expected", [(None, 2.0), (0.5, 0.5), (4.0, 4.0)])
def test_doctor_bounds_optional_agent_inventory(agent_client_path: Path, timeout, expected: float) -> None:
    (agent_client_path / "codex").touch(mode=0o755)

    def run(command, **kwargs):
        if command[0] == "codex":
            assert kwargs["timeout"] == expected
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return _hcli_success(command, **kwargs)

    result = doctor.run_doctor(timeout=timeout, runner=run, discover_databases_fn=lambda _timeout: [])
    assert result["healthy"] is True
    check = next(item for item in result["checks"] if item["component"] == "agent")
    assert check["status"] == "warn"


def test_doctor_reports_blocked_protocol_without_probing() -> None:
    result = doctor.run_doctor(
        version_getter=_versions,
        runner=_hcli_success,
        discover_databases_fn=lambda _timeout: [_discovered("blocked")],
        remote_probe_fn=lambda _instance, _timeout: (_ for _ in ()).throw(AssertionError("must not probe")),
    )

    assert result["healthy"] is False
    discovery = next(item for item in result["checks"] if item["name"] == "discovery")
    assert discovery["status"] == "error"
    serialized = json.dumps(discovery)
    assert "secret" not in serialized
    assert "registry.json" not in serialized
    assert '"port"' not in serialized
    assert "unsupported protocol version 7" in serialized


def test_doctor_warns_when_no_database_is_running() -> None:
    result = doctor.run_doctor(
        version_getter=_versions,
        runner=_hcli_success,
        discover_databases_fn=lambda _timeout: [],
        remote_probe_fn=lambda _instance, _timeout: (_ for _ in ()).throw(AssertionError("must not probe")),
    )

    assert result["healthy"] is True
    assert result["status"] == "warn"
    discovery = next(item for item in result["checks"] if item["name"] == "discovery")
    assert discovery["status"] == "warn"
    assert "no running" in discovery["summary"].lower()


def test_doctor_reports_missing_or_malformed_hcli_status() -> None:
    cases = [
        (
            subprocess.CompletedProcess(
                [],
                1,
                '{"plugins":[{"name":"ida-nexus","installed":false}]}',
                "not installed",
            ),
            "not installed",
        ),
        (
            subprocess.CompletedProcess([], 1, "", "configured hcli default IDA installation does not exist"),
            "configured hcli default ida installation does not exist",
        ),
    ]

    for completed, diagnostic in cases:
        result = doctor.run_doctor(
            version_getter=_versions,
            runner=lambda _command, _completed=completed, **_kwargs: _completed,
            discover_databases_fn=lambda _timeout: [],
        )

        plugin = next(item for item in result["checks"] if item["component"] == "gui")
        assert plugin["status"] == "error"
        assert diagnostic in plugin["summary"].lower()


def test_doctor_rejects_old_remote_python_and_ida() -> None:
    result = doctor.run_doctor(
        version_getter=_versions,
        runner=_hcli_success,
        discover_databases_fn=lambda _timeout: [_discovered()],
        remote_probe_fn=lambda _instance, _timeout: {
            "ida_nexus": _versions("ida-nexus"),
            "ida_domain": _versions("ida-domain"),
            "ida": "9.3",
            "python": "3.10.14",
        },
    )

    assert result["healthy"] is False
    remote = next(item for item in result["checks"] if item["name"] == "remote_environment")
    assert remote["status"] == "error"
    mismatches = " ".join(remote["details"]["mismatches"])
    assert "IDA" in mismatches
    assert "Python" in mismatches


def test_doctor_default_probe_releases_the_remote_database_handle(monkeypatch) -> None:
    calls: dict[str, object] = {}
    discovered = _discovered()

    class Handle:
        @classmethod
        def attach(cls, selected, *, keepalive):
            calls["selected"] = selected
            return cls()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            calls["closed"] = True

        def execute_python(self, code, **kwargs):
            calls["executed"] = True
            return {
                "result": _remote_environment(discovered.instance, kwargs["timeout"]),
                "stdout": "",
                "stderr": "",
            }

    monkeypatch.setitem(sys.modules, "ida_nexus", SimpleNamespace(DatabaseHandle=Handle))

    result = doctor.run_doctor(
        timeout=4.0,
        version_getter=_versions,
        runner=_hcli_success,
        discover_databases_fn=lambda _timeout: [discovered],
    )

    assert result["healthy"] is True
    assert calls["selected"].record_id == discovered.instance.record_id
    assert calls["executed"] is True
    assert calls["closed"] is True
