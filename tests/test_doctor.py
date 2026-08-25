from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

from idac import doctor


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
    return {
        "ida-nexus": doctor.IDA_NEXUS_VERSION,
        "ida-domain": doctor.IDA_DOMAIN_VERSION,
        "ida-hcli": doctor.IDA_HCLI_VERSION,
    }[distribution]


def _hcli_success(command, **kwargs):
    payload = {
        "plugins": [
            {
                "name": "ida-nexus",
                "version": doctor.IDA_NEXUS_VERSION,
                "installed": True,
                "kind": "installed",
            }
        ]
    }
    return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")


def _remote_environment(_instance, _timeout):
    return {
        "ida_nexus": doctor.IDA_NEXUS_VERSION,
        "ida_domain": doctor.IDA_DOMAIN_VERSION,
        "ida": "9.4",
        "python": "3.11.9",
    }


def test_doctor_reports_an_exact_healthy_nexus_stack() -> None:
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
        ("gui", "plugin"): "ok",
        ("nexus", "discovery"): "ok",
        ("nexus", "remote_environment"): "ok",
    }
    assert expected.items() <= statuses.items()


def test_doctor_fails_closed_before_discovery_on_local_version_mismatch() -> None:
    def mismatched_version(distribution: str) -> str:
        return "0.8.0" if distribution == "ida-nexus" else _versions(distribution)

    result = doctor.run_doctor(
        version_getter=mismatched_version,
        runner=_hcli_success,
        discover_databases_fn=lambda _timeout: (_ for _ in ()).throw(AssertionError("must not discover")),
        remote_probe_fn=lambda _instance, _timeout: (_ for _ in ()).throw(AssertionError("must not probe")),
    )

    assert result["healthy"] is False
    assert result["status"] == "error"
    errors = [item for item in result["checks"] if item["status"] == "error"]
    assert {(item["component"], item["name"]) for item in errors} >= {
        ("runtime", "ida_nexus"),
        ("nexus", "discovery"),
    }
    discovery = next(item for item in errors if item["name"] == "discovery")
    serialized = json.dumps(discovery)
    assert "secret" not in serialized
    assert "registry.json" not in serialized
    assert '"port"' not in serialized
    assert "local ida-nexus stack is unsupported" in serialized


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
            subprocess.CompletedProcess([], 0, "not json", ""),
            "invalid",
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
            "ida_nexus": doctor.IDA_NEXUS_VERSION,
            "ida_domain": doctor.IDA_DOMAIN_VERSION,
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
    assert calls["selected"] is discovered.instance
    assert calls["executed"] is True
    assert calls["closed"] is True
