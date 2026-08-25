from __future__ import annotations

import importlib.metadata
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from typing import Any

from .compatibility import (
    IDA_DOMAIN_VERSION,
    IDA_HCLI_VERSION,
    IDA_NEXUS_VERSION,
    MINIMUM_PYTHON_VERSION,
    REMOTE_ENVIRONMENT_CODE,
    compatibility_mismatches,
)
from .nexus import KEEPALIVE_SECONDS, _target_row

HCLI_STATUS_COMMAND = (
    sys.executable,
    "-m",
    "hcli",
    "plugin",
    "status",
    "ida-nexus",
    "--skip-upgrade-check",
    "--json",
)

VersionGetter = Callable[[str], str]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
DiscoverDatabases = Callable[[float], Sequence[Any]]
RemoteProbe = Callable[[Any, float | None], dict[str, Any]]


def _check(status: str, component: str, name: str, summary: str, **details: Any) -> dict[str, Any]:
    return {
        "status": status,
        "component": component,
        "name": name,
        "summary": summary,
        "details": details,
    }


def _python_check() -> dict[str, Any]:
    current = sys.version_info
    current_tuple = (int(current.major), int(current.minor))
    required = ".".join(str(part) for part in MINIMUM_PYTHON_VERSION)
    version = ".".join(str(part) for part in (current.major, current.minor, current.micro))
    if current_tuple < MINIMUM_PYTHON_VERSION:
        return _check(
            "error",
            "runtime",
            "python",
            f"Python {required} or newer is required",
            version=version,
            required=f">={required}",
            executable=sys.executable,
        )
    return _check(
        "ok",
        "runtime",
        "python",
        "Python version is supported",
        version=version,
        required=f">={required}",
        executable=sys.executable,
    )


def _package_check(distribution: str, expected: str, version_getter: VersionGetter) -> dict[str, Any]:
    name = distribution.replace("-", "_")
    try:
        installed = version_getter(distribution)
    except importlib.metadata.PackageNotFoundError:
        return _check(
            "error",
            "runtime",
            name,
            f"{distribution} is not installed",
            expected=expected,
            installed=None,
        )
    except Exception as exc:
        return _check(
            "error",
            "runtime",
            name,
            f"failed to inspect {distribution}: {exc}",
            expected=expected,
            installed=None,
        )

    if installed != expected:
        return _check(
            "error",
            "runtime",
            name,
            f"{distribution} version does not match the supported stack",
            expected=expected,
            installed=installed,
        )
    return _check(
        "ok",
        "runtime",
        name,
        f"{distribution} version matches the supported stack",
        expected=expected,
        installed=installed,
    )


def _run_hcli_status(
    *,
    timeout: float | None,
    runner: CommandRunner,
) -> dict[str, Any]:
    try:
        process = runner(
            list(HCLI_STATUS_COMMAND),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return _check(
            "error",
            "gui",
            "plugin",
            "timed out while checking the ida-nexus plugin with ida-hcli",
            expected=IDA_NEXUS_VERSION,
            command=list(HCLI_STATUS_COMMAND),
            timeout=timeout,
        )
    except OSError as exc:
        return _check(
            "error",
            "gui",
            "plugin",
            f"failed to run the pinned ida-hcli status command: {exc}",
            expected=IDA_NEXUS_VERSION,
            command=list(HCLI_STATUS_COMMAND),
        )

    try:
        payload = json.loads(process.stdout)
    except (TypeError, json.JSONDecodeError):
        return _check(
            "error",
            "gui",
            "plugin",
            "ida-hcli returned invalid plugin status JSON",
            expected=IDA_NEXUS_VERSION,
            returncode=process.returncode,
            stdout=(process.stdout or "")[:4000],
            stderr=(process.stderr or "")[:4000],
        )

    plugins = payload.get("plugins") if isinstance(payload, dict) else None
    entry = next(
        (item for item in plugins or () if isinstance(item, dict) and item.get("name") == "ida-nexus"),
        None,
    )
    installed = entry.get("version") if isinstance(entry, dict) and entry.get("installed") is True else None
    if process.returncode != 0 or installed is None:
        return _check(
            "error",
            "gui",
            "plugin",
            "ida-nexus is not installed through ida-hcli",
            expected=IDA_NEXUS_VERSION,
            installed=installed,
            returncode=process.returncode,
            stderr=(process.stderr or "")[:4000],
        )
    if installed != IDA_NEXUS_VERSION:
        return _check(
            "error",
            "gui",
            "plugin",
            "installed ida-nexus plugin version does not match the supported stack",
            expected=IDA_NEXUS_VERSION,
            installed=installed,
        )
    return _check(
        "ok",
        "gui",
        "plugin",
        "installed ida-nexus plugin version matches the supported stack",
        expected=IDA_NEXUS_VERSION,
        installed=installed,
    )


def _discover_check(
    *,
    timeout: float,
    discover_databases_fn: DiscoverDatabases,
) -> tuple[dict[str, Any], list[Any]]:
    try:
        discovered = list(discover_databases_fn(timeout))
    except Exception as exc:
        return (
            _check(
                "error",
                "nexus",
                "discovery",
                f"Nexus discovery failed: {exc}",
                timeout=timeout,
            ),
            [],
        )

    rows = [_target_row(item) for item in discovered]
    ready = [item for item in discovered if item.state.value == "ready"]
    unavailable_count = len(discovered) - len(ready)
    if not discovered:
        return (
            _check(
                "warn",
                "nexus",
                "discovery",
                "no running Nexus database instances found",
                timeout=timeout,
                ready_count=0,
                unavailable_count=0,
                instances=[],
            ),
            [],
        )
    if not ready:
        return (
            _check(
                "error",
                "nexus",
                "discovery",
                "Nexus instances were found, but none are ready",
                timeout=timeout,
                ready_count=0,
                unavailable_count=unavailable_count,
                instances=rows,
            ),
            [],
        )
    status = "warn" if unavailable_count else "ok"
    summary = f"found {len(ready)} ready Nexus database instance(s)"
    if unavailable_count:
        summary += f" and {unavailable_count} unavailable instance(s)"
    return (
        _check(
            status,
            "nexus",
            "discovery",
            summary,
            timeout=timeout,
            ready_count=len(ready),
            unavailable_count=unavailable_count,
            instances=rows,
        ),
        ready,
    )


def _default_remote_probe(instance: Any, timeout: float | None) -> dict[str, Any]:
    from ida_nexus import DatabaseHandle

    with DatabaseHandle.attach(instance, keepalive=KEEPALIVE_SECONDS) as handle:
        execution = handle.execute_python(
            REMOTE_ENVIRONMENT_CODE,
            timeout=timeout,
            operation_label="idac: doctor",
            persist_globals=False,
            filename="<idac-doctor>",
        )
    result = execution.get("result") if isinstance(execution, dict) else None
    if not isinstance(result, dict):
        raise ValueError("remote environment probe returned an invalid result")
    return result


def _remote_checks(
    ready: Sequence[Any],
    *,
    timeout: float | None,
    remote_probe_fn: RemoteProbe,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for discovered in ready:
        instance = discovered.instance
        identity = {
            "record_id": instance.record_id,
            "backend": instance.backend,
            "pid": instance.pid,
            "idb_path": instance.idb_path,
            "exe_path": instance.exe_path,
        }
        try:
            environment = remote_probe_fn(instance, timeout)
        except Exception as exc:
            checks.append(
                _check(
                    "error",
                    "nexus",
                    "remote_environment",
                    f"failed to probe Nexus instance {instance.record_id}: {exc}",
                    **identity,
                )
            )
            continue

        mismatches = compatibility_mismatches(environment)
        if mismatches:
            checks.append(
                _check(
                    "error",
                    "nexus",
                    "remote_environment",
                    f"Nexus instance {instance.record_id} does not match the supported stack",
                    **identity,
                    environment=environment,
                    mismatches=mismatches,
                )
            )
            continue
        checks.append(
            _check(
                "ok",
                "nexus",
                "remote_environment",
                f"Nexus instance {instance.record_id} matches the supported stack",
                **identity,
                environment=environment,
            )
        )
    return checks


def run_doctor(
    *,
    timeout: float | None = None,
    version_getter: VersionGetter = importlib.metadata.version,
    runner: CommandRunner = subprocess.run,
    discover_databases_fn: DiscoverDatabases | None = None,
    remote_probe_fn: RemoteProbe | None = None,
) -> dict[str, Any]:
    """Inspect the exact local Nexus stack without changing any installation."""

    discovery_timeout = 1.0 if timeout is None else timeout
    nexus_package = _package_check("ida-nexus", IDA_NEXUS_VERSION, version_getter)
    domain_package = _package_check("ida-domain", IDA_DOMAIN_VERSION, version_getter)
    hcli_package = _package_check("ida-hcli", IDA_HCLI_VERSION, version_getter)
    checks = [
        _python_check(),
        nexus_package,
        domain_package,
        hcli_package,
        _run_hcli_status(timeout=timeout, runner=runner),
    ]
    local_stack_supported = nexus_package["status"] == "ok" and domain_package["status"] == "ok"

    if not local_stack_supported:
        discovery = _check(
            "error",
            "nexus",
            "discovery",
            "skipped Nexus discovery because the local ida-nexus stack is unsupported",
            timeout=discovery_timeout,
        )
        ready: list[Any] = []
    else:
        if discover_databases_fn is None:
            try:
                from ida_nexus import discover_databases
            except Exception as exc:
                discovery = _check(
                    "error",
                    "nexus",
                    "discovery",
                    f"failed to import the public ida-nexus discovery API: {exc}",
                    timeout=discovery_timeout,
                )
                ready = []
            else:
                discover_databases_fn = discover_databases
        if discover_databases_fn is not None:
            discovery, ready = _discover_check(
                timeout=discovery_timeout,
                discover_databases_fn=discover_databases_fn,
            )
    checks.append(discovery)
    checks.extend(
        _remote_checks(
            ready,
            timeout=timeout,
            remote_probe_fn=remote_probe_fn if remote_probe_fn is not None else _default_remote_probe,
        )
    )

    status_order = {"ok": 0, "warn": 1, "error": 2}
    overall_status = max(
        (str(item.get("status", "error")) for item in checks),
        key=lambda status: status_order.get(status, 99),
        default="ok",
    )
    return {
        "healthy": overall_status in {"ok", "warn"},
        "status": overall_status,
        "check_count": len(checks),
        "checks": checks,
    }
