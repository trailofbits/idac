from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

import pytest

_LIVE_GUI_ENV = "IDAC_RUN_LIVE_GUI_TESTS"


def pytest_collection_modifyitems(config, items) -> None:
    if os.environ.get(_LIVE_GUI_ENV) == "1":
        return
    skip_live = pytest.mark.skip(reason=f"set {_LIVE_GUI_ENV}=1 to run gui_live integration tests")
    for item in items:
        if "gui_live" in item.keywords:
            item.add_marker(skip_live)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return _repo_root() / "fixtures"


@pytest.fixture(scope="session")
def tiny_source(fixtures_dir: Path) -> Path:
    return fixtures_dir / "src" / "tiny.c"


@pytest.fixture(scope="session")
def tiny_binary(fixtures_dir: Path) -> Path:
    return fixtures_dir / "build" / "tiny"


@pytest.fixture(scope="session")
def tiny_stripped_binary(fixtures_dir: Path) -> Path:
    return fixtures_dir / "build" / "tiny.stripped"


@pytest.fixture(scope="session")
def tiny_database(fixtures_dir: Path) -> Path:
    return fixtures_dir / "idb" / "tiny.i64"


@pytest.fixture(scope="session")
def tiny_stripped_database(fixtures_dir: Path) -> Path:
    return fixtures_dir / "idb" / "tiny_stripped.i64"


@pytest.fixture(scope="session")
def handler_hierarchy_source(fixtures_dir: Path) -> Path:
    return fixtures_dir / "src" / "handler_hierarchy.cpp"


@pytest.fixture(scope="session")
def handler_hierarchy_types(fixtures_dir: Path) -> Path:
    return fixtures_dir / "src" / "handler_hierarchy.hpp"


@pytest.fixture(scope="session")
def handler_hierarchy_database(fixtures_dir: Path) -> Path:
    return fixtures_dir / "idb" / "handler_hierarchy.i64"


@pytest.fixture(scope="session")
def handler_hierarchy_stripped_database(fixtures_dir: Path) -> Path:
    return fixtures_dir / "idb" / "handler_hierarchy_stripped.i64"


@pytest.fixture(scope="session")
def idac_cmd() -> list[str]:
    """
    Run the package through the current interpreter against the local source tree.
    """
    return [sys.executable, "-m", "idac"]


def _cleanup_runtime_dir(runtime_dir: Path) -> None:
    for registry_path in runtime_dir.glob("idac-idalib-*.json"):
        try:
            payload = json.loads(registry_path.read_text(encoding="utf-8"))
            pid = int(payload.get("pid", 0))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pid = 0
        if pid > 0:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        live = False
        for registry_path in runtime_dir.glob("idac-idalib-*.json"):
            try:
                payload = json.loads(registry_path.read_text(encoding="utf-8"))
                pid = int(payload.get("pid", 0))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pid = 0
            if pid <= 0:
                continue
            try:
                os.kill(pid, 0)
            except OSError:
                continue
            live = True
            break
        if not live:
            break
        time.sleep(0.05)
    shutil.rmtree(runtime_dir, ignore_errors=True)


@pytest.fixture
def idac_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_repo_root() / "src")
    runtime_dir = Path(tempfile.mkdtemp(prefix="idac-test-runtime-"))
    env["IDAC_RUNTIME_DIR"] = str(runtime_dir)
    try:
        yield env
    finally:
        _cleanup_runtime_dir(runtime_dir)


@pytest.fixture
def copy_database(tmp_path: Path) -> Callable[[Path], Path]:
    def _copy(source: Path) -> Path:
        target = tmp_path / source.name
        shutil.copy2(source, target)
        return target

    return _copy
