from __future__ import annotations

import contextlib
import functools
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import pytest

_LIVE_GUI_ENV = "IDAC_RUN_LIVE_GUI_TESTS"

# Modules whose tests all talk to a real idalib daemon and therefore need a
# local IDA install; individual tests elsewhere use @pytest.mark.requires_ida.
_REQUIRES_IDA_MODULE_PREFIX = "test_idalib_"
_REQUIRES_IDA_MODULES = {"test_preview", "test_output_limits"}


@functools.lru_cache(maxsize=1)
def _idalib_available() -> bool:
    # Mirror bootstrap_idapro's search order: idapro may already be importable
    # from the venv/site-packages, otherwise it is discovered from an install
    # dir. Checking only install dirs would skip integration tests that would
    # actually run.
    import importlib.util

    if importlib.util.find_spec("idapro") is not None:
        return True
    from idac.transport.idalib_common import candidate_ida_dirs

    try:
        return any((ida_dir / "idalib" / "python").exists() for ida_dir in candidate_ida_dirs())
    except OSError:
        return False


def pytest_collection_modifyitems(config, items) -> None:
    requires_ida = pytest.mark.requires_ida
    skip_no_ida = pytest.mark.skip(reason="no local IDA install with idalib found; integration tests skipped")
    skip_live = pytest.mark.skip(reason=f"set {_LIVE_GUI_ENV}=1 to run gui_live integration tests")
    run_gui_live = os.environ.get(_LIVE_GUI_ENV) == "1"
    for item in items:
        module_name = item.module.__name__.rpartition(".")[2]
        if module_name.startswith(_REQUIRES_IDA_MODULE_PREFIX) or module_name in _REQUIRES_IDA_MODULES:
            item.add_marker(requires_ida)
        if "requires_ida" in item.keywords and not _idalib_available():
            item.add_marker(skip_no_ida)
        if "gui_live" in item.keywords and not run_gui_live:
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


def _prepare_isolated_idausr(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for name in ("ida.reg", "ida-config.json"):
        source_file = source / name
        if source_file.is_file():
            shutil.copy2(source_file, target / name)
    for license_file in source.glob("idapro_*.hexlic"):
        if license_file.is_file():
            shutil.copy2(license_file, target / license_file.name)
    (target / "plugins").mkdir(exist_ok=True)


@pytest.fixture
def idac_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_repo_root() / "src")
    runtime_dir = Path(tempfile.mkdtemp(prefix="idac-test-runtime-"))
    idausr_dir = Path(tempfile.mkdtemp(prefix="idac-test-idapro-"))
    source_idausr = Path(env.get("IDAUSR", Path.home() / ".idapro")).expanduser()
    _prepare_isolated_idausr(source_idausr, idausr_dir)
    env["IDAC_RUNTIME_DIR"] = str(runtime_dir)
    env["IDAUSR"] = str(idausr_dir)
    try:
        yield env
    finally:
        _cleanup_runtime_dir(runtime_dir)
        shutil.rmtree(idausr_dir, ignore_errors=True)


@pytest.fixture
def copy_database(tmp_path: Path) -> Callable[[Path], Path]:
    def _copy(source: Path) -> Path:
        target = tmp_path / source.name
        shutil.copy2(source, target)
        return target

    return _copy
