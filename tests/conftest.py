from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

_LIVE_GUI_ENV = "IDAC_RUN_NEXUS_GUI_TESTS"

# Integration modules that open real databases through Nexus. Keep this list
# explicit so unit tests for the Nexus client itself remain runnable without IDA.
_REQUIRES_IDA_MODULES = {
    "test_nexus_batch",
    "test_nexus_binary_workflow",
    "test_nexus_bookmarks",
    "test_nexus_classes",
    "test_nexus_ctree",
    "test_nexus_function_inspection_search",
    "test_nexus_headless_lifecycle",
    "test_nexus_locals",
    "test_nexus_name_locals_semantics",
    "test_nexus_proto_comments",
    "test_nexus_reads",
    "test_nexus_reanalyze_python",
    "test_nexus_struct_enum_semantics",
    "test_nexus_types",
    "test_output_limits",
    "test_preview",
}


@functools.lru_cache(maxsize=1)
def _nexus_ida_available() -> bool:
    """Report whether ida-nexus has a configured idalib installation."""

    configured = os.environ.get("IDADIR")
    if not configured:
        idausr = Path(os.environ.get("IDAUSR", Path.home() / ".idapro")).expanduser()
        config_path = Path(str(idausr).split(os.pathsep)[0]) / "ida-config.json"
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            paths = payload.get("Paths", {})
            configured = paths.get("ida-install-dir") if isinstance(paths, dict) else None
        except (OSError, TypeError, json.JSONDecodeError):
            return False
    if not isinstance(configured, str) or not configured.strip():
        return False
    ida_dir = Path(configured).expanduser()
    try:
        return any(
            path.is_file()
            for path in (
                ida_dir / "libidalib.so",
                ida_dir / "libidalib.dylib",
                ida_dir / "idalib.dll",
                ida_dir / "Contents" / "MacOS" / "libidalib.dylib",
            )
        )
    except OSError:
        return False


def pytest_collection_modifyitems(config, items) -> None:
    requires_ida = pytest.mark.requires_ida
    skip_no_ida = pytest.mark.skip(reason="no local IDA installation configured for ida-nexus")
    skip_live = pytest.mark.skip(reason=f"set {_LIVE_GUI_ENV}=1 to run nexus_gui_live integration tests")
    run_gui_live = os.environ.get(_LIVE_GUI_ENV) == "1"
    for item in items:
        module_name = item.module.__name__.rpartition(".")[2]
        if module_name in _REQUIRES_IDA_MODULES:
            item.add_marker(requires_ida)
        if "requires_ida" in item.keywords and not _nexus_ida_available():
            item.add_marker(skip_no_ida)
        if "nexus_gui_live" in item.keywords and not run_gui_live:
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


def _shutdown_nexus_workers(env: dict[str, str]) -> None:
    """Stop fixture-owned headless instances through ida-nexus's public API."""

    code = """
from ida_nexus import DatabaseHandle, InstanceState, discover_databases, wait_database_released

for discovered in discover_databases(timeout=1.0):
    if discovered.state is not InstanceState.READY or discovered.instance.backend != "idalib":
        continue
    instance = discovered.instance
    handle = DatabaseHandle.attach(instance, keepalive=0.0)
    try:
        handle.shutdown_database(save=True)
    finally:
        handle.close()
    if not wait_database_released(instance, timeout=20.0):
        raise TimeoutError(f"Nexus worker did not release {instance.record_id}")
"""
    subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


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
    env["IDA_NEXUS_STATE_DIR"] = str(runtime_dir)
    env["IDAUSR"] = str(idausr_dir)
    try:
        yield env
    finally:
        _shutdown_nexus_workers(env)
        shutil.rmtree(runtime_dir, ignore_errors=True)
        shutil.rmtree(idausr_dir, ignore_errors=True)


@pytest.fixture
def copy_database(tmp_path: Path) -> Callable[[Path], Path]:
    def _copy(source: Path) -> Path:
        target = tmp_path / source.name
        shutil.copy2(source, target)
        return target

    return _copy
