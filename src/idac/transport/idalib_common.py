from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from idac.paths import ida_configured_install_dir

IDAPRO_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, OSError, RuntimeError, ValueError)


class WorkerError(RuntimeError):
    """Raised when the headless idalib worker cannot start cleanly."""

    pass


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    return list(dict.fromkeys(paths))


def default_ida_install_dirs() -> list[Path]:
    """Return platform-specific default directories that may contain IDA."""

    candidates: list[Path] = []
    if sys.platform == "darwin":
        candidates.extend(sorted(Path("/Applications").glob("IDA Professional*.app/Contents/MacOS"), reverse=True))
    elif sys.platform.startswith("linux"):
        for pattern in ("ida*", "IDA*"):
            candidates.extend(sorted(Path("/opt").glob(pattern), reverse=True))
            candidates.extend(sorted(Path.home().glob(pattern), reverse=True))
    elif os.name == "nt":
        for env_name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            root = os.environ.get(env_name)
            if not root:
                continue
            candidates.extend(sorted(Path(root).glob("IDA*"), reverse=True))
    return candidates


def candidate_ida_dirs() -> list[Path]:
    """Return deduplicated IDA install candidates, preferring explicit env vars."""

    explicit = [
        Path(raw).expanduser() for raw in (os.environ.get("IDAC_IDA_INSTALL_DIR"), os.environ.get("IDADIR")) if raw
    ]
    configured = ida_configured_install_dir()
    configured_candidates = [] if configured is None else [configured]
    return _dedupe_paths([*explicit, *configured_candidates, *default_ida_install_dirs()])


def normalize_database_path(path: str) -> str:
    return str(Path(path).expanduser().resolve(strict=False))


def load_registry(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def build_target_row(*, pid: int, database_path: str, socket_path: str | Path) -> dict[str, Any]:
    db = Path(database_path)
    return {
        "target_id": str(pid),
        "selector": db.name,
        "filename": database_path,
        "module": db.stem,
        "active": True,
        "instance_pid": pid,
        "socket_path": str(socket_path),
    }


def _import_idapro() -> Any:
    import idapro  # type: ignore

    return idapro


def bootstrap_idapro():
    """Import ``idapro``, searching common install locations when needed."""

    try:
        return _import_idapro()
    except IDAPRO_IMPORT_ERRORS:
        pass

    last_error: Optional[Exception] = None
    for ida_dir in candidate_ida_dirs():
        python_dir = ida_dir / "idalib" / "python"
        if not python_dir.exists():
            continue
        # IDA's Python modules are not importable until its bundled site-packages
        # directory is injected into ``sys.path``.
        os.environ.setdefault("IDADIR", str(ida_dir))
        python_dir_text = str(python_dir)
        if python_dir_text not in sys.path:
            sys.path.insert(0, python_dir_text)
        try:
            return _import_idapro()
        except IDAPRO_IMPORT_ERRORS as exc:
            last_error = exc

    if last_error is not None:
        raise WorkerError(f"failed to import idapro: {last_error}") from last_error
    raise WorkerError("failed to import idapro: no usable IDA installation found")
