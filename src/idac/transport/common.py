from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

_TIMEOUT_REQUIRED_OPS = frozenset({"search_bytes", "strings"})


def pid_is_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def normalize_timeout(raw_timeout: float | None) -> float | None:
    if raw_timeout is None:
        return None
    timeout = float(raw_timeout)
    if timeout <= 0:
        raise ValueError("backend timeout must be greater than 0")
    return timeout


def require_timeout_for_operation(op: str, timeout: float | None) -> None:
    if op in _TIMEOUT_REQUIRED_OPS and timeout is None:
        raise ValueError(f"operation `{op}` requires a request timeout (`--timeout` on the CLI)")


def recv_all(sock) -> list[bytes]:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return chunks
        chunks.append(chunk)


def read_request_bytes(connection, *, timeout: float, max_bytes: int) -> bytes:
    connection.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"request body exceeds maximum size of {max_bytes} bytes")
        chunks.append(chunk)


def atomic_write_json(path: Path, payload: Any) -> None:
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(payload, indent=2, sort_keys=True))
        assert temp_path is not None
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            with contextlib.suppress(FileNotFoundError):
                temp_path.unlink()
