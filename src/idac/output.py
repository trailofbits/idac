from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

DEFAULT_INLINE_CHAR_LIMIT = 10_000


class OutputTooLargeError(RuntimeError):
    """Raised when stdout output exceeds the inline safety limit."""

    def __init__(
        self,
        *,
        chars: int,
        limit: int,
        out_flag: str = "--out",
        hint: str | None = None,
    ) -> None:
        message = f"output is {chars} characters, over the inline limit of {limit}"
        if hint:
            message += f"; {hint}"
        else:
            message += f"; rerun with `{out_flag}`"
        super().__init__(message)
        self.chars = chars
        self.limit = limit
        self.out_flag = out_flag
        self.hint = hint


@dataclass
class OutputResult:
    """Rendered stdout text plus optional on-disk artifact metadata."""

    rendered: str
    artifact: Optional[dict[str, Any]]


def resolve_output_format(fmt: str, out_path: Optional[Path], *, force_fmt: bool = False) -> str:
    """Infer structured formats from output suffixes unless the caller explicitly forces fmt."""

    if force_fmt:
        return fmt
    if out_path and out_path.suffix.lower() == ".json":
        return "json"
    if out_path and out_path.suffix.lower() == ".jsonl":
        return "jsonl"
    return fmt


def _render_value(value: Any, fmt: str) -> str:
    """Render a response value in the requested transport format."""

    if fmt == "json":
        return json.dumps(value, indent=2, sort_keys=True) + "\n"
    if fmt == "jsonl":
        rows = value if isinstance(value, list) else [value]
        return "".join(json.dumps(item, sort_keys=True) + "\n" for item in rows)
    if isinstance(value, str):
        return value if value.endswith("\n") else value + "\n"
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _artifact_summary(value: Any) -> dict[str, Any]:
    """Summarize the result shape without repeating the full payload."""

    if isinstance(value, dict):
        return {"kind": "object", "count": len(value), "keys": sorted(value.keys())[:10]}
    if isinstance(value, list):
        return {"kind": "array", "count": len(value)}
    if isinstance(value, str):
        return {"kind": "string", "chars": len(value)}
    return {"kind": type(value).__name__}


def _artifact_write_target(path: Path) -> Path:
    """Follow symlink destinations so `--out` keeps prior write semantics."""

    if path.is_symlink():
        return Path(os.path.realpath(path))
    return path


def _default_artifact_mode() -> int:
    """Approximate the mode a normal write would create under the current umask."""

    current_umask = os.umask(0)
    os.umask(current_umask)
    return 0o666 & ~current_umask


def _write_artifact(path: Path, rendered: str, fmt: str, value: Any) -> dict[str, Any]:
    """Write the rendered payload and return stable metadata about the artifact."""

    write_path = _artifact_write_target(path)
    write_path.parent.mkdir(parents=True, exist_ok=True)
    data = rendered.encode("utf-8")
    desired_mode = _default_artifact_mode()
    if write_path.exists():
        desired_mode = stat.S_IMODE(write_path.stat().st_mode)

    fd, temp_name = tempfile.mkstemp(prefix=f".{write_path.name}.", suffix=".tmp", dir=str(write_path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), desired_mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, write_path)
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(write_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return {
        "ok": True,
        "artifact_path": str(path),
        "bytes": len(data),
        "format": fmt,
        "sha256": hashlib.sha256(data).hexdigest(),
        "summary": _artifact_summary(value),
    }


def write_output_result(
    value: Any,
    *,
    fmt: str,
    out_path: Optional[Path],
    stem: str,
    inline_char_limit: int = DEFAULT_INLINE_CHAR_LIMIT,
    force_fmt: bool = False,
) -> OutputResult:
    """Render a command result either inline or as an output artifact."""

    effective_fmt = resolve_output_format(fmt, out_path, force_fmt=force_fmt)
    rendered = _render_value(value, effective_fmt)
    if out_path:
        artifact = _write_artifact(out_path, rendered, effective_fmt, value)
        return OutputResult(rendered="", artifact=artifact)

    if len(rendered) > inline_char_limit:
        raise OutputTooLargeError(chars=len(rendered), limit=inline_char_limit)
    return OutputResult(rendered=rendered, artifact=None)
