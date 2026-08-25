from __future__ import annotations

import os
from pathlib import Path

SKILL_NAME = "idac"


def package_source_dir() -> Path:
    """Return the installed idac package directory containing bundled assets."""

    return Path(__file__).resolve().parent


def skill_source_dir() -> Path:
    return package_source_dir() / "skills" / SKILL_NAME


def skill_reference_source_dir() -> Path:
    return skill_source_dir() / "references"


def workspace_template_source_dir() -> Path:
    return package_source_dir() / "workspace_template" / "default"


def skill_install_dir(*, host: str = "codex") -> Path:
    if host == "codex":
        base = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    elif host == "claude":
        base = Path(os.environ.get("CLAUDE_HOME", Path.home() / ".claude")).expanduser()
    else:
        raise ValueError(f"unsupported skill host: {host}")
    return base / "skills" / SKILL_NAME


def skill_install_dirs(*, host: str = "both") -> list[Path]:
    if host == "both":
        destinations = [skill_install_dir(host="claude"), skill_install_dir(host="codex")]
        return list(dict.fromkeys(destinations))
    return [skill_install_dir(host=host)]


__all__ = [
    "SKILL_NAME",
    "package_source_dir",
    "skill_install_dir",
    "skill_install_dirs",
    "skill_reference_source_dir",
    "skill_source_dir",
    "workspace_template_source_dir",
]
