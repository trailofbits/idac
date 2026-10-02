from __future__ import annotations

from pathlib import Path


def package_source_dir() -> Path:
    """Return the installed idac package directory containing bundled assets."""

    return Path(__file__).resolve().parent


def workspace_template_source_dir() -> Path:
    return package_source_dir() / "workspace_template" / "default"


__all__ = [
    "package_source_dir",
    "workspace_template_source_dir",
]
