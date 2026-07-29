from __future__ import annotations

from pathlib import Path


def is_ignored_install_path(path: Path) -> bool:
    return "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}


def copytree_ignore(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if is_ignored_install_path(Path(name))}


def relative_install_files(root: Path) -> set[Path]:
    return {
        relative
        for path in root.rglob("*")
        if path.is_file() and not is_ignored_install_path(relative := path.relative_to(root))
    }
