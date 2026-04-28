from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .paths import skill_reference_source_dir, workspace_template_source_dir

_WORKSPACE_MARKER = ".idac"
_WORKSPACE_TMP = ".idac/tmp"
_CONFIG_PATHS = frozenset(
    {
        ".claude/settings.json",
        ".codex/config.toml",
        ".codex/rules/default.rules",
        "CLAUDE.md",
        "AGENTS.md",
        ".gitignore",
    }
)


def _display_path(relative: Path, *, is_dir: bool) -> str:
    """Format one created workspace path for user-facing summaries."""

    rendered = relative.as_posix()
    return f"{rendered}/" if is_dir else rendered


def _ensure_directory(path: Path, *, root: Path) -> list[str]:
    """Create missing directories below ``root`` and report each one."""

    created: list[str] = []
    missing: list[Path] = []
    current = path
    while current != root and not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir()
        created.append(_display_path(directory.relative_to(root), is_dir=True))
    return created


def _git_repo_root(path: Path) -> Path | None:
    """Return the enclosing git root for ``path`` when one exists."""

    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise OSError("git is required for `idac workspace init`") from exc
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    return Path(raw).resolve() if raw else None


def _git_init(path: Path) -> Path:
    """Initialize a git repository and return its detected root."""

    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "init"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise OSError("git is required for `idac workspace init`") from exc
    if proc.returncode != 0:
        details = (proc.stderr or proc.stdout).strip() or "git init failed"
        raise OSError(details)
    repo_root = _git_repo_root(path)
    if repo_root is None:
        raise OSError("git repository initialization succeeded but no repo root was detected")
    return repo_root


def _copy_template_file(
    source: Path,
    dest: Path,
    *,
    overwrite: bool,
    skip_existing: bool,
) -> tuple[bool, bool]:
    """Copy one template file, reporting whether it was created or overwritten."""

    dest.parent.mkdir(parents=True, exist_ok=True)
    source_bytes = source.read_bytes()
    if dest.exists():
        if dest.is_dir():
            raise OSError(f"destination already exists as a directory: {dest}")
        if dest.read_bytes() == source_bytes:
            return False, False
        if skip_existing:
            return False, False
        if not overwrite:
            raise OSError(f"destination already exists: {dest} (use --force to overwrite)")
        dest.write_bytes(source_bytes)
        return False, True
    dest.write_bytes(source_bytes)
    return True, False


def _copy_tree(
    source_root: Path,
    dest_root: Path,
    *,
    tracking_root: Path,
    force: bool,
    workspace_exists: bool,
    config_paths: Iterable[str] = (),
) -> tuple[list[str], list[str]]:
    """Copy one source tree into the workspace and report created/overwritten paths."""

    created: list[str] = []
    overwritten: list[str] = []
    config_path_set = frozenset(config_paths)

    for source in sorted(source_root.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(source_root)
        dest = dest_root / relative
        created.extend(_ensure_directory(dest.parent, root=tracking_root))
        overwrite = force and relative.as_posix() in config_path_set
        skip_existing = workspace_exists and force and not overwrite
        file_created, file_overwritten = _copy_template_file(
            source,
            dest,
            overwrite=overwrite,
            skip_existing=skip_existing,
        )
        display = _display_path(dest.relative_to(tracking_root), is_dir=False)
        if file_created and display not in created:
            created.append(display)
        if file_overwritten and display not in overwritten:
            overwritten.append(display)

    return created, overwritten


def initialize_workspace(dest: Path, *, force: bool = False) -> dict[str, Any]:
    """Create or refresh an idac workspace from the bundled template."""

    destination = dest.expanduser()
    destination.mkdir(parents=True, exist_ok=True)

    marker = destination / _WORKSPACE_MARKER
    workspace_exists = marker.is_dir()
    if workspace_exists and not force:
        raise OSError("workspace already initialized (use --force to overwrite config)")

    template_root = workspace_template_source_dir()
    created: list[str] = []
    overwritten: list[str] = []

    template_created, template_overwritten = _copy_tree(
        template_root,
        destination,
        tracking_root=destination,
        force=force,
        workspace_exists=workspace_exists,
        config_paths=_CONFIG_PATHS,
    )
    created.extend(template_created)
    overwritten.extend(template_overwritten)

    reference_created, reference_overwritten = _copy_tree(
        skill_reference_source_dir(),
        destination / "reference",
        tracking_root=destination,
        force=force,
        workspace_exists=workspace_exists,
    )
    created.extend(reference_created)
    overwritten.extend(reference_overwritten)

    tmp_dir = destination / _WORKSPACE_TMP
    if not tmp_dir.exists():
        created.extend(_ensure_directory(tmp_dir, root=destination))

    repo_root = _git_repo_root(destination)
    git_initialized = False
    if repo_root is None:
        repo_root = _git_init(destination)
        git_initialized = True

    return {
        "initialized": True,
        "destination": str(destination.resolve()),
        "display_destination": str(dest) if str(dest) else ".",
        "created": created,
        "overwritten": overwritten,
        "git": {
            "initialized": git_initialized,
            "repo_root": str(repo_root),
        },
        "next_steps": [
            "Run `idac misc skill install` if you haven't already",
            "Edit CLAUDE.md to set your default target",
            "Commit when the workspace looks right",
        ],
    }
