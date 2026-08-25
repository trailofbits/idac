from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .compatibility import IDA_DOMAIN_VERSION, IDA_HCLI_VERSION, IDA_NEXUS_VERSION
from .paths import skill_install_dirs, skill_source_dir

IDA_NEXUS_RELEASE = f"https://github.com/HexRaysSA/ida-nexus@v{IDA_NEXUS_VERSION}"

HCLI_INSTALL_COMMAND = (
    sys.executable,
    "-m",
    "hcli",
    "plugin",
    "install",
    IDA_NEXUS_RELEASE,
)


def setup_gui(
    *,
    timeout: float | None = None,
    runner: Any = subprocess.run,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Install the exact supported Nexus GUI plugin with the official installer."""

    with tempfile.TemporaryDirectory(prefix="idac-nexus-constraint-") as temporary_dir:
        constraint = Path(temporary_dir) / "constraints.txt"
        constraint.write_text(f"ida-domain=={IDA_DOMAIN_VERSION}\n", encoding="utf-8")
        process_environment = dict(os.environ if environ is None else environ)
        process_environment["PIP_CONSTRAINT"] = str(constraint)
        process_environment["UV_CONSTRAINT"] = str(constraint)
        try:
            process = runner(
                list(HCLI_INSTALL_COMMAND),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=process_environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError("timed out while installing the ida-nexus GUI plugin") from exc
        except OSError as exc:
            raise OSError(f"failed to run the pinned ida-hcli installer: {exc}") from exc

    if process.returncode != 0:
        output = "\n".join(part.strip() for part in (process.stdout, process.stderr) if part and part.strip())
        suffix = f": {output}" if output else ""
        raise OSError(f"ida-hcli failed to install ida-nexus (exit {process.returncode}){suffix}")
    return {
        "installed": True,
        "plugin": "ida-nexus",
        "version": IDA_NEXUS_VERSION,
        "ida_domain_version": IDA_DOMAIN_VERSION,
        "installer": f"ida-hcli=={IDA_HCLI_VERSION}",
        "source": IDA_NEXUS_RELEASE,
    }


def _install_skill_path(source: Path, destination: Path, *, mode: str, force: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if not force:
            raise OSError(f"destination already exists: {destination}")
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
        else:
            shutil.rmtree(destination)
    if mode == "copy":
        shutil.copytree(source, destination)
    else:
        os.symlink(source, destination, target_is_directory=True)


def setup_skill(
    *,
    mode: str = "symlink",
    force: bool = False,
    host: str = "both",
    dest: str | Path | None = None,
) -> dict[str, Any]:
    """Install the bundled idac skill for Claude Code, Codex, or a custom path."""

    if mode not in {"copy", "symlink"}:
        raise ValueError("mode must be 'copy' or 'symlink'")
    if host not in {"claude", "codex", "both"}:
        raise ValueError("host must be 'claude', 'codex', or 'both'")

    source = skill_source_dir()
    if not source.exists():
        raise OSError(f"source path is missing: {source}")
    destinations = [Path(dest).expanduser()] if dest is not None else skill_install_dirs(host=host)
    for destination in destinations:
        _install_skill_path(source, destination, mode=mode, force=force)
    return {
        "installed": True,
        "mode": mode,
        "source": str(source),
        "destinations": [str(destination) for destination in destinations],
    }
