from __future__ import annotations

import importlib.metadata
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .compatibility import runtime_requirements


def setup_gui(
    *,
    timeout: float | None = None,
    runner: Any = subprocess.run,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Install the GUI plugin matching the installed Nexus client."""

    nexus_version = importlib.metadata.version("ida-nexus")
    source = f"https://github.com/HexRaysSA/ida-nexus@v{nexus_version}"
    domain_requirement = str(runtime_requirements()["ida-domain"])

    with tempfile.TemporaryDirectory(prefix="idac-nexus-constraint-") as temporary_dir:
        constraint = Path(temporary_dir) / "constraints.txt"
        constraint.write_text(f"ida-domain{domain_requirement}\n", encoding="utf-8")
        process_environment = dict(os.environ if environ is None else environ)
        process_environment["PIP_CONSTRAINT"] = str(constraint)
        process_environment["UV_CONSTRAINT"] = str(constraint)
        try:
            process = runner(
                [sys.executable, "-m", "hcli", "plugin", "install", source],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=process_environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError("timed out while installing the ida-nexus GUI plugin") from exc
        except OSError as exc:
            raise OSError(f"failed to run the ida-hcli installer: {exc}") from exc

    if process.returncode != 0:
        output = "\n".join(part.strip() for part in (process.stdout, process.stderr) if part and part.strip())
        suffix = f": {output}" if output else ""
        raise OSError(f"ida-hcli failed to install ida-nexus (exit {process.returncode}){suffix}")
    return {
        "installed": True,
        "plugin": "ida-nexus",
        "version": nexus_version,
        "ida_domain_requirement": domain_requirement,
        "installer": f"ida-hcli=={importlib.metadata.version('ida-hcli')}",
        "source": source,
    }
