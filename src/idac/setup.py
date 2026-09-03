from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .compatibility import IDA_DOMAIN_VERSION, IDA_HCLI_VERSION, IDA_NEXUS_VERSION

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
