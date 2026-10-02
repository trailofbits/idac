from __future__ import annotations

import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from idac import setup


def test_setup_gui_installs_the_supported_stack() -> None:
    nexus_version = metadata.version("ida-nexus")
    domain_requirement = next(
        requirement.specifier
        for dependency in metadata.requires("idac") or ()
        if (requirement := Requirement(dependency)).name == "ida-domain"
    )
    source = f"https://github.com/HexRaysSA/ida-nexus@v{nexus_version}"
    observed: dict[str, object] = {}

    def runner(command, **kwargs):
        observed["command"] = command
        observed["timeout"] = kwargs["timeout"]
        environment = kwargs["env"]
        observed["constraints"] = {
            name: Path(environment[name]).read_text(encoding="utf-8") for name in ("PIP_CONSTRAINT", "UV_CONSTRAINT")
        }
        return subprocess.CompletedProcess(command, 0, "Installed plugin: ida-nexus", "")

    result = setup.setup_gui(timeout=30.0, runner=runner, environ={"PATH": "/bin"})

    assert observed["timeout"] == 30.0
    assert result["installed"] is True
    assert result["plugin"] == "ida-nexus"
    assert observed["command"] == [sys.executable, "-m", "hcli", "plugin", "install", source]
    assert result["version"] == nexus_version
    assert result["source"] == source
    assert result["ida_domain_requirement"] == str(domain_requirement)
    assert observed["constraints"] == dict.fromkeys(
        ("PIP_CONSTRAINT", "UV_CONSTRAINT"), f"ida-domain{domain_requirement}\n"
    )


def test_setup_gui_surfaces_installer_failure() -> None:
    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 2, "", "dependency resolution failed")

    with pytest.raises(OSError, match=r"ida-hcli failed.*dependency resolution failed"):
        setup.setup_gui(runner=runner, environ={})
