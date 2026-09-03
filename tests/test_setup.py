from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from idac import setup


def test_setup_gui_installs_the_supported_stack() -> None:
    observed: dict[str, object] = {}

    def runner(command, **kwargs):
        assert setup.IDA_NEXUS_RELEASE in command
        observed["timeout"] = kwargs["timeout"]
        environment = kwargs["env"]
        pip_constraint = Path(environment["PIP_CONSTRAINT"])
        observed["same_constraint"] = environment["UV_CONSTRAINT"] == str(pip_constraint)
        observed["constraint"] = pip_constraint.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "Installed plugin: ida-nexus==0.7.0", "")

    result = setup.setup_gui(timeout=30.0, runner=runner, environ={"PATH": "/bin"})

    assert observed["timeout"] == 30.0
    assert observed["same_constraint"] is True
    assert f"ida-domain=={setup.IDA_DOMAIN_VERSION}" in str(observed["constraint"])
    assert result["installed"] is True
    assert result["plugin"] == "ida-nexus"
    assert result["version"] == setup.IDA_NEXUS_VERSION
    assert result["ida_domain_version"] == setup.IDA_DOMAIN_VERSION
    assert result["source"] == setup.IDA_NEXUS_RELEASE


def test_setup_gui_surfaces_installer_failure() -> None:
    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 2, "", "dependency resolution failed")

    with pytest.raises(OSError, match=r"ida-hcli failed.*dependency resolution failed"):
        setup.setup_gui(runner=runner, environ={})
