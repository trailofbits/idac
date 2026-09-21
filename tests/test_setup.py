from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from idac import setup


def test_setup_gui_installs_the_supported_stack() -> None:
    observed: dict[str, object] = {}

    def runner(command, **kwargs):
        observed["source"] = command[-1]
        observed["timeout"] = kwargs["timeout"]
        environment = kwargs["env"]
        pip_constraint = Path(environment["PIP_CONSTRAINT"])
        observed["constraint"] = pip_constraint.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "Installed plugin: ida-nexus", "")

    result = setup.setup_gui(timeout=30.0, runner=runner, environ={"PATH": "/bin"})

    assert observed["timeout"] == 30.0
    assert result["installed"] is True
    assert result["plugin"] == "ida-nexus"
    assert result["source"] == observed["source"]
    assert result["source"].endswith(f"@v{result['version']}")
    assert observed["constraint"] == f"ida-domain{result['ida_domain_requirement']}\n"


def test_setup_gui_surfaces_installer_failure() -> None:
    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 2, "", "dependency resolution failed")

    with pytest.raises(OSError, match=r"ida-hcli failed.*dependency resolution failed"):
        setup.setup_gui(runner=runner, environ={})
