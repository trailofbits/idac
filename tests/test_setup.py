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


def test_setup_skill_symlinks_both_supported_hosts(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / ".claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))

    result = setup.setup_skill()

    destinations = [Path(item) for item in result["destinations"]]
    assert result["installed"] is True
    assert len(destinations) == 2
    assert all(destination.is_symlink() for destination in destinations)
    assert all(destination.resolve() == setup.skill_source_dir().resolve() for destination in destinations)


def test_setup_skill_copies_to_custom_destination_and_force_replaces(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("current\n", encoding="utf-8")
    destination = tmp_path / "custom" / "idac"
    destination.mkdir(parents=True)
    (destination / "stale.txt").write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(setup, "skill_source_dir", lambda: source)

    with pytest.raises(OSError, match="destination already exists"):
        setup.setup_skill(mode="copy", dest=destination)

    result = setup.setup_skill(mode="copy", force=True, host="claude", dest=destination)

    assert result["destinations"] == [str(destination)]
    assert not destination.is_symlink()
    assert (destination / "SKILL.md").read_text(encoding="utf-8") == "current\n"
    assert not (destination / "stale.txt").exists()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"mode": "hardlink"}, "mode must be"),
        ({"host": "other"}, "host must be"),
    ],
)
def test_setup_skill_validates_direct_callers(kwargs, message) -> None:
    with pytest.raises(ValueError, match=message):
        setup.setup_skill(**kwargs)
