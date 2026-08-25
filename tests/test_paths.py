from __future__ import annotations

from pathlib import Path

import pytest

from idac.paths import (
    skill_install_dir,
    skill_install_dirs,
)


def test_skill_destinations_honor_host_homes_without_creating_them(monkeypatch, tmp_path: Path) -> None:
    claude_home = tmp_path / "claude-home"
    codex_home = tmp_path / "codex-home"
    monkeypatch.setenv("CLAUDE_HOME", str(claude_home))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    assert skill_install_dir(host="claude") == claude_home / "skills" / "idac"
    assert skill_install_dir(host="codex") == codex_home / "skills" / "idac"
    assert set(skill_install_dirs()) == {
        claude_home / "skills" / "idac",
        codex_home / "skills" / "idac",
    }
    assert skill_install_dirs(host="codex") == [codex_home / "skills" / "idac"]
    assert not claude_home.exists()
    assert not codex_home.exists()


def test_duplicate_skill_destinations_are_collapsed(monkeypatch, tmp_path: Path) -> None:
    shared_home = tmp_path / "shared"
    monkeypatch.setenv("CLAUDE_HOME", str(shared_home))
    monkeypatch.setenv("CODEX_HOME", str(shared_home))

    assert skill_install_dirs() == [shared_home / "skills" / "idac"]


def test_unknown_skill_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported skill host: editor"):
        skill_install_dir(host="editor")
