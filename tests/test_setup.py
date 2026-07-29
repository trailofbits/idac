from __future__ import annotations

import os
from pathlib import Path

import pytest

from idac import setup


def _skill_destinations(tmp_path: Path) -> list[Path]:
    return [
        tmp_path / ".claude" / "skills" / "idac",
        tmp_path / ".codex" / "skills" / "idac",
    ]


def _seed_original_destinations(destinations: list[Path]) -> None:
    for index, destination in enumerate(destinations):
        destination.mkdir(parents=True)
        (destination / "original.txt").write_text(f"original-{index}", encoding="utf-8")


def _assert_original_destinations(destinations: list[Path]) -> None:
    for index, destination in enumerate(destinations):
        assert (destination / "original.txt").read_text(encoding="utf-8") == f"original-{index}"
        assert not (destination / "SKILL.md").exists()


def test_setup_update_rolls_back_every_destination_when_commit_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / ".claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    destinations = _skill_destinations(tmp_path)
    _seed_original_destinations(destinations)

    original_replace = os.replace
    staged_commits = 0

    def fail_second_staged_commit(source: str | Path, destination: str | Path) -> None:
        nonlocal staged_commits
        if ".idac-stage-" in str(source):
            staged_commits += 1
            if staged_commits == 2:
                raise OSError("injected commit failure")
        original_replace(source, destination)

    monkeypatch.setattr(setup.os, "replace", fail_second_staged_commit)
    plan = setup.plan_setup(setup.SetupRequest(action="update", components=("skill",), mode="copy"))

    with pytest.raises(OSError, match="failed to commit setup transaction"):
        setup.apply_setup(plan)

    _assert_original_destinations(destinations)
    assert not list(tmp_path.rglob("*.idac-stage-*"))
    assert not list(tmp_path.rglob("*.idac-backup-*"))


@pytest.mark.parametrize("interrupt_after", ["backup", "staged_commit"])
def test_setup_update_rolls_back_when_interrupted_after_replace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interrupt_after: str,
) -> None:
    destination = tmp_path / "skills" / "idac"
    _seed_original_destinations([destination])
    original_replace = os.replace
    interrupted = False

    def interrupt_after_replace(source: str | Path, target: str | Path) -> None:
        nonlocal interrupted
        should_interrupt = not interrupted and (
            (interrupt_after == "backup" and ".idac-backup-" in Path(target).name)
            or (interrupt_after == "staged_commit" and ".idac-stage-" in Path(source).name)
        )
        original_replace(source, target)
        if should_interrupt:
            interrupted = True
            raise KeyboardInterrupt

    monkeypatch.setattr(setup.os, "replace", interrupt_after_replace)
    plan = setup.plan_setup(
        setup.SetupRequest(
            action="update",
            components=("skill",),
            mode="copy",
            skill_destination=destination,
        )
    )

    with pytest.raises(KeyboardInterrupt):
        setup.apply_setup(plan)

    assert interrupted is True
    _assert_original_destinations([destination])
    assert not list(tmp_path.rglob("*.idac-stage-*"))
    assert not list(tmp_path.rglob("*.idac-backup-*"))


def test_setup_interrupt_reports_rollback_failures(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    destination = tmp_path / "skills" / "idac"
    _seed_original_destinations([destination])
    plan = setup.plan_setup(
        setup.SetupRequest(
            action="update",
            components=("skill",),
            mode="copy",
            skill_destination=destination,
        )
    )
    original_replace = os.replace
    original_remove_path = setup._remove_path

    def interrupt_after_staged_commit(source: str | Path, target: str | Path) -> None:
        original_replace(source, target)
        if ".idac-stage-" in Path(source).name:
            raise KeyboardInterrupt

    def fail_rollback(path: Path) -> None:
        if path == destination:
            raise PermissionError("rollback destination is locked")
        original_remove_path(path)

    monkeypatch.setattr(setup.os, "replace", interrupt_after_staged_commit)
    monkeypatch.setattr(setup, "_remove_path", fail_rollback)

    with pytest.raises(KeyboardInterrupt) as exc_info:
        setup.apply_setup(plan)

    diagnostics = "\n".join(getattr(exc_info.value, "__notes__", ())) + str(exc_info.value)
    assert "setup rollback errors" in diagnostics
    assert "rollback destination is locked" in diagnostics


def test_setup_cleans_partial_staging_when_copy_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / ".claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
    destinations = _skill_destinations(tmp_path)
    _seed_original_destinations(destinations)

    original_copytree = setup.shutil.copytree
    staged_copies = 0

    def fail_second_staged_copy(source: str | Path, destination: str | Path, *args, **kwargs):
        nonlocal staged_copies
        staged_copies += 1
        if staged_copies == 2:
            partial = Path(destination)
            partial.mkdir()
            (partial / "partial.txt").write_text("partial", encoding="utf-8")
            raise OSError("injected staging failure")
        return original_copytree(source, destination, *args, **kwargs)

    monkeypatch.setattr(setup.shutil, "copytree", fail_second_staged_copy)
    plan = setup.plan_setup(setup.SetupRequest(action="update", components=("skill",), mode="copy"))

    with pytest.raises(OSError, match="injected staging failure"):
        setup.apply_setup(plan)

    _assert_original_destinations(destinations)
    assert not list(tmp_path.rglob("*.idac-stage-*"))


@pytest.mark.parametrize(
    ("plugin_destination", "skill_destination"),
    [
        (Path("integrations/idac_bridge"), Path("integrations")),
        (Path("integrations"), Path("integrations/skills/idac")),
    ],
)
def test_setup_rejects_nested_custom_destinations_before_staging(
    tmp_path: Path,
    plugin_destination: Path,
    skill_destination: Path,
) -> None:
    integration_root = tmp_path / "integrations"
    request = setup.SetupRequest(
        action="update",
        components=("plugin", "skill"),
        mode="copy",
        plugin_destination=tmp_path / plugin_destination,
        skill_destination=tmp_path / skill_destination,
    )

    with pytest.raises(setup.SetupValidationError, match="setup destinations must not be equal or nested"):
        setup.plan_setup(request)

    assert not integration_root.exists()


def test_setup_rejects_destination_aliases_that_resolve_to_the_same_path(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias_parent = tmp_path / "alias"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    request = setup.SetupRequest(
        action="update",
        components=("plugin", "skill"),
        plugin_destination=real_parent / "idac_bridge",
        skill_destination=alias_parent / "idac",
    )

    with pytest.raises(setup.SetupValidationError, match="setup destinations must not be equal or nested"):
        setup.plan_setup(request)


def test_setup_rejects_case_insensitive_destination_source_alias(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "skills" / "idac"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text("skill", encoding="utf-8")
    monkeypatch.setattr(setup, "skill_source_dir", lambda: source)
    original_samefile = os.path.samefile

    def case_insensitive_samefile(first: str | Path, second: str | Path) -> bool:
        if os.fspath(first).casefold() == os.fspath(second).casefold():
            return True
        return original_samefile(first, second)

    monkeypatch.setattr(setup.os.path, "samefile", case_insensitive_samefile)
    request = setup.SetupRequest(
        action="update",
        components=("skill",),
        skill_destination=source.with_name("IDAC"),
    )

    with pytest.raises(setup.SetupValidationError, match="must not overlap bundled source"):
        setup.plan_setup(request)


@pytest.mark.parametrize("destination_kind", ["source_parent", "inside_source"])
def test_setup_rejects_destination_source_overlap_in_both_directions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    destination_kind: str,
) -> None:
    source_parent = tmp_path / "bundled-skills"
    source = source_parent / "idac"
    (source / "agents").mkdir(parents=True)
    (source / "SKILL.md").write_text("skill", encoding="utf-8")
    (source / "agents" / "openai.yaml").write_text("agent", encoding="utf-8")
    (source_parent / "OTHER.md").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(setup, "skill_source_dir", lambda: source)
    destination = source_parent if destination_kind == "source_parent" else source / "installed"
    request = setup.SetupRequest(
        action="update",
        components=("skill",),
        mode="copy",
        skill_destination=destination,
    )

    with pytest.raises(setup.SetupValidationError, match="must not overlap bundled source"):
        setup.plan_setup(request)

    assert source.exists()
    assert (source_parent / "OTHER.md").read_text(encoding="utf-8") == "keep"


def test_setup_rejects_plugin_destination_named_like_runtime_package(tmp_path: Path) -> None:
    request = setup.SetupRequest(
        action="update",
        components=("plugin",),
        plugin_destination=tmp_path / "plugins" / "idac",
    )

    with pytest.raises(setup.SetupValidationError, match="--plugin-dest cannot end in `idac`"):
        setup.plan_setup(request)


def test_setup_plan_marks_alternate_symlink_for_replacement(tmp_path: Path) -> None:
    old_source = tmp_path / "old-skill"
    old_source.mkdir()
    destination = tmp_path / "skills" / "idac"
    destination.parent.mkdir()
    destination.symlink_to(old_source, target_is_directory=True)
    request = setup.SetupRequest(
        action="update",
        components=("skill",),
        skill_destination=destination,
    )

    plan = setup.plan_setup(request)

    assert plan.targets[0].status == "updated"
    assert plan.targets[0].mode == "symlink"
    assert plan.requires_confirmation is True


def test_setup_copy_omits_python_cache_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "source-skill"
    (source / "agents").mkdir(parents=True)
    (source / "__pycache__").mkdir()
    (source / "SKILL.md").write_text("skill", encoding="utf-8")
    (source / "agents" / "openai.yaml").write_text("agent", encoding="utf-8")
    (source / "__pycache__" / "cached.pyc").write_bytes(b"cache")
    (source / "loose.pyc").write_bytes(b"cache")
    (source / "keep.py").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(setup, "skill_source_dir", lambda: source)
    destination = tmp_path / "installed-skill"
    request = setup.SetupRequest(
        action="install",
        components=("skill",),
        mode="copy",
        skill_destination=destination,
    )

    result = setup.apply_setup(setup.plan_setup(request))

    assert result["phase"] == "applied"
    assert (destination / "keep.py").exists()
    assert not (destination / "__pycache__").exists()
    assert not (destination / "loose.pyc").exists()


def test_setup_reports_backup_cleanup_failure_after_successful_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    destination = tmp_path / "skills" / "idac"
    (destination / "agents").mkdir(parents=True)
    (destination / "SKILL.md").write_text("old", encoding="utf-8")
    (destination / "agents" / "openai.yaml").write_text("old", encoding="utf-8")
    plan = setup.plan_setup(
        setup.SetupRequest(
            action="update",
            components=("skill",),
            mode="copy",
            skill_destination=destination,
        )
    )
    original_remove_path = setup._remove_path

    def fail_backup_cleanup(path: Path) -> None:
        if ".idac-backup-" in path.name:
            raise PermissionError("backup is locked")
        original_remove_path(path)

    monkeypatch.setattr(setup, "_remove_path", fail_backup_cleanup)

    result = setup.apply_setup(plan)

    assert result["phase"] == "applied"
    assert (destination / "SKILL.md").read_text(encoding="utf-8").startswith("---")
    cleanup_warnings = result["cleanup_warnings"]
    assert isinstance(cleanup_warnings, list)
    assert len(cleanup_warnings) == 1
    assert "backup is locked" in str(cleanup_warnings[0])
    assert list(destination.parent.glob(".*.idac-backup-*"))
