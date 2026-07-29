from __future__ import annotations

import importlib
import io
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from idac.cli import main
from tests.helpers import run_cli, run_cli_json


def _target_rows(result: dict[str, Any], component: str) -> list[dict[str, Any]]:
    return [item for item in result["targets"] if item["component"] == component]


def _run_setup_json(idac_cmd: list[str], env: dict[str, str], *args: object) -> dict[str, Any]:
    result = run_cli_json(idac_cmd, env, *args)
    assert isinstance(result, dict)
    return cast(dict[str, Any], result)


class _InteractiveInput(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_setup_install_symlinks_plugin_and_both_skills(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    env["IDAUSR"] = str(tmp_path / ".idapro")
    env["CLAUDE_HOME"] = str(tmp_path / ".claude")
    env["CODEX_HOME"] = str(tmp_path / ".codex")

    result = _run_setup_json(idac_cmd, env, "setup", "install")

    assert result["action"] == "install"
    assert result["phase"] == "applied"
    assert result["components"] == ["plugin", "skill"]
    assert result["changed"] is True
    assert result["ida_reload_recommended"] is True
    assert len(result["targets"]) == 5
    assert {item["status"] for item in result["targets"]} == {"installed"}
    assert all(Path(str(item["destination"])).is_symlink() for item in result["targets"])


def test_setup_install_skill_for_single_agent(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    env["CLAUDE_HOME"] = str(tmp_path / ".claude")
    env["CODEX_HOME"] = str(tmp_path / ".codex")

    result = _run_setup_json(idac_cmd, env, "setup", "install", "--component", "skill", "--agent", "claude")

    targets = _target_rows(result, "skill")
    assert result["components"] == ["skill"]
    assert result["ida_reload_recommended"] is False
    assert len(targets) == 1
    assert targets[0]["name"] == "skill_claude"
    assert targets[0]["destination"] == str(tmp_path / ".claude" / "skills" / "idac")
    assert Path(str(targets[0]["destination"])).is_symlink()
    assert not (tmp_path / ".codex").exists()


def test_setup_install_skill_copy_at_custom_destination(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "skills" / "idac"

    result = _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "install",
        "--component",
        "skill",
        "--mode",
        "copy",
        "--skill-dest",
        str(destination),
    )

    targets = _target_rows(result, "skill")
    assert len(targets) == 1
    assert targets[0]["destination"] == str(destination)
    assert targets[0]["mode"] == "copy"
    assert destination.exists()
    assert not destination.is_symlink()
    assert (destination / "SKILL.md").exists()
    assert (destination / "agents" / "openai.yaml").exists()


def test_setup_install_refuses_all_existing_destinations_before_mutating(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    env["CLAUDE_HOME"] = str(tmp_path / ".claude")
    env["CODEX_HOME"] = str(tmp_path / ".codex")
    claude_destination = tmp_path / ".claude" / "skills" / "idac"
    claude_destination.mkdir(parents=True)
    (claude_destination / "keep.txt").write_text("keep", encoding="utf-8")

    proc = run_cli(idac_cmd, env, "setup", "install", "--component", "skill")

    assert proc.returncode == 1
    assert "setup destination already exists" in proc.stderr
    assert "idac setup update" in proc.stderr
    assert (claude_destination / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / ".codex" / "skills" / "idac").exists()


def test_setup_update_replaces_skill_copy_and_preserves_mode(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "skills" / "idac"
    install_args = (
        "setup",
        "install",
        "--component",
        "skill",
        "--mode",
        "copy",
        "--skill-dest",
        str(destination),
    )
    _run_setup_json(idac_cmd, env, *install_args)
    (destination / "stale.txt").write_text("remove me", encoding="utf-8")

    result = _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "update",
        "--component",
        "skill",
        "--skill-dest",
        str(destination),
        "--force",
    )

    target = _target_rows(result, "skill")[0]
    assert target["status"] == "updated"
    assert target["mode"] == "copy"
    assert not destination.is_symlink()
    assert not (destination / "stale.txt").exists()
    assert (destination / "SKILL.md").exists()


def test_setup_update_installs_missing_default_skill_agent_noninteractively(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    env["CLAUDE_HOME"] = str(tmp_path / ".claude")
    env["CODEX_HOME"] = str(tmp_path / ".codex")
    _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "install",
        "--component",
        "skill",
        "--agent",
        "claude",
        "--mode",
        "copy",
    )

    result = _run_setup_json(idac_cmd, env, "setup", "update", "--component", "skill")

    targets = _target_rows(result, "skill")
    assert {item["status"] for item in targets} == {"installed", "updated"}
    assert {item["mode"] for item in targets} == {"copy"}
    assert not (tmp_path / ".claude" / "skills" / "idac").is_symlink()
    assert not (tmp_path / ".codex" / "skills" / "idac").is_symlink()


def test_setup_update_dry_run_reports_destructive_plan_without_mutating(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "skills"
    destination.mkdir()
    (destination / "important.txt").write_text("keep", encoding="utf-8")

    result = _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "update",
        "--component",
        "skill",
        "--skill-dest",
        str(destination),
        "--dry-run",
    )

    assert result["phase"] == "planned"
    assert result["requires_confirmation"] is True
    assert _target_rows(result, "skill")[0]["status"] == "updated"
    assert (destination / "important.txt").read_text(encoding="utf-8") == "keep"
    assert not (destination / "SKILL.md").exists()


def test_setup_update_requires_force_when_noninteractive(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "skills"
    destination.mkdir()
    (destination / "important.txt").write_text("keep", encoding="utf-8")

    proc = run_cli(
        idac_cmd,
        env,
        "setup",
        "update",
        "--component",
        "skill",
        "--skill-dest",
        str(destination),
        input_text="",
    )

    assert proc.returncode == 1
    assert "Setup update plan (no changes applied)." in proc.stderr
    assert "Existing destinations listed as updated will be replaced in full." in proc.stderr
    assert "inspect with --dry-run and rerun with --force" in proc.stderr
    assert (destination / "important.txt").read_text(encoding="utf-8") == "keep"


def test_setup_update_applies_after_interactive_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    destination = tmp_path / "skills" / "idac"
    (destination / "agents").mkdir(parents=True)
    (destination / "SKILL.md").write_text("old", encoding="utf-8")
    (destination / "agents" / "openai.yaml").write_text("old", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", _InteractiveInput("yes\n"))

    exit_code = main(
        [
            "setup",
            "update",
            "--component",
            "skill",
            "--skill-dest",
            str(destination),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Setup update plan (no changes applied)." in captured.err
    assert "Existing destinations listed as updated will be replaced in full." in captured.err
    assert "Continue? [y/N]" in captured.err
    assert (destination / "SKILL.md").read_text(encoding="utf-8").startswith("---")


def test_setup_update_cancellation_leaves_destination_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    destination = tmp_path / "skills"
    destination.mkdir()
    (destination / "important.txt").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", _InteractiveInput("no\n"))

    exit_code = main(
        [
            "setup",
            "update",
            "--component",
            "skill",
            "--skill-dest",
            str(destination),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Existing destinations listed as updated will be replaced in full." in captured.err
    assert "setup update cancelled" in captured.err
    assert (destination / "important.txt").read_text(encoding="utf-8") == "keep"
    assert not (destination / "SKILL.md").exists()


@pytest.mark.parametrize(
    ("initial_mode", "update_mode", "expected_symlink"),
    [("symlink", "copy", False), ("copy", "symlink", True)],
)
def test_setup_update_changes_installation_mode_when_requested(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    tmp_path: Path,
    initial_mode: str,
    update_mode: str,
    expected_symlink: bool,
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "skills" / "idac"
    _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "install",
        "--component",
        "skill",
        "--skill-dest",
        str(destination),
        "--mode",
        initial_mode,
    )

    result = _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "update",
        "--component",
        "skill",
        "--skill-dest",
        str(destination),
        "--mode",
        update_mode,
        "--force",
    )

    target = _target_rows(result, "skill")[0]
    assert target["status"] == "updated"
    assert target["mode"] == update_mode
    assert destination.is_symlink() is expected_symlink


def test_setup_rejects_agent_with_custom_skill_destination(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    proc = run_cli(
        idac_cmd,
        idac_env,
        "setup",
        "install",
        "--component",
        "skill",
        "--agent",
        "claude",
        "--skill-dest",
        str(tmp_path / "idac"),
    )

    assert proc.returncode == 1
    assert "--agent cannot be combined with --skill-dest" in proc.stderr


def test_setup_install_plugin_symlink(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    env["IDAUSR"] = str(tmp_path / ".idapro")

    result = _run_setup_json(idac_cmd, env, "setup", "install", "--component", "plugin")

    targets = _target_rows(result, "plugin")
    by_name = {item["name"]: Path(str(item["destination"])) for item in targets}
    assert len(targets) == 3
    assert all(destination.is_symlink() for destination in by_name.values())
    repo_package = Path(__file__).resolve().parents[1] / "src" / "idac"
    assert by_name["bridge_package"].resolve() == (repo_package / "ida_plugin" / "idac_bridge").resolve()
    assert by_name["bootstrap"].resolve() == (repo_package / "ida_plugin" / "idac_bridge_plugin.py").resolve()
    assert by_name["runtime_package"].resolve() == repo_package.resolve()


def test_setup_update_keeps_matching_plugin_symlinks_without_recommending_ida_reload(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    env["IDAUSR"] = str(tmp_path / ".idapro")
    _run_setup_json(idac_cmd, env, "setup", "install", "--component", "plugin")

    result = _run_setup_json(idac_cmd, env, "setup", "update", "--component", "plugin")

    targets = _target_rows(result, "plugin")
    assert result["changed"] is False
    assert result["ida_reload_recommended"] is False
    assert {item["status"] for item in targets} == {"unchanged"}


def test_setup_install_plugin_copy_at_custom_destination(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "plugins" / "idac_bridge"

    result = _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "install",
        "--component",
        "plugin",
        "--mode",
        "copy",
        "--plugin-dest",
        str(destination),
    )

    targets = _target_rows(result, "plugin")
    by_name = {item["name"]: Path(str(item["destination"])) for item in targets}
    assert by_name["bridge_package"] == destination
    assert by_name["bootstrap"] == destination.parent / "idac_bridge_plugin.py"
    assert by_name["runtime_package"] == destination.parent / "idac"
    assert (by_name["bridge_package"] / "__init__.py").exists()
    assert by_name["bootstrap"].is_file()
    assert (by_name["runtime_package"] / "cli.py").exists()
    assert all(not path.is_symlink() for path in by_name.values())


def test_setup_update_replaces_plugin_copy_targets(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "plugins" / "idac_bridge"
    install_args = (
        "setup",
        "install",
        "--component",
        "plugin",
        "--mode",
        "copy",
        "--plugin-dest",
        str(destination),
    )
    _run_setup_json(idac_cmd, env, *install_args)
    runtime_destination = destination.parent / "idac"
    (destination / "stale.txt").write_text("remove me", encoding="utf-8")
    (runtime_destination / "stale.txt").write_text("remove me", encoding="utf-8")

    result = _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "update",
        "--component",
        "plugin",
        "--plugin-dest",
        str(destination),
        "--force",
    )

    targets = _target_rows(result, "plugin")
    assert {item["status"] for item in targets} == {"updated"}
    assert {item["mode"] for item in targets} == {"copy"}
    assert result["ida_reload_recommended"] is True
    assert not (destination / "stale.txt").exists()
    assert not (runtime_destination / "stale.txt").exists()


def test_setup_plugin_copy_is_importable_without_repo_root(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path, monkeypatch
) -> None:
    env = dict(idac_env)
    destination = tmp_path / "plugins" / "idac_bridge"
    _run_setup_json(
        idac_cmd,
        env,
        "setup",
        "install",
        "--component",
        "plugin",
        "--mode",
        "copy",
        "--plugin-dest",
        str(destination),
    )

    plugins_dir = destination.parent
    saved_modules = {
        name: sys.modules.pop(name)
        for name in list(sys.modules)
        if name == "idac" or name.startswith(("idac.", "idac_bridge", "idac_bridge_plugin"))
    }
    sys.path.insert(0, str(plugins_dir))
    monkeypatch.setitem(
        sys.modules,
        "idaapi",
        SimpleNamespace(
            plugin_t=object,
            PLUGIN_FIX=1,
            PLUGIN_KEEP=2,
            msg=lambda _text: None,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        SimpleNamespace(MFF_WRITE=1, execute_sync=lambda fn, _flags: fn()),
    )
    try:
        module = importlib.import_module("idac_bridge_plugin")
        imported_idac = importlib.import_module("idac")
    finally:
        sys.path.pop(0)
        for name in list(sys.modules):
            if name == "idac" or name.startswith(("idac.", "idac_bridge", "idac_bridge_plugin")):
                sys.modules.pop(name, None)
        sys.modules.update(saved_modules)

    assert Path(imported_idac.__file__).resolve().is_relative_to((plugins_dir / "idac").resolve())
    assert callable(module.PLUGIN_ENTRY)


def test_setup_plugin_reports_ida_reload_warning(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    env["IDAUSR"] = str(tmp_path / ".idapro")

    proc = run_cli(idac_cmd, env, "setup", "install", "--component", "plugin")

    assert proc.returncode == 0
    assert "Setup install complete." in proc.stdout
    assert "reload the idac bridge plugin" in proc.stderr


def test_removed_misc_installer_commands_are_not_accepted(idac_cmd: list[str], idac_env: dict[str, str]) -> None:
    plugin = run_cli(idac_cmd, idac_env, "misc", "plugin", "install")
    skill = run_cli(idac_cmd, idac_env, "misc", "skill", "install")

    assert plugin.returncode == 2
    assert skill.returncode == 2
    assert "invalid choice: 'plugin'" in plugin.stderr
    assert "invalid choice: 'skill'" in skill.stderr
