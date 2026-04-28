from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

from tests.helpers import run_cli, run_cli_json


def test_skill_install_symlink(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    env["CLAUDE_HOME"] = str(tmp_path / ".claude")
    env["CODEX_HOME"] = str(tmp_path / ".codex")

    result = run_cli_json(idac_cmd, env, "misc", "skill", "install")

    destinations = [Path(str(item)) for item in result["destinations"]]
    assert result["installed"] is True
    assert len(destinations) == 2
    assert all(dest.is_symlink() for dest in destinations)
    expected = (Path(__file__).resolve().parents[1] / "src" / "idac" / "skills" / "idac").resolve()
    assert all(dest.resolve() == expected for dest in destinations)


def test_skill_install_symlink_single_host(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    env["CLAUDE_HOME"] = str(tmp_path / ".claude")
    env["CODEX_HOME"] = str(tmp_path / ".codex")

    result = run_cli_json(idac_cmd, env, "misc", "skill", "install", "--host", "claude")

    destinations = [Path(str(item)) for item in result["destinations"]]
    assert result["installed"] is True
    assert len(destinations) == 1
    dest = destinations[0]
    assert dest == tmp_path / ".claude" / "skills" / "idac"
    assert dest.is_symlink()


def test_skill_install_copy_custom_dest(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    dest = tmp_path / "skills" / "idac"

    result = run_cli_json(idac_cmd, env, "misc", "skill", "install", "--mode", "copy", "--dest", str(dest))

    assert result["installed"] is True
    assert result["destinations"] == [str(dest)]
    assert dest.exists()
    assert not dest.is_symlink()
    assert (dest / "SKILL.md").exists()
    assert (dest / "agents" / "openai.yaml").exists()


def test_skill_install_refuses_existing_destination_without_force(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    dest = tmp_path / "skills" / "idac"
    dest.mkdir(parents=True)
    (dest / "stale.txt").write_text("keep", encoding="utf-8")

    proc = run_cli(idac_cmd, env, "misc", "skill", "install", "--mode", "copy", "--dest", str(dest))

    assert proc.returncode == 1
    assert f"destination already exists: {dest}" in proc.stderr
    assert (dest / "stale.txt").read_text(encoding="utf-8") == "keep"


def test_skill_install_force_replaces_existing_custom_copy(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    dest = tmp_path / "skills" / "idac"
    dest.mkdir(parents=True)
    (dest / "stale.txt").write_text("remove me", encoding="utf-8")

    result = run_cli_json(
        idac_cmd,
        env,
        "misc",
        "skill",
        "install",
        "--mode",
        "copy",
        "--dest",
        str(dest),
        "--force",
    )

    assert result["installed"] is True
    assert result["destinations"] == [str(dest)]
    assert not (dest / "stale.txt").exists()
    assert (dest / "SKILL.md").exists()
    assert (dest / "agents" / "openai.yaml").exists()


def test_plugin_install_symlink(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    env["IDAUSR"] = str(tmp_path / ".idapro")

    result = run_cli_json(idac_cmd, env, "misc", "plugin", "install")

    package_dest = Path(str(result["package_destination"]))
    bootstrap_dest = Path(str(result["bootstrap_destination"]))
    runtime_package_dest = Path(str(result["runtime_package_destination"]))
    assert package_dest.is_symlink()
    assert bootstrap_dest.is_symlink()
    assert runtime_package_dest.is_symlink()
    assert (
        package_dest.resolve()
        == (Path(__file__).resolve().parents[1] / "src" / "idac" / "ida_plugin" / "idac_bridge").resolve()
    )
    assert (
        bootstrap_dest.resolve()
        == (Path(__file__).resolve().parents[1] / "src" / "idac" / "ida_plugin" / "idac_bridge_plugin.py").resolve()
    )
    assert runtime_package_dest.resolve() == (Path(__file__).resolve().parents[1] / "src" / "idac").resolve()


def test_plugin_install_copy_custom_dest(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    env = dict(idac_env)
    dest = tmp_path / "plugins" / "idac_bridge"

    result = run_cli_json(idac_cmd, env, "misc", "plugin", "install", "--mode", "copy", "--dest", str(dest))

    package_dest = Path(str(result["package_destination"]))
    bootstrap_dest = Path(str(result["bootstrap_destination"]))
    runtime_package_dest = Path(str(result["runtime_package_destination"]))
    assert package_dest == dest
    assert bootstrap_dest == dest.parent / "idac_bridge_plugin.py"
    assert runtime_package_dest == dest.parent / "idac"
    assert package_dest.exists()
    assert not package_dest.is_symlink()
    assert (package_dest / "__init__.py").exists()
    assert bootstrap_dest.exists()
    assert not bootstrap_dest.is_symlink()
    assert runtime_package_dest.exists()
    assert not runtime_package_dest.is_symlink()
    assert (runtime_package_dest / "cli.py").exists()


def test_plugin_install_refuses_existing_destination_without_force(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    dest = tmp_path / "plugins" / "idac_bridge"
    dest.mkdir(parents=True)
    (dest / "stale.txt").write_text("keep", encoding="utf-8")

    proc = run_cli(idac_cmd, env, "misc", "plugin", "install", "--mode", "copy", "--dest", str(dest))

    assert proc.returncode == 1
    assert f"destination already exists: {dest}" in proc.stderr
    assert (dest / "stale.txt").read_text(encoding="utf-8") == "keep"
    assert not (dest.parent / "idac_bridge_plugin.py").exists()
    assert not (dest.parent / "idac").exists()


def test_plugin_install_force_replaces_existing_copy_targets(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(idac_env)
    dest = tmp_path / "plugins" / "idac_bridge"
    bootstrap_dest = dest.parent / "idac_bridge_plugin.py"
    runtime_dest = dest.parent / "idac"
    dest.mkdir(parents=True)
    runtime_dest.mkdir()
    (dest / "stale.txt").write_text("remove me", encoding="utf-8")
    bootstrap_dest.write_text("stale bootstrap\n", encoding="utf-8")
    (runtime_dest / "stale.txt").write_text("remove me", encoding="utf-8")

    result = run_cli_json(
        idac_cmd,
        env,
        "misc",
        "plugin",
        "install",
        "--mode",
        "copy",
        "--dest",
        str(dest),
        "--force",
    )

    assert result["installed"] is True
    assert result["package_destination"] == str(dest)
    assert result["bootstrap_destination"] == str(bootstrap_dest)
    assert result["runtime_package_destination"] == str(runtime_dest)
    assert not (dest / "stale.txt").exists()
    assert not (runtime_dest / "stale.txt").exists()
    assert (dest / "__init__.py").exists()
    assert (bootstrap_dest).exists()
    assert (runtime_dest / "cli.py").exists()


def test_plugin_install_copy_custom_dest_is_importable_without_repo_root(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path, monkeypatch
) -> None:
    env = dict(idac_env)
    dest = tmp_path / "plugins" / "idac_bridge"

    run_cli_json(idac_cmd, env, "misc", "plugin", "install", "--mode", "copy", "--dest", str(dest))

    plugins_dir = dest.parent
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
