from __future__ import annotations

import json
from pathlib import Path

import idac.paths as paths
from idac.paths import (
    bridge_registry_paths,
    claude_skills_dir,
    codex_skills_dir,
    ensure_claude_skills_dir,
    ensure_codex_skills_dir,
    ensure_user_runtime_dir,
    hcli_config_dir,
    hcli_configured_install_dir,
    ida_config_path,
    ida_configured_install_dir,
    plugin_bootstrap_install_path,
    plugin_bootstrap_source_path,
    plugin_install_dir,
    plugin_runtime_package_install_dir,
    plugin_runtime_package_source_dir,
    plugin_source_dir,
    skill_install_dir,
    skill_install_dirs,
    skill_reference_source_dir,
    skill_source_dir,
    user_runtime_dir,
    workspace_template_source_dir,
)


def test_read_only_path_getters_do_not_create_directories(monkeypatch, tmp_path: Path) -> None:
    idausr = tmp_path / ".idapro"
    claude_home = tmp_path / ".claude"
    codex_home = tmp_path / ".codex"
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("IDAUSR", str(idausr))
    monkeypatch.setenv("CLAUDE_HOME", str(claude_home))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setattr(paths, "runtime_dir", lambda: runtime)

    assert user_runtime_dir() == runtime
    assert bridge_registry_paths() == []
    assert ida_config_path() == idausr / "ida-config.json"
    assert ida_configured_install_dir() is None
    assert hcli_configured_install_dir() is None
    assert plugin_install_dir() == idausr / "plugins" / "idac_bridge"
    assert plugin_bootstrap_install_path() == idausr / "plugins" / "idac_bridge_plugin.py"
    assert plugin_runtime_package_install_dir() == idausr / "plugins" / "idac"
    assert claude_skills_dir() == claude_home / "skills"
    assert codex_skills_dir() == codex_home / "skills"
    assert skill_install_dir(host="claude") == claude_home / "skills" / "idac"
    assert skill_install_dir() == codex_home / "skills" / "idac"
    assert skill_install_dirs() == [
        claude_home / "skills" / "idac",
        codex_home / "skills" / "idac",
    ]

    assert not idausr.exists()
    assert not claude_home.exists()
    assert not codex_home.exists()


def test_ensure_helpers_create_directories(monkeypatch, tmp_path: Path) -> None:
    idausr = tmp_path / ".idapro"
    claude_home = tmp_path / ".claude"
    codex_home = tmp_path / ".codex"
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("IDAUSR", str(idausr))
    monkeypatch.setenv("CLAUDE_HOME", str(claude_home))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setattr(paths, "runtime_dir", lambda: runtime)

    assert ensure_user_runtime_dir() == runtime
    assert ensure_claude_skills_dir() == claude_home / "skills"
    assert ensure_codex_skills_dir() == codex_home / "skills"
    assert runtime.is_dir()
    assert (claude_home / "skills").is_dir()
    assert (codex_home / "skills").is_dir()


def test_source_paths_resolve_packaged_assets() -> None:
    assert plugin_source_dir().name == "idac_bridge"
    assert (plugin_source_dir() / "__init__.py").exists()
    assert plugin_bootstrap_source_path().name == "idac_bridge_plugin.py"
    assert plugin_bootstrap_source_path().exists()
    assert plugin_runtime_package_source_dir().name == "idac"
    assert skill_source_dir().name == "idac"
    assert skill_source_dir().parent.name == "skills"
    assert (skill_source_dir() / "SKILL.md").exists()
    assert skill_reference_source_dir().name == "references"
    assert (skill_reference_source_dir() / "cli.md").exists()
    assert workspace_template_source_dir().name == "default"
    assert (workspace_template_source_dir() / ".gitignore").exists()


def test_ida_configured_install_dir_reads_user_config(monkeypatch, tmp_path: Path) -> None:
    idausr = tmp_path / ".idapro"
    install_dir = tmp_path / "IDA Professional.app" / "Contents" / "MacOS"
    monkeypatch.setenv("IDAUSR", str(idausr))
    idausr.mkdir()
    ida_config_path().write_text(
        json.dumps({"Paths": {"ida-install-dir": str(install_dir)}}),
        encoding="utf-8",
    )

    assert ida_configured_install_dir() == install_dir


def test_hcli_configured_install_dir_reads_default_instance(monkeypatch, tmp_path: Path) -> None:
    config_dir = tmp_path / "hcli"
    install_dir = tmp_path / "IDA Professional 9.2.app"
    monkeypatch.setattr(paths, "hcli_config_dir", lambda: config_dir)
    config_dir.mkdir()
    (config_dir / "config.json").write_text(
        json.dumps(
            {
                "ida.default": "ida-pro-9.2",
                "ida.instances": {
                    "ida-pro-9.1": str(tmp_path / "IDA Professional 9.1.app"),
                    "ida-pro-9.2": str(install_dir),
                },
            }
        ),
        encoding="utf-8",
    )

    assert hcli_configured_install_dir() == install_dir


def test_hcli_config_dir_uses_macos_location_before_xdg(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    monkeypatch.setattr(paths.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))

    assert hcli_config_dir() == tmp_path / "Library" / "Application Support" / "hcli"


def test_hcli_config_dir_uses_xdg_config_home_off_macos(monkeypatch, tmp_path: Path) -> None:
    xdg_config_home = tmp_path / "xdg-config"
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_config_home))

    assert hcli_config_dir() == xdg_config_home / "hcli"


def test_hcli_config_dir_uses_windows_location_before_xdg(monkeypatch, tmp_path: Path) -> None:
    local_app_data = tmp_path / "LocalAppData"
    monkeypatch.setattr(paths.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))

    assert hcli_config_dir() == local_app_data / "hex-rays" / "hcli"


def test_hcli_configured_install_dir_ignores_missing_default(monkeypatch, tmp_path: Path) -> None:
    config_dir = tmp_path / "hcli"
    monkeypatch.setattr(paths, "hcli_config_dir", lambda: config_dir)
    config_dir.mkdir()
    (config_dir / "config.json").write_text(
        json.dumps(
            {
                "ida.default": "ida-pro-9.3",
                "ida.instances": {"ida-pro-9.2": str(tmp_path / "IDA Professional 9.2.app")},
            }
        ),
        encoding="utf-8",
    )

    assert hcli_configured_install_dir() is None
