from __future__ import annotations

from pathlib import Path

from idac.paths import skill_source_dir, workspace_template_source_dir


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_plugin_assets_exist_in_single_packaged_location() -> None:
    plugin_root = _repo_root() / "src" / "idac" / "ida_plugin"
    expected = {
        "idac_bridge/__init__.py",
        "idac_bridge/bridge.py",
        "idac_bridge/handlers.py",
        "idac_bridge/protocol.py",
        "idac_bridge_plugin.py",
    }
    for relative in expected:
        assert (plugin_root / relative).is_file()


def test_packaged_skill_assets_match_checkout_sources_when_duplicated() -> None:
    repo_root = _repo_root()
    expected = {
        "SKILL.md",
        "agents/openai.yaml",
        "references/class-recovery.md",
        "references/cli.md",
        "references/targets-and-backends.md",
        "references/troubleshooting.md",
        "references/workflows.md",
    }
    packaged_root = skill_source_dir()
    checkout_root = repo_root / "src" / "idac" / "skills" / "idac"

    for relative in expected:
        packaged_path = packaged_root / relative
        assert packaged_path.is_file()
        repo_path = checkout_root / relative
        assert repo_path.is_file()
        assert packaged_path.read_text(encoding="utf-8") == repo_path.read_text(encoding="utf-8")


def test_workspace_template_assets_exist_in_single_packaged_location() -> None:
    template_root = workspace_template_source_dir()
    expected = {
        ".claude/settings.json",
        ".codex/config.toml",
        ".codex/rules/default.rules",
        ".gitignore",
        "AGENTS.md",
        "CLAUDE.md",
        "audit/.gitkeep",
        "headers/recovered/.gitkeep",
        "headers/vendor/.gitkeep",
        "prompts/general-analysis.md",
        "scripts/.gitkeep",
    }

    for relative in expected:
        assert (template_root / relative).is_file()
