from __future__ import annotations

from idac.paths import skill_source_dir


def test_bundled_skill_contains_supported_host_entrypoints() -> None:
    skill_root = skill_source_dir()

    assert (skill_root / "SKILL.md").is_file()
    assert (skill_root / ".claude-plugin" / "plugin.json").is_file()
    assert (skill_root / "agents" / "openai.yaml").is_file()
