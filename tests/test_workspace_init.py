from __future__ import annotations

import subprocess
from pathlib import Path

from tests.helpers import run_cli


def _git_repo_root(path: Path) -> Path:
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return Path(proc.stdout.strip()).resolve()


def test_workspace_init_creates_expected_tree(idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path) -> None:
    dest = tmp_path / "firmware-audit"

    proc = run_cli(idac_cmd, idac_env, "workspace", "init", str(dest))

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert (dest / ".claude" / "settings.json").is_file()
    assert (dest / ".codex" / "config.toml").is_file()
    assert (dest / ".codex" / "rules" / "default.rules").is_file()
    assert (dest / "CLAUDE.md").is_file()
    assert (dest / "AGENTS.md").is_file()
    assert (dest / ".gitignore").is_file()
    assert (dest / ".idac" / "tmp").is_dir()
    assert (dest / "audit").is_dir()
    assert (dest / "headers" / "recovered").is_dir()
    assert (dest / "headers" / "vendor").is_dir()
    assert (dest / "scripts").is_dir()
    assert not any(path.is_file() and path.name != ".gitkeep" for path in (dest / "scripts").iterdir())
    assert (dest / "prompts" / "general-analysis.md").is_file()
    assert (dest / "reference" / "cli.md").is_file()
    assert (dest / "reference" / "class-recovery.md").is_file()
    assert (dest / ".git").is_dir()
    assert _git_repo_root(dest) == dest.resolve()
    assert "Initialized git repository." in proc.stdout
    assert ".claude/" in proc.stdout
    assert ".codex/rules/" in proc.stdout
    assert "audit/.gitkeep" in proc.stdout
    assert "prompts/general-analysis.md" in proc.stdout
    assert "reference/cli.md" in proc.stdout
    assert "reference/workflows.md" in proc.stdout
    assert ".idac/" in proc.stdout
    assert ".idac/tmp/" in proc.stdout


def test_workspace_init_into_existing_empty_directory_succeeds(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    dest = tmp_path / "existing"
    dest.mkdir()

    proc = run_cli(idac_cmd, idac_env, "workspace", "init", str(dest))

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert (dest / ".idac" / "tmp").is_dir()
    assert (dest / "CLAUDE.md").is_file()
    assert (dest / "reference" / "cli.md").is_file()


def test_workspace_init_refuses_existing_workspace_without_force(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    dest = tmp_path / "workspace"
    first = run_cli(idac_cmd, idac_env, "workspace", "init", str(dest))
    assert first.returncode == 0, first.stderr or first.stdout

    second = run_cli(idac_cmd, idac_env, "workspace", "init", str(dest))

    assert second.returncode == 1
    assert "workspace already initialized (use --force to overwrite config)" in second.stderr


def test_workspace_init_force_overwrites_config_but_preserves_content(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    dest = tmp_path / "workspace"
    proc = run_cli(idac_cmd, idac_env, "workspace", "init", str(dest))
    assert proc.returncode == 0, proc.stderr or proc.stdout

    claude_path = dest / "CLAUDE.md"
    prompt_path = dest / "prompts" / "general-analysis.md"
    reference_path = dest / "reference" / "cli.md"
    custom_audit_note = dest / "audit" / "finding.txt"
    original_claude = claude_path.read_text(encoding="utf-8")

    claude_path.write_text("custom claude content\n", encoding="utf-8")
    prompt_path.write_text("custom prompt content\n", encoding="utf-8")
    reference_path.write_text("custom reference content\n", encoding="utf-8")
    custom_audit_note.write_text("keep me\n", encoding="utf-8")

    forced = run_cli(idac_cmd, idac_env, "workspace", "init", str(dest), "--force")

    assert forced.returncode == 0, forced.stderr or forced.stdout
    assert claude_path.read_text(encoding="utf-8") == original_claude
    assert prompt_path.read_text(encoding="utf-8") == "custom prompt content\n"
    assert reference_path.read_text(encoding="utf-8") == "custom reference content\n"
    assert custom_audit_note.read_text(encoding="utf-8") == "keep me\n"
    assert "Overwrote:" in forced.stdout
    assert "CLAUDE.md" in forced.stdout


def test_workspace_init_adopts_existing_parent_repo_without_nesting(
    idac_cmd: list[str], idac_env: dict[str, str], tmp_path: Path
) -> None:
    repo_root = tmp_path / "engagement"
    repo_root.mkdir()
    init_proc = subprocess.run(
        ["git", "-C", str(repo_root), "init"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert init_proc.returncode == 0, init_proc.stderr or init_proc.stdout
    dest = repo_root / "workspace"

    proc = run_cli(idac_cmd, idac_env, "workspace", "init", str(dest))

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert not (dest / ".git").exists()
    assert _git_repo_root(dest) == repo_root.resolve()
    assert "Using existing git repository:" in proc.stdout
