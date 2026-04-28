from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from idac.output import resolve_output_format, write_output_result


def test_resolve_output_format_prefers_jsonl_suffix() -> None:
    assert resolve_output_format("text", Path("rows.jsonl")) == "jsonl"


def test_resolve_output_format_honors_forced_format() -> None:
    assert resolve_output_format("text", Path("rows.jsonl"), force_fmt=True) == "text"


def test_write_output_result_renders_jsonl_rows() -> None:
    result = write_output_result(
        [{"b": 2, "a": 1}, {"a": 3}],
        fmt="jsonl",
        out_path=None,
        stem="rows",
    )

    assert result.artifact is None
    assert [json.loads(line) for line in result.rendered.splitlines()] == [{"a": 1, "b": 2}, {"a": 3}]


def test_write_output_result_infers_jsonl_artifact_format(tmp_path: Path) -> None:
    out_path = tmp_path / "rows.jsonl"

    result = write_output_result(
        [{"b": 2, "a": 1}, {"a": 3}],
        fmt="text",
        out_path=out_path,
        stem="rows",
    )

    assert result.rendered == ""
    assert result.artifact is not None
    assert result.artifact["format"] == "jsonl"
    assert [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()] == [
        {"a": 1, "b": 2},
        {"a": 3},
    ]


def test_write_output_result_can_force_text_for_json_suffix(tmp_path: Path) -> None:
    out_path = tmp_path / "combined.json"

    result = write_output_result(
        "int main(void) { return 0; }\n",
        fmt="text",
        out_path=out_path,
        stem="decompile_bulk",
        force_fmt=True,
    )

    assert result.rendered == ""
    assert result.artifact is not None
    assert result.artifact["format"] == "text"
    assert out_path.read_text(encoding="utf-8") == "int main(void) { return 0; }\n"


def test_write_output_result_atomically_replaces_existing_artifact(tmp_path: Path) -> None:
    out_path = tmp_path / "decompile.txt"
    out_path.write_text("old\n", encoding="utf-8")

    result = write_output_result(
        "new decompile text\n",
        fmt="text",
        out_path=out_path,
        stem="decompile",
    )

    assert result.rendered == ""
    assert result.artifact is not None
    assert out_path.read_text(encoding="utf-8") == "new decompile text\n"
    assert not any(path.name.startswith(f".{out_path.name}.") for path in tmp_path.iterdir())


def test_write_output_result_preserves_symlink_output_target(tmp_path: Path) -> None:
    real_path = tmp_path / "real.txt"
    real_path.write_text("old\n", encoding="utf-8")
    link_path = tmp_path / "link.txt"
    link_path.symlink_to(real_path.name)

    result = write_output_result(
        "new through symlink\n",
        fmt="text",
        out_path=link_path,
        stem="decompile",
    )

    assert result.rendered == ""
    assert result.artifact is not None
    assert link_path.is_symlink()
    assert os.readlink(link_path) == real_path.name
    assert real_path.read_text(encoding="utf-8") == "new through symlink\n"
    assert link_path.resolve() == real_path.resolve()


def test_write_output_result_preserves_existing_mode_bits(tmp_path: Path) -> None:
    out_path = tmp_path / "shared.txt"
    out_path.write_text("old\n", encoding="utf-8")
    os.chmod(out_path, 0o664)

    result = write_output_result(
        "new\n",
        fmt="text",
        out_path=out_path,
        stem="decompile",
    )

    assert result.rendered == ""
    assert result.artifact is not None
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o664


def test_write_output_result_honors_umask_for_new_artifact(tmp_path: Path) -> None:
    out_path = tmp_path / "fresh.txt"
    previous_umask = os.umask(0o027)
    try:
        result = write_output_result(
            "new\n",
            fmt="text",
            out_path=out_path,
            stem="decompile",
        )
    finally:
        os.umask(previous_umask)

    assert result.rendered == ""
    assert result.artifact is not None
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o640
