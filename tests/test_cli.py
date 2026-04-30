from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from idac.cli import build_parser, main
from idac.cli2 import batch as batch_module
from idac.cli2.errors import CliUserError
from idac.cli2.result import CommandResult

FIXTURE_DB = "db:fixtures/idb/tiny.i64"


def _help_text(parser, *args: str, capsys) -> str:
    with pytest.raises(SystemExit):
        parser.parse_args([*list(args), "--help"])
    return capsys.readouterr().out


@pytest.fixture
def short_runtime_dir(monkeypatch):
    runtime_dir = Path(tempfile.mkdtemp(prefix="idacrt-", dir="/tmp"))
    monkeypatch.setenv("IDAC_RUNTIME_DIR", str(runtime_dir))
    try:
        yield runtime_dir
    finally:
        shutil.rmtree(runtime_dir, ignore_errors=True)


def _copied_fixture_db(copy_database, tiny_database: Path) -> str:
    return f"db:{copy_database(tiny_database)}"


def test_root_help_shows_misc_and_hides_old_names(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, capsys=capsys)

    assert "docs" in help_text
    assert "misc" in help_text
    assert "decompilemany" in help_text
    assert "strings" not in help_text


def test_root_help_mentions_global_context_forwarding(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, capsys=capsys)

    assert "-c LOCATOR" in help_text
    assert "--timeout TIMEOUT" in help_text


def test_root_full_help_shows_misc_and_hides_old_function_show(capsys) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--full-help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "# idac function metadata" in help_text
    assert "# idac function show" not in help_text
    assert "# idac docs" in help_text
    assert "# idac misc" in help_text
    assert "# idac misc reanalyze" in help_text
    assert "# idac misc plugin install" in help_text
    assert "# idac misc skill install" in help_text
    assert "# idac segment list" in help_text
    assert "# idac targets list" in help_text
    assert "# idac targets cleanup" in help_text
    assert "# idac doctor check" not in help_text
    assert "# idac doctor targets" not in help_text
    assert "# idac doctor cleanup" not in help_text
    assert "# idac search strings" in help_text


def test_function_help_uses_metadata_and_prototype(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "function", capsys=capsys)

    assert "metadata" in help_text
    assert "callers" in help_text
    assert "callees" in help_text
    assert "prototype" in help_text


def test_function_list_help_mentions_name_filter_regex_and_ignore_case(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "function", "list", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "NAME_FILTER" in help_text
    assert "not a list of function names" in normalized_help
    assert "--limit" in help_text
    assert "--demangle" in help_text
    assert "--regex" in help_text
    assert "--ignore-case" in help_text


def test_database_help_omits_segments(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "database", capsys=capsys)

    assert "show" in help_text
    assert "segments" not in help_text


def test_database_segments_command_is_not_registered(capsys) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["database", "segments"])

    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_segment_list_help_mentions_filter_regex_and_ignore_case(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "segment", "list", capsys=capsys)

    assert "SEGMENT_FILTER" in help_text
    assert "--regex" in help_text
    assert "--ignore-case" in help_text


def test_search_help_lists_bytes_and_strings(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "search", capsys=capsys)

    assert "bytes" in help_text
    assert "strings" in help_text


def test_search_strings_help_mentions_scan_flag(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "search", "strings", capsys=capsys)

    assert "TEXT_FILTER" in help_text
    assert "--scan" in help_text
    assert "defined strings" in help_text
    assert "examples:" in help_text


def test_search_bytes_help_clarifies_ida_byte_pattern(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "search", "bytes", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "BYTE_PATTERN" in help_text
    assert "IDA byte pattern" in normalized_help
    assert "not a regex" in normalized_help
    assert "examples:" in help_text


def test_preview_help_mentions_wrapped_command_and_out(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "preview", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "COMMAND..." in help_text
    assert "without the leading `idac`" in normalized_help
    assert "requires --out" in normalized_help
    assert "examples:" in help_text


def test_batch_help_mentions_file_format_and_relative_paths(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "batch", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "BATCH_FILE" in help_text
    assert "one shell-like idac subcommand per line" in normalized_help
    assert "relative child paths" in normalized_help
    assert "preview lines are allowed" in normalized_help


def test_locals_help_clarifies_selector_and_new_name(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "function", "locals", "rename", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "LOCAL_SELECTOR" in help_text
    assert "--new-name" in help_text
    assert "prefer --local-id or --index" in normalized_help
    assert "examples:" in help_text


def test_doctor_help_is_direct_health_check(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "doctor", capsys=capsys)

    assert "--backend" not in help_text
    assert "-c LOCATOR" not in help_text
    assert "--timeout" in help_text
    assert "--json" in help_text
    assert "check" not in help_text
    assert "targets" not in help_text
    assert "cleanup" not in help_text
    assert "plugin" not in help_text
    assert "skill" not in help_text


def test_docs_default_prints_agent_oriented_index(capsys) -> None:
    exit_code = main(["docs"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Use `idac docs TOPIC`" in output
    assert "CLI and operation help:" in output
    assert "IDA reference:" in output
    assert "Workflows:" in output
    assert "Workspace resources:" in output
    assert "idac docs cli" in output
    assert "idac docs workflows" in output
    assert "idac docs class-recovery" in output
    assert output.index("idac docs cli") < output.index("idac docs troubleshooting")
    assert output.index("idac docs troubleshooting") < output.index("idac docs ida-cpp-type-details")
    assert output.index("idac docs ida-cpp-type-details") < output.index("idac docs workflows")


def test_docs_topic_prints_bundled_reference(capsys) -> None:
    exit_code = main(["docs", "cli"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "# idac Quick Reference" in output
    assert "The command grammar for the `idac` CLI." in output


def test_docs_large_topic_prints_inline(capsys) -> None:
    exit_code = main(["docs", "class-recovery"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "# Class Recovery" in output
    assert "## Practical caveat" in output


def test_docs_list_prints_available_topics(capsys) -> None:
    exit_code = main(["docs", "--list"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "CLI and operation help:" in output
    assert "IDA reference:" in output
    assert "Workspace resources:" in output
    assert "cli" in output
    assert "workflows" in output
    assert "class-recovery" in output
    assert "ida-cpp-type-details" in output
    assert "prototype-pass" not in output
    assert "prompt-class-recovery-pass" not in output
    assert "claude-workspace" not in output
    assert "skill" not in output
    assert output.index("  cli") < output.index("  troubleshooting")
    assert output.index("  troubleshooting") < output.index("  targets")
    assert output.index("  targets") < output.index("  ida-cpp-type-details")
    assert output.index("  ida-advanced-type-annotations") < output.index("  workflows")


def test_docs_json_includes_topic_metadata(capsys) -> None:
    exit_code = main(["docs", "workspace", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["topic"] == "workspace"
    assert payload["title"] == "Workspace Instructions"
    assert "AGENTS.md" in payload["path"]
    assert "# Workspace" in payload["text"]


def test_docs_rejects_unknown_topic(capsys) -> None:
    exit_code = main(["docs", "nope"])

    assert exit_code == 1
    error = capsys.readouterr().err
    assert "unknown docs topic: nope" in error
    assert "prototype-pass" not in error
    assert "prompt-class-recovery-pass" not in error


def test_docs_rejects_root_context(capsys) -> None:
    exit_code = main(["-c", "db:/tmp/demo.i64", "docs"])

    assert exit_code == 1
    assert "`idac docs` does not accept -c/--context" in capsys.readouterr().err


def test_targets_help_keeps_list_cleanup_only(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "targets", capsys=capsys)

    assert "list" in help_text
    assert "cleanup" in help_text
    assert "plugin" not in help_text
    assert "skill" not in help_text


def test_old_doctor_subcommands_are_not_registered(capsys) -> None:
    parser = build_parser()

    for subcommand in ("check", "targets", "cleanup"):
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["doctor", subcommand])

        assert exc.value.code == 2
        assert f"unrecognized arguments: {subcommand}" in capsys.readouterr().err


def test_doctor_backend_option_is_not_registered(capsys) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["doctor", "--backend", "gui"])

    assert exc.value.code == 2
    assert "unrecognized arguments: --backend gui" in capsys.readouterr().err


def test_doctor_context_is_not_registered(capsys) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["doctor", "-c", "db:/tmp/demo.i64"])

    assert exc.value.code == 2
    assert "unrecognized arguments: -c db:/tmp/demo.i64" in capsys.readouterr().err


def test_doctor_rejects_root_context(capsys) -> None:
    exit_code = main(["-c", "db:/tmp/demo.i64", "doctor"])

    assert exit_code == 1
    assert "`idac doctor` does not accept -c/--context" in capsys.readouterr().err


def test_doctor_accepts_root_timeout(capsys, monkeypatch) -> None:
    captured = {}

    def fake_run_doctor(**kwargs):
        captured.update(kwargs)
        return {
            "backend": "all",
            "healthy": True,
            "status": "ok",
            "checks": [],
        }

    monkeypatch.setattr("idac.cli2.commands.doctor.run_doctor", fake_run_doctor)

    exit_code = main(["--timeout", "2.5", "doctor"])

    assert exit_code == 0
    assert captured == {"backend": "all", "timeout": 2.5}
    assert "status: ok" in capsys.readouterr().out


def test_targets_list_sends_list_targets_request(capsys, monkeypatch) -> None:
    captured = {}

    def fake_send_request(request):
        captured["request"] = request
        return {
            "ok": True,
            "result": [
                {
                    "selector": "pid:1234",
                    "status": "active",
                    "module": "tiny",
                    "pid": 1234,
                }
            ],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["targets", "list", "-c", "pid:1234"])

    assert exit_code == 0
    assert captured["request"].op == "list_targets"
    assert captured["request"].backend == "gui"
    assert captured["request"].target == "pid:1234"
    assert "pid:1234 (tiny)" in capsys.readouterr().out


def test_targets_cleanup_uses_cleanup_runner(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        "idac.cli2.commands.targets.run_doctor_cleanup",
        lambda: {
            "runtime_dir": "/tmp/idac",
            "removed_count": 1,
            "kept_count": 2,
            "missing_count": 0,
        },
    )

    exit_code = main(["targets", "cleanup"])

    assert exit_code == 0
    assert "removed: 1" in capsys.readouterr().out


def test_py_help_only_exposes_exec(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "py", capsys=capsys)

    assert "{exec}" in help_text
    assert "eval" not in help_text


def test_decompilemany_help_mentions_file_and_output_modes(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "decompilemany", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "FUNCTION_FILTER" in help_text
    assert "--file" in help_text
    assert "--functions-file" in help_text
    assert "--out-file" in help_text
    assert "--out-dir" in help_text
    assert "--regex" in help_text
    assert "This is not a list of function names" in normalized_help
    assert "one per line" in normalized_help
    assert "examples:" in help_text


def test_decompilemany_accepts_functions_file_alias(tmp_path: Path) -> None:
    parser = build_parser()
    functions_file = tmp_path / "funcs.txt"
    out_dir = tmp_path / "decomp"

    args = parser.parse_args(["decompilemany", "--functions-file", str(functions_file), "--out-dir", str(out_dir)])

    assert args.file == functions_file
    assert args.out_dir == out_dir


def test_decompilemany_rejects_multiple_positional_exact_functions(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "decomp"

    exit_code = main(["decompilemany", "main", "add", "--out-dir", str(out_dir), "-c", "db:/tmp/demo.i64"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "decompilemany accepts one FUNCTION_FILTER" in captured.err
    assert "--functions-file/--file" in captured.err


def test_type_list_help_uses_type_filter(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "type", "list", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "TYPE_FILTER" in help_text
    assert "requires --out" in normalized_help
    assert "Interpret TYPE_FILTER" in normalized_help


def test_type_declare_help_clarifies_decl_file_and_examples(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "type", "declare", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "--decl-file" in help_text
    assert "C/C++ declarations" in normalized_help
    assert "--bisect" in help_text
    assert "--clang" in help_text
    assert "examples:" in help_text


def test_type_class_candidates_help_uses_candidate_filter(capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, "type", "class", "candidates", capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert "CANDIDATE_FILTER" in help_text
    assert "Use --kind to narrow candidate categories" in normalized_help
    assert "Interpret CANDIDATE_FILTER" in normalized_help


@pytest.mark.parametrize(
    ("command_args", "filter_name"),
    [
        (("type", "class", "list"), "CLASS_FILTER"),
        (("type", "struct", "list"), "STRUCT_FILTER"),
        (("type", "enum", "list"), "ENUM_FILTER"),
    ],
)
def test_type_family_list_help_uses_specific_filters(command_args: tuple[str, ...], filter_name: str, capsys) -> None:
    parser = build_parser()
    help_text = _help_text(parser, *command_args, capsys=capsys)
    normalized_help = " ".join(help_text.split())

    assert filter_name in help_text
    assert f"Interpret {filter_name}" in normalized_help


def test_workspace_init_runs_on_public_cli(tmp_path: Path, capsys) -> None:
    dest = tmp_path / "workspace"

    exit_code = main(["workspace", "init", str(dest), "--format", "json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["initialized"] is True
    assert payload["display_destination"] == str(dest)
    assert payload["created"] == [
        ".claude/",
        ".claude/settings.json",
        ".codex/",
        ".codex/config.toml",
        ".codex/rules/",
        ".codex/rules/default.rules",
        ".gitignore",
        "AGENTS.md",
        "CLAUDE.md",
        "audit/",
        "audit/.gitkeep",
        "headers/",
        "headers/recovered/",
        "headers/recovered/.gitkeep",
        "headers/vendor/",
        "headers/vendor/.gitkeep",
        "prompts/",
        "prompts/class-recovery-pass.md",
        "prompts/general-analysis.md",
        "prompts/reverse-engineer.md",
        "scripts/",
        "scripts/.gitkeep",
        "reference/",
        "reference/class-recovery.md",
        "reference/cli.md",
        "reference/ida-advanced-type-annotations.md",
        "reference/ida-cpp-type-details.md",
        "reference/ida-set-types.md",
        "reference/targets-and-backends.md",
        "reference/templates/",
        "reference/templates/README.md",
        "reference/templates/checkpoint-note.md",
        "reference/templates/locals-jq-snippets.sh",
        "reference/templates/prototype-pass.idac",
        "reference/templates/rename-pass.idac",
        "reference/troubleshooting.md",
        "reference/workflows.md",
        ".idac/",
        ".idac/tmp/",
    ]
    assert (dest / "AGENTS.md").exists()
    assert (dest / "prompts" / "general-analysis.md").exists()
    assert (dest / ".codex" / "config.toml").exists()


def test_main_incomplete_group_command_returns_group_help(capsys) -> None:
    exit_code = main(["function"])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "usage: idac function " in captured.out
    assert "metadata" in captured.out


def test_type_list_without_pattern_requires_out(capsys) -> None:
    exit_code = main(["type", "list", "-c", FIXTURE_DB])

    assert exit_code == 1
    assert "rerun with a pattern or `--out <path>`" in capsys.readouterr().err


def test_function_metadata_smoke(capsys, copy_database, tiny_database: Path, short_runtime_dir) -> None:
    fixture_db = _copied_fixture_db(copy_database, tiny_database)
    exit_code = main(["function", "metadata", "main", "-c", fixture_db])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "main @ 0x100000460" in output
    assert "prototype:" in output


def test_root_context_forwards_to_direct_command(monkeypatch, tmp_path: Path) -> None:
    captured = {}
    out_path = tmp_path / "main.c"

    def fake_send_request(request):
        captured["request"] = request
        return {"ok": True, "result": {"text": "int main(void)\n{\n  return 0;\n}\n"}, "warnings": []}

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["-c", "db:/tmp/demo.i64", "--timeout", "7", "decompile", "main", "--out", str(out_path)])

    assert exit_code == 0
    assert captured["request"].backend == "idalib"
    assert captured["request"].database == "/tmp/demo.i64"
    assert captured["request"].timeout == 7.0


def test_root_context_forwards_to_nested_command(monkeypatch, capsys) -> None:
    captured = {}

    def fake_send_request(request):
        captured["request"] = request
        return {
            "ok": True,
            "result": {"address": "0x1000", "name": "main", "prototype": "int main(void)"},
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["-c", "pid:84428", "function", "metadata", "main", "--format", "json"])

    assert exit_code == 0
    assert captured["request"].backend == "gui"
    assert captured["request"].target == "pid:84428"
    assert json.loads(capsys.readouterr().out)["name"] == "main"


def test_command_local_context_overrides_root_context(monkeypatch, tmp_path: Path) -> None:
    captured = {}
    out_path = tmp_path / "main.c"

    def fake_send_request(request):
        captured["request"] = request
        return {"ok": True, "result": {"text": "int main(void)\n{\n  return 0;\n}\n"}, "warnings": []}

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(
        [
            "-c",
            "db:/tmp/root.i64",
            "decompile",
            "main",
            "-c",
            "db:/tmp/child.i64",
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == 0
    assert captured["request"].database == "/tmp/child.i64"


def test_function_locals_rename_accepts_index_without_positional_selector(capsys, monkeypatch) -> None:
    captured = {}

    def fake_send_request(request):
        captured["request"] = request
        return {"ok": True, "result": {"locals": []}, "warnings": []}

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(
        [
            "function",
            "locals",
            "rename",
            "main",
            "--index",
            "4",
            "--new-name",
            "msgBufferPtr",
            "-c",
            "db:/tmp/demo.i64",
        ]
    )

    assert exit_code == 0
    assert captured["request"].params["identifier"] == "main"
    assert captured["request"].params["index"] == 4
    assert captured["request"].params["new_name"] == "msgBufferPtr"
    assert capsys.readouterr().err == ""


def test_function_locals_rename_rejects_ambiguous_single_positional_with_stable_selector(capsys) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["function", "locals", "rename", "main", "v4", "-c", "db:/tmp/demo.i64"])

    assert exc.value.code == 2
    assert "--new-name" in capsys.readouterr().err


def test_function_locals_retype_accepts_local_id_without_positional_selector(capsys, monkeypatch) -> None:
    captured = {}

    def fake_send_request(request):
        captured["request"] = request
        return {"ok": True, "result": {"locals": []}, "warnings": []}

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(
        [
            "function",
            "locals",
            "retype",
            "main",
            "--local-id",
            "stack(16)@0x100000460",
            "--decl",
            "unsigned int msgBufferPtr;",
            "-c",
            "db:/tmp/demo.i64",
        ]
    )

    assert exit_code == 0
    assert captured["request"].params["identifier"] == "main"
    assert captured["request"].params["local_id"] == "stack(16)@0x100000460"
    assert captured["request"].params["decl"] == "unsigned int msgBufferPtr;"
    assert capsys.readouterr().err == ""


def test_function_locals_retype_accepts_type_shorthand(capsys, monkeypatch) -> None:
    captured = {}

    def fake_send_request(request):
        captured["request"] = request
        return {"ok": True, "result": {"locals": []}, "warnings": []}

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(
        [
            "function",
            "locals",
            "retype",
            "main",
            "--index",
            "4",
            "--type",
            "unsigned int",
            "-c",
            "db:/tmp/demo.i64",
        ]
    )

    assert exit_code == 0
    assert captured["request"].params["identifier"] == "main"
    assert captured["request"].params["index"] == 4
    assert captured["request"].params["decl"] == "unsigned int __idac_local;"
    assert capsys.readouterr().err == ""


def test_function_locals_retype_rejects_positional_selector_with_stable_selector(capsys) -> None:
    exit_code = main(
        [
            "function",
            "locals",
            "retype",
            "main",
            "v4",
            "--index",
            "4",
            "--decl",
            "unsigned int msgBufferPtr;",
            "-c",
            "db:/tmp/demo.i64",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "do not combine a positional selector with --local-id or --index" in captured.err


def test_function_locals_update_rejects_multiple_stable_selectors(capsys) -> None:
    exit_code = main(
        [
            "function",
            "locals",
            "update",
            "main",
            "--local-id",
            "stack(16)@0x100000460",
            "--index",
            "4",
            "--rename",
            "msgBufferPtr",
            "-c",
            "db:/tmp/demo.i64",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--local-id and --index are mutually exclusive" in captured.err


def test_function_locals_update_rejects_positional_selector_with_stable_selector(capsys) -> None:
    exit_code = main(
        [
            "function",
            "locals",
            "update",
            "main",
            "v4",
            "--index",
            "4",
            "--rename",
            "msgBufferPtr",
            "-c",
            "db:/tmp/demo.i64",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "do not combine a positional selector with --local-id or --index" in captured.err


def test_preview_requires_out_outside_batch(capsys) -> None:
    exit_code = main(["preview", "-c", FIXTURE_DB, "function", "metadata", "main"])

    assert exit_code == 1
    assert "preview requires `--out <path.json|path.jsonl>`" in capsys.readouterr().err


def test_preview_rejects_non_previewable_misc_command(tmp_path: Path, capsys) -> None:
    out_path = tmp_path / "preview.json"

    exit_code = main(["preview", "-o", str(out_path), "misc", "rename", "main", "renamed"])

    assert exit_code == 1
    assert "command is not available in preview mode" in capsys.readouterr().err


def test_root_context_forwards_to_preview_wrapper(tmp_path: Path, monkeypatch) -> None:
    captured = {}
    out_path = tmp_path / "preview.json"

    def fake_send_request(request):
        captured["request"] = request
        return {
            "ok": True,
            "result": {
                "before": {"comment": None},
                "after": {"comment": "entry point"},
                "result": {"comment": "entry point"},
                "preview_mode": "undo",
                "persisted": False,
            },
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(
        ["-c", "db:/tmp/demo.i64", "preview", "-o", str(out_path), "comment", "set", "main", "entry point"]
    )

    assert exit_code == 0
    assert captured["request"].backend == "idalib"
    assert captured["request"].database == "/tmp/demo.i64"


def test_batch_allows_preview_and_writes_jsonl(
    tmp_path: Path, copy_database, tiny_database: Path, short_runtime_dir
) -> None:
    fixture_db = _copied_fixture_db(copy_database, tiny_database)
    batch_path = tmp_path / "commands.txt"
    out_path = tmp_path / "batch.jsonl"
    batch_path.write_text(
        "\n".join(
            [
                f"function metadata main -c {fixture_db}",
                f'preview -c {fixture_db} comment set main "entry point"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    exit_code = main(["batch", str(batch_path), "-o", str(out_path)])

    assert exit_code == 0
    rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 2
    assert rows[0]["command"].startswith("function metadata")
    assert rows[1]["command"].startswith("preview ")
    assert rows[1]["result"]["after"]["comment"] == "entry point"


def test_batch_resolves_preview_wrapped_relative_paths(tmp_path: Path, capsys, monkeypatch) -> None:
    batch_dir = tmp_path / "batch"
    cwd = tmp_path / "cwd"
    batch_dir.mkdir()
    cwd.mkdir()
    decl_file = batch_dir / "sub_401000.h"
    decl_file.write_text("int sub_401000(void);\n", encoding="utf-8")
    batch_path = batch_dir / "commands.idac"
    batch_path.write_text(
        "preview -c db:/tmp/demo.i64 function prototype set sub_401000 --decl-file sub_401000.h\n",
        encoding="utf-8",
    )
    captured = {}

    def fake_preview_execute(parsed, *, root_parser):
        captured["decl_file"] = parsed.decl_file
        return CommandResult(
            render_op="proto_set",
            value={
                "before": {"prototype": "int sub_401000(void);"},
                "after": {"prototype": "int sub_401000(void);"},
                "result": {"prototype": "int sub_401000(void);"},
                "preview_mode": "undo",
                "persisted": False,
            },
        )

    monkeypatch.setattr("idac.cli2.preview.execute_parsed", fake_preview_execute)
    monkeypatch.chdir(cwd)

    exit_code = main(["batch", str(batch_path)])

    assert exit_code == 0
    assert captured["decl_file"] == decl_file
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_root_context_forwards_to_batch_children(tmp_path: Path, capsys, monkeypatch) -> None:
    batch_path = tmp_path / "commands.txt"
    batch_path.write_text("function metadata main\n", encoding="utf-8")
    captured = {}

    def fake_send_request(request):
        captured["request"] = request
        return {"ok": True, "result": {"address": "0x1000", "name": "main"}, "warnings": []}

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["-c", "db:/tmp/demo.i64", "batch", str(batch_path)])

    assert exit_code == 0
    assert captured["request"].backend == "idalib"
    assert captured["request"].database == "/tmp/demo.i64"
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_batch_with_out_still_prints_failures_to_stderr(tmp_path: Path, capsys, monkeypatch) -> None:
    batch_path = tmp_path / "commands.txt"
    out_path = tmp_path / "batch.json"
    batch_path.write_text("function metadata missing_symbol -c db:/tmp/demo.i64\n", encoding="utf-8")

    def fake_send_request(request):
        return {"ok": False, "error": "symbol not found: missing_symbol", "warnings": []}

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["batch", str(batch_path), "-o", str(out_path)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "batch line 1:" in captured.err
    assert "symbol not found: missing_symbol" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["results"][0]["stderr"] == "symbol not found: missing_symbol"


def test_batch_reports_renderer_failures_with_structured_fallback(tmp_path: Path, capsys, monkeypatch) -> None:
    batch_path = tmp_path / "commands.txt"
    out_path = tmp_path / "batch.json"
    batch_path.write_text("function metadata main -c db:/tmp/demo.i64\n", encoding="utf-8")

    monkeypatch.setattr(
        "idac.cli2.batch.execute_parsed",
        lambda parsed, *, root_parser: CommandResult(
            render_op="function_show",
            value={"address": "0x1000", "name": "main"},
            exit_code=1,
        ),
    )

    def broken_renderer(value) -> str:
        raise RuntimeError("boom")

    monkeypatch.setitem(batch_module.TEXT_RENDERERS, "function_show", broken_renderer)

    exit_code = main(["batch", str(batch_path), "-o", str(out_path)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "renderer failure while formatting function_show: RuntimeError: boom" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    stderr_text = payload["results"][0]["stderr"]
    assert "renderer failure while formatting function_show: RuntimeError: boom" in stderr_text
    assert '"name": "main"' in stderr_text


def test_batch_preserves_missing_timeout_error_in_structured_output(tmp_path: Path, capsys) -> None:
    batch_path = tmp_path / "commands.txt"
    out_path = tmp_path / "batch.json"
    batch_path.write_text('search bytes "74 69 6e 79" --segment __TEXT\n', encoding="utf-8")

    exit_code = main(["batch", str(batch_path), "-o", str(out_path)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "`idac search bytes` requires --timeout" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["results"][0]["stderr"] == "`idac search bytes` requires --timeout"


def test_batch_preserves_argparse_error_in_structured_output(tmp_path: Path, capsys) -> None:
    batch_path = tmp_path / "commands.txt"
    out_path = tmp_path / "batch.json"
    batch_path.write_text("does-not-exist\n", encoding="utf-8")

    exit_code = main(["batch", str(batch_path), "-o", str(out_path)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid choice: 'does-not-exist'" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert "invalid choice: 'does-not-exist'" in payload["results"][0]["stderr"]


def test_batch_records_incomplete_command_groups_in_structured_output(tmp_path: Path, capsys) -> None:
    batch_path = tmp_path / "commands.txt"
    out_path = tmp_path / "batch.json"
    batch_path.write_text("function\nmisc\n", encoding="utf-8")

    exit_code = main(["batch", str(batch_path), "-o", str(out_path)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: idac function" in captured.err
    assert "usage: idac misc" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["commands_failed"] == 2
    assert payload["results"][0]["exit_code"] == 2
    assert payload["results"][1]["exit_code"] == 2
    assert "usage: idac function" in payload["results"][0]["stderr"]
    assert "usage: idac misc" in payload["results"][1]["stderr"]


def test_type_declare_failure_returns_exit_1_and_stderr(capsys, monkeypatch) -> None:
    def fake_send_request(request):
        return {
            "ok": True,
            "result": {
                "aliases_applied": [],
                "bisect": None,
                "declaration_count": 1,
                "diagnostics": [
                    {
                        "kind": "unterminated_declaration",
                        "line": 1,
                        "message": "declaration does not end with a top-level semicolon",
                    }
                ],
                "errors": 1,
                "imported_types": [],
                "replace": False,
                "replaced_types": [],
                "success": False,
            },
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["type", "declare", "-c", "db:/tmp/demo.i64", "--decl", "struct broken { int x;"])

    assert exit_code == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["success"] is False
    assert "type declare failed:" in captured.err
    assert "line 1:" in captured.err


def test_preview_failure_writes_artifact_and_stderr_summary(tmp_path: Path, capsys, monkeypatch) -> None:
    out_path = tmp_path / "preview.json"

    def fake_send_request(request):
        return {
            "ok": True,
            "result": {
                "aliases_applied": [],
                "bisect": None,
                "before": {"type_count": 1},
                "after": {"type_count": 1},
                "diagnostics": [
                    {
                        "kind": "unterminated_declaration",
                        "line": 1,
                        "message": "declaration does not end with a top-level semicolon",
                    }
                ],
                "errors": 1,
                "imported_types": [],
                "replace": False,
                "replaced_types": [],
                "result": {"success": False},
                "success": False,
            },
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(
        [
            "preview",
            "-o",
            str(out_path),
            "-c",
            "db:/tmp/demo.i64",
            "type",
            "declare",
            "--decl",
            "struct broken { int x;",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "type declare failed:" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "failed"
    assert any("type declare failed:" in line for line in payload["stderr"])


def test_decompilemany_failure_prints_stderr_summary(tmp_path: Path, capsys, monkeypatch) -> None:
    out_dir = tmp_path / "out"

    monkeypatch.setattr(
        "idac.cli2.commands.top_level._decompilemany_targets",
        lambda args: [
            {"identifier": "ok", "name": "ok", "address": "0x1"},
            {"identifier": "bad", "name": "bad", "address": "0x2"},
        ],
    )

    def fake_single(args, *, identifier: str) -> dict[str, object]:
        if identifier == "bad":
            raise CliUserError("symbol not found: bad")
        return {"text": "int ok(void) { return 0; }\n"}

    monkeypatch.setattr("idac.cli2.commands.top_level._run_single_decompile", fake_single)

    exit_code = main(["decompilemany", "demo", "--out-dir", str(out_dir), "-c", "db:/tmp/demo.i64"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "out_dir:" in captured.out
    assert "decompilemany failed for 1/2 function(s)" in captured.err
    assert "bad: symbol not found: bad" in captured.err
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["functions_failed"] == 1


def test_decompilemany_out_file_keeps_raw_text_with_json_suffix(tmp_path: Path, capsys, monkeypatch) -> None:
    out_file = tmp_path / "combined.json"

    monkeypatch.setattr(
        "idac.cli2.commands.top_level._decompilemany_targets",
        lambda args: [
            {"identifier": "first", "name": "first", "address": "0x1"},
            {"identifier": "second", "name": "second", "address": "0x2"},
        ],
    )

    def fake_single(args, *, identifier: str) -> dict[str, object]:
        return {"text": f"int {identifier}(void) {{ return 0; }}\n"}

    monkeypatch.setattr("idac.cli2.commands.top_level._run_single_decompile", fake_single)

    exit_code = main(["decompilemany", "demo", "--out-file", str(out_file), "-c", "db:/tmp/demo.i64"])

    assert exit_code == 0
    capsys.readouterr()
    content = out_file.read_text(encoding="utf-8")
    assert content.startswith("int first(void)")
    assert "\nint second(void)" in content
    with pytest.raises(json.JSONDecodeError):
        json.loads(content)


def test_doctor_with_out_prints_error_summary(tmp_path: Path, capsys, monkeypatch) -> None:
    out_path = tmp_path / "doctor.json"

    captured = {}

    def fake_run_doctor(**kwargs):
        captured.update(kwargs)
        return {
            "backend": kwargs.get("backend", "all"),
            "healthy": False,
            "status": "error",
            "checks": [
                {
                    "component": "gui",
                    "name": "bridge_targets",
                    "status": "error",
                    "summary": "no running GUI bridge instances found",
                }
            ],
        }

    monkeypatch.setattr(
        "idac.cli2.commands.doctor.run_doctor",
        fake_run_doctor,
    )

    exit_code = main(["doctor", "--out", str(out_path)])

    assert exit_code == 1
    assert captured["backend"] == "all"
    assert "database" not in captured
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "doctor failed: backend=all status=error" in captured.err
    assert "gui.bridge_targets: no running GUI bridge instances found" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["healthy"] is False


def test_function_list_with_out_prints_count_summary(tmp_path: Path, capsys, monkeypatch) -> None:
    out_path = tmp_path / "functions.json"

    def fake_send_request(request):
        return {
            "ok": True,
            "result": [
                {"address": "0x1000", "name": "CMessag::init"},
                {"address": "0x1010", "name": "CMessag::run"},
            ],
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["function", "list", "CMessag", "-c", "db:/tmp/demo.i64", "--json", "--out", str(out_path)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"wrote 2 functions to {out_path}" in captured.err
    assert "inspect that file for the full result" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(payload) == 2


def test_database_open_with_out_prints_generic_artifact_notice(tmp_path: Path, capsys, monkeypatch) -> None:
    database_path = tmp_path / "tiny.i64"
    out_path = tmp_path / "open.json"

    def fake_send_request(request):
        return {
            "ok": True,
            "result": {"database": str(database_path), "opened": True},
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["database", "open", str(database_path), "--out", str(out_path)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"wrote result to {out_path}" in captured.err
    assert "inspect that file for the full result" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["opened"] is True


def test_decompile_with_out_prints_specific_artifact_notice(tmp_path: Path, capsys, monkeypatch) -> None:
    out_path = tmp_path / "main.c"

    def fake_send_request(request):
        return {
            "ok": True,
            "result": {"text": "int main(void)\n{\n  return 0;\n}\n"},
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["decompile", "main", "-c", "db:/tmp/demo.i64", "--out", str(out_path)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"wrote decompile text to {out_path}" in captured.err
    assert "inspect that file for the full result" in captured.err
    assert out_path.read_text(encoding="utf-8").startswith("int main")


def test_large_decompile_output_suggests_dash_o(capsys, monkeypatch) -> None:
    def fake_send_request(request):
        return {
            "ok": True,
            "result": {"text": "x" * 12050},
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["decompile", "main", "-c", "db:/tmp/demo.i64"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "rerun with `-o <path>` to write the full decompile to a file" in captured.err
    assert captured.out.startswith("x")


def test_large_locals_output_suggests_json_out(capsys, monkeypatch) -> None:
    locals_rows = [
        {
            "index": i,
            "local_id": f"stack({i * 8})@0x100000460",
            "definition_address": "0x100000460",
            "location": f"stack({i * 8})",
            "name": f"local_{i}_{'x' * 80}",
            "display_name": f"local_{i}_{'x' * 80}",
            "type": "unsigned int",
            "is_arg": False,
            "is_stack": True,
            "stack_offset": i * 8,
            "size": 4,
        }
        for i in range(80)
    ]

    def fake_send_request(request):
        return {
            "ok": True,
            "result": {
                "function": "main",
                "address": "0x100000460",
                "locals": locals_rows,
            },
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["function", "locals", "list", "main", "-c", "db:/tmp/demo.i64"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "rerun with `--json --out <path>` to inspect the full locals table" in captured.err
    assert "main @ 0x100000460" in captured.out


def test_preview_success_with_out_prints_artifact_notice(tmp_path: Path, capsys, monkeypatch) -> None:
    out_path = tmp_path / "preview.json"

    def fake_send_request(request):
        return {
            "ok": True,
            "result": {
                "before": {"comment": None},
                "after": {"comment": "entry point"},
                "result": {"comment": "entry point"},
                "preview_mode": "undo",
                "persisted": False,
            },
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(
        ["preview", "-o", str(out_path), "-c", "db:/tmp/demo.i64", "comment", "set", "main", "entry point"]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"wrote preview data to {out_path}" in captured.err
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["status"] == "ok"


def test_database_open_uses_idalib_backend(monkeypatch, capsys, tmp_path: Path) -> None:
    captured = {}

    def fake_send_request(request):
        captured["request"] = request
        return {
            "ok": True,
            "result": {"database": str(tmp_path / "tiny.i64"), "opened": True},
            "warnings": [],
        }

    monkeypatch.setattr("idac.cli2.commands.common.send_request", fake_send_request)

    exit_code = main(["database", "open", str(tmp_path / "tiny.i64"), "--format", "json"])

    assert exit_code == 0
    assert captured["request"].backend == "idalib"
    assert captured["request"].database is None
    assert json.loads(capsys.readouterr().out)["opened"] is True


def test_bookmark_show_invalid_slot_returns_user_error(capsys) -> None:
    exit_code = main(["bookmark", "show", "-c", FIXTURE_DB, "abc"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "bookmark slot" in captured.err
    assert "Traceback" not in captured.err


def test_type_declare_missing_decl_file_returns_user_error(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.h"

    exit_code = main(["type", "declare", "-c", FIXTURE_DB, "--decl-file", str(missing)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(missing) in captured.err
    assert "Traceback" not in captured.err


def test_root_context_is_rejected_for_contextless_command(tmp_path: Path, capsys) -> None:
    dest = tmp_path / "workspace"

    exit_code = main(["-c", "db:/tmp/demo.i64", "workspace", "init", str(dest)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "`idac workspace init` does not accept -c/--context" in captured.err


def test_root_timeout_is_rejected_for_contextless_command(tmp_path: Path, capsys) -> None:
    dest = tmp_path / "workspace"

    exit_code = main(["--timeout", "5", "workspace", "init", str(dest)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "`idac workspace init` does not accept --timeout" in captured.err
