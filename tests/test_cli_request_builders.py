from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from idac.cli import main


@pytest.fixture
def database(tmp_path: Path) -> Path:
    path = tmp_path / "sample.i64"
    path.touch()
    return path


@pytest.fixture
def capture_nexus(monkeypatch: pytest.MonkeyPatch):
    class CaptureSession:
        instances: ClassVar[list[CaptureSession]] = []

        def __init__(self, **_kwargs: object) -> None:
            self.calls: list[dict[str, Any]] = []
            self.__class__.instances.append(self)

        def execute_operation(
            self,
            op: str,
            params: dict[str, Any],
            *,
            preview: bool,
            operation_label: str,
        ) -> Any:
            self.calls.append({"op": op, "params": params})
            if op == "function_list":
                return [{"name": "demo", "address": "0x1000"}]
            if op in {"decompile", "disasm", "disasm_range", "ctree"}:
                return {"text": f"{op} output\n"}
            if op in {"type_declare", "type_declare_check"}:
                return {"success": True, "errors": 0}
            return {}

        def close(self) -> None:
            return None

    monkeypatch.setattr("idac.nexus.NexusSession", CaptureSession)
    return CaptureSession


def test_local_update_uses_stable_selector_on_the_wire(database: Path, capture_nexus, capsys) -> None:
    assert (
        main(
            [
                "function",
                "locals",
                "update",
                "main",
                "--local-id",
                "stack(-16)@0x401000",
                "--rename",
                "sum_value",
                "--decl",
                "unsigned int sum_value;",
                "-c",
                str(database),
            ]
        )
        == 0
    )

    assert capture_nexus.instances[0].calls[0]["params"] == {
        "identifier": "main",
        "local_id": "stack(-16)@0x401000",
        "new_name": "sum_value",
        "decl": "unsigned int sum_value;",
    }
    capsys.readouterr()


@pytest.mark.parametrize(
    ("selector_args", "expected_selector"),
    [
        (["v4"], {"old_name": "v4"}),
        (["--index", "4"], {"index": 4}),
    ],
)
def test_local_rename_selector_forms_reach_the_wire(
    selector_args: list[str],
    expected_selector: dict[str, object],
    database: Path,
    capture_nexus,
    capsys,
) -> None:
    assert (
        main(
            [
                "function",
                "locals",
                "rename",
                "main",
                *selector_args,
                "--new-name",
                "msg_buffer",
                "-c",
                str(database),
            ]
        )
        == 0
    )

    assert capture_nexus.instances[0].calls[0]["params"] == {
        "identifier": "main",
        "new_name": "msg_buffer",
        **expected_selector,
    }
    capsys.readouterr()


def test_local_retype_expands_type_shorthand_on_the_wire(database: Path, capture_nexus, capsys) -> None:
    assert (
        main(
            [
                "function",
                "locals",
                "retype",
                "main",
                "v4",
                "--type",
                "unsigned int",
                "-c",
                str(database),
            ]
        )
        == 0
    )

    assert capture_nexus.instances[0].calls[0]["params"] == {
        "identifier": "main",
        "local_name": "v4",
        "decl": "unsigned int __idac_local;",
    }
    capsys.readouterr()


@pytest.mark.parametrize(
    ("command", "message"),
    [
        (
            ["function", "locals", "rename", "main", "--new-name", "renamed"],
            "local selector is required",
        ),
        (
            [
                "function",
                "locals",
                "rename",
                "main",
                "v4",
                "--index",
                "4",
                "--new-name",
                "renamed",
            ],
            "do not combine a positional selector",
        ),
        (
            [
                "function",
                "locals",
                "retype",
                "main",
                "--local-id",
                "stack(-16)@0x401000",
                "--index",
                "4",
                "--type",
                "int",
            ],
            "--local-id and --index are mutually exclusive",
        ),
    ],
)
def test_local_selector_conflicts_fail_before_dispatch(
    command: list[str],
    message: str,
    database: Path,
    capture_nexus,
    capsys,
) -> None:
    assert main([*command, "-c", str(database)]) == 1

    assert message in capsys.readouterr().err
    assert all(not session.calls for session in capture_nexus.instances)


def test_decompilemany_writes_requested_artifacts_and_manifest(
    database: Path,
    capture_nexus,
    tmp_path: Path,
    capsys,
) -> None:
    out_dir = tmp_path / "out"

    assert (
        main(
            [
                "decompilemany",
                "demo",
                "--out-dir",
                str(out_dir),
                "--regex",
                "--f5",
                "--disasm",
                "--ctree",
                "-c",
                str(database),
            ]
        )
        == 0
    )

    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["pattern"] == "demo"
    assert manifest["functions_total"] == 1
    assert manifest["functions_succeeded"] == 1
    assert manifest["functions_failed"] == 0

    [function] = manifest["functions"]
    assert function["identifier"] == "demo"
    assert function["ok"] is True
    assert set(function["artifacts"]) == {"decompile", "disasm", "ctree"}
    for kind, path in function["artifacts"].items():
        assert Path(path).read_text(encoding="utf-8") == f"{kind} output\n"

    calls = capture_nexus.instances[0].calls
    assert {
        "op": "function_list",
        "params": {"pattern": "demo", "regex": True, "ignore_case": False},
    } in calls
    assert {"op": "decompile", "params": {"identifier": "demo", "no_cache": True}} in calls
    capsys.readouterr()


def test_decompilemany_rejects_extra_positional_filters(database: Path, capture_nexus, tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "decompilemany",
                "main",
                "helper",
                "--out-dir",
                str(tmp_path / "out"),
                "-c",
                str(database),
            ]
        )
        == 1
    )

    assert "accepts one FUNCTION_FILTER" in capsys.readouterr().err
    assert all(not session.calls for session in capture_nexus.instances)


@pytest.mark.parametrize(
    ("selector_args", "expected_op", "expected_params"),
    [
        (["main"], "disasm", {"identifier": "main"}),
        (["--start", "0x1000", "--end", "0x1010"], "disasm_range", {"start": "0x1000", "end": "0x1010"}),
    ],
)
def test_disasm_selector_forms_choose_the_wire_operation(
    selector_args: list[str],
    expected_op: str,
    expected_params: dict[str, object],
    database: Path,
    capture_nexus,
    capsys,
) -> None:
    assert main(["disasm", *selector_args, "-c", str(database), "--json"]) == 0

    assert capture_nexus.instances[0].calls[0]["op"] == expected_op
    assert capture_nexus.instances[0].calls[0]["params"] == expected_params
    capsys.readouterr()


def test_disasm_rejects_missing_selector(database: Path, capture_nexus, capsys) -> None:
    assert main(["disasm", "-c", str(database), "--json"]) == 1

    assert "disasm requires a function or --start/--end" in capsys.readouterr().err
    assert all(not session.calls for session in capture_nexus.instances)


def test_locals_apply_accepts_a_list_plan(database: Path, capture_nexus, tmp_path: Path, capsys) -> None:
    plan_path = tmp_path / "locals.json"
    items = [{"local_id": "stack(16)@0x401000", "rename": "count"}]
    plan_path.write_text(json.dumps(items), encoding="utf-8")

    assert (
        main(
            [
                "function",
                "locals",
                "apply",
                "sub_401000",
                "--json-file",
                str(plan_path),
                "-c",
                str(database),
            ]
        )
        == 0
    )

    assert capture_nexus.instances[0].calls[0]["params"] == {
        "identifier": "sub_401000",
        "items": items,
    }
    capsys.readouterr()


def test_locals_apply_rejects_the_legacy_object_shape(database: Path, capture_nexus, tmp_path: Path, capsys) -> None:
    plan_path = tmp_path / "locals.json"
    plan_path.write_text(json.dumps({"items": [{"index": 3, "type": "uint64_t"}]}), encoding="utf-8")

    assert (
        main(
            [
                "function",
                "locals",
                "apply",
                "sub_401000",
                "--json-file",
                str(plan_path),
                "-c",
                str(database),
            ]
        )
        == 1
    )

    assert "local apply JSON must be a list" in capsys.readouterr().err
    assert all(not session.calls for session in capture_nexus.instances)


@pytest.mark.parametrize(
    ("search_args", "expected_params"),
    [
        (
            ["hello", "--segment", "__TEXT", "--ignore-case"],
            {"pattern": "hello", "regex": False, "ignore_case": True, "segment": "__TEXT"},
        ),
        (
            ["needle", "--scan", "--segment", "__TEXT", "--start", "0x1000", "--end", "0x2000"],
            {
                "pattern": "needle",
                "regex": False,
                "ignore_case": False,
                "segment": "__TEXT",
                "scan": True,
                "start": "0x1000",
                "end": "0x2000",
            },
        ),
    ],
)
def test_string_search_modes_reach_the_wire(
    search_args: list[str],
    expected_params: dict[str, object],
    database: Path,
    capture_nexus,
    capsys,
) -> None:
    assert (
        main(
            [
                "search",
                "strings",
                *search_args,
                "--timeout",
                "10",
                "-c",
                str(database),
                "--json",
            ]
        )
        == 0
    )

    assert capture_nexus.instances[0].calls[0]["params"] == expected_params
    capsys.readouterr()


def test_string_search_rejects_scan_bounds_without_scan(database: Path, capture_nexus, capsys) -> None:
    assert (
        main(
            [
                "search",
                "strings",
                "needle",
                "--segment",
                "__TEXT",
                "--start",
                "0x1000",
                "--end",
                "0x2000",
                "--timeout",
                "10",
                "-c",
                str(database),
            ]
        )
        == 1
    )

    assert "only valid with `search strings --scan`" in capsys.readouterr().err
    assert all(not session.calls for session in capture_nexus.instances)


@pytest.mark.parametrize(
    ("command", "expected_op", "expected_params"),
    [
        (
            [
                "type",
                "declare",
                "--decl",
                "typedef int OLD;",
                "--replace",
                "--alias",
                "OLD=NEW",
                "--bisect",
                "--clang",
            ],
            "type_declare",
            {
                "decl": "typedef int OLD;",
                "replace": True,
                "aliases": [{"from": "OLD", "to": "NEW"}],
                "bisect": True,
                "clang": True,
            },
        ),
        (
            ["type", "check", "--decl", "typedef int OLD;", "--alias", "OLD=NEW"],
            "type_declare_check",
            {
                "decl": "typedef int OLD;",
                "aliases": [{"from": "OLD", "to": "NEW"}],
                "clang": False,
            },
        ),
    ],
)
def test_type_declaration_modes_build_the_wire_contract(
    command: list[str],
    expected_op: str,
    expected_params: dict[str, object],
    database: Path,
    capture_nexus,
    capsys,
) -> None:
    assert main([*command, "-c", str(database), "--json"]) == 0

    assert capture_nexus.instances[0].calls[0]["op"] == expected_op
    assert capture_nexus.instances[0].calls[0]["params"] == expected_params
    capsys.readouterr()


@pytest.mark.parametrize(
    ("option", "expected_params"),
    [
        ([], {"identifier": "add", "decl": "void __fastcall add(int value);"}),
        (
            ["--propagate-callers"],
            {
                "identifier": "add",
                "decl": "void __fastcall add(int value);",
                "propagate_callers": True,
            },
        ),
    ],
)
def test_prototype_caller_propagation_is_opt_in_on_the_wire(
    option: list[str],
    expected_params: dict[str, object],
    database: Path,
    capture_nexus,
    capsys,
) -> None:
    assert (
        main(
            [
                "function",
                "prototype",
                "set",
                "add",
                "--decl",
                "void __fastcall add(int value);",
                *option,
                "-c",
                str(database),
            ]
        )
        == 0
    )

    assert capture_nexus.instances[0].calls[0]["params"] == expected_params
    capsys.readouterr()


def test_comment_scope_and_repeatability_reach_the_wire(database: Path, capture_nexus, capsys) -> None:
    assert (
        main(
            [
                "comment",
                "show",
                "main",
                "--scope",
                "function",
                "--repeatable",
                "-c",
                str(database),
                "--json",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "comment",
                "set",
                "main",
                "entry",
                "--posterior",
                "-c",
                str(database),
                "--json",
            ]
        )
        == 0
    )

    assert capture_nexus.instances[0].calls[0]["params"] == {
        "address": "main",
        "scope": "function",
        "repeatable": True,
    }
    assert capture_nexus.instances[1].calls[0]["params"] == {
        "address": "main",
        "text": "entry",
        "scope": "posterior",
    }
    capsys.readouterr()


def test_repeatable_extra_comments_are_rejected(database: Path, capture_nexus, capsys) -> None:
    assert (
        main(
            [
                "comment",
                "show",
                "main",
                "--anterior",
                "--repeatable",
                "-c",
                str(database),
            ]
        )
        == 1
    )

    assert "--repeatable is only valid for line or function comments" in capsys.readouterr().err
    assert all(not session.calls for session in capture_nexus.instances)
