from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from idac.cli import build_parser, main
from idac.nexus import NexusSessionError


@pytest.fixture
def fake_nexus(monkeypatch):
    class FakeNexusSession:
        instances: ClassVar[list[FakeNexusSession]] = []
        discovered: ClassVar[list[dict[str, object]]] = []

        def __init__(
            self,
            locator: str | None = None,
            instance_id: str | None = None,
            timeout: float | None = None,
        ) -> None:
            self.locator = locator
            self.instance_id = instance_id
            self.timeout = timeout
            self.calls: list[dict[str, Any]] = []
            self.closed = False
            self.__class__.instances.append(self)

        def execute_operation(
            self,
            op: str,
            params: dict[str, Any],
            *,
            preview: bool,
            operation_label: str,
        ) -> Any:
            self.calls.append(
                {
                    "op": op,
                    "params": params,
                    "preview": preview,
                }
            )
            if preview:
                return {
                    "before": {"text": None},
                    "after": {"text": params.get("text")},
                    "result": {"changed": True},
                    "preview_mode": "rollback"
                    if op
                    in {"bookmark_add", "bookmark_set", "bookmark_delete", "comment_set", "comment_delete", "name_set"}
                    else "undo",
                    "persisted": False,
                }
            if op == "database_info":
                return {"database": self.locator, "record_id": self.instance_id}
            return {"op": op, "params": params}

        def execute_python(
            self,
            source: str,
            *,
            filename: str,
            operation_label: str,
        ) -> dict[str, Any]:
            self.calls.append(
                {
                    "source": source,
                }
            )
            return {"result": {"result": 7, "result_repr": "7"}, "stdout": "hello\n", "stderr": ""}

        def save_database(self) -> dict[str, Any]:
            self.calls.append({"save": True})
            return {"saved": True, "database": self.locator}

        def list_targets(self) -> list[dict[str, object]]:
            return list(self.__class__.discovered)

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("idac.nexus.NexusSession", FakeNexusSession)
    return FakeNexusSession


def test_help_describes_nexus_surface(capsys) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--full-help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "-c PATH" in help_text
    assert "--instance RECORD_ID" in help_text
    assert "ida-nexus" in help_text
    assert "# idac setup gui" in help_text
    assert "# idac setup skill" in help_text
    assert "# idac database show" in help_text
    assert "# idac database save" in help_text


@pytest.mark.parametrize("value", ["0", "nan"])
def test_timeout_rejects_nonpositive_or_nonfinite_values(
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as caught:
        parser.parse_args(["targets", "list", f"--timeout={value}"])
    assert caught.value.code == 2

    assert "--timeout must be a positive finite number" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("locator", "message"),
    [
        ("db:sample.i64", "legacy db:/pid:/module: context locators were removed"),
        ("sample.idb", "32-bit .idb databases are not supported"),
    ],
)
def test_removed_context_forms_fail_closed(locator: str, message: str, capsys) -> None:
    assert main(["-c", locator, "database", "show", "--json"]) == 1
    assert message in capsys.readouterr().err


def test_missing_context_path_fails_before_creating_session(tmp_path: Path, fake_nexus, capsys) -> None:
    missing = tmp_path / "missing.bin"
    Path(f"{missing}.i64").touch()

    assert main(["-c", str(missing), "database", "show", "--json"]) == 1
    assert f"context path is not a file: {missing}" in capsys.readouterr().err
    assert fake_nexus.instances == []


@pytest.mark.parametrize("use_symlink", [False, True])
def test_output_cannot_overwrite_selected_database(
    use_symlink: bool,
    tmp_path: Path,
    fake_nexus,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    database.write_bytes(b"database sentinel")
    out_path = database
    if use_symlink:
        out_path = tmp_path / "output.json"
        out_path.symlink_to(database)

    assert main(["-c", str(database), "database", "show", "--out", str(out_path)]) == 1

    assert database.read_bytes() == b"database sentinel"
    assert "must not overwrite the selected input or database" in capsys.readouterr().err
    assert fake_nexus.instances == []


def test_output_cannot_overwrite_database_created_for_binary(tmp_path: Path, fake_nexus, capsys) -> None:
    binary = tmp_path / "sample.bin"
    database = Path(f"{binary}.i64")
    binary.write_bytes(b"binary sentinel")
    database.write_bytes(b"database sentinel")

    assert main(["-c", str(binary), "database", "show", "--out", str(database)]) == 1

    assert binary.read_bytes() == b"binary sentinel"
    assert database.read_bytes() == b"database sentinel"
    assert "must not overwrite the selected input or database" in capsys.readouterr().err
    assert fake_nexus.instances == []


def test_instance_output_cannot_overwrite_discovered_database(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "selected.i64"
    database.write_bytes(b"database sentinel")
    fake_nexus.discovered = [
        {
            "record_id": "record-42",
            "state": "ready",
            "idb_path": str(database),
            "exe_path": None,
        }
    ]

    assert main(["--instance", "record-42", "database", "show", "--out", str(database)]) == 1

    assert database.read_bytes() == b"database sentinel"
    assert "must not overwrite the selected input or database" in capsys.readouterr().err
    assert len(fake_nexus.instances) == 1
    assert fake_nexus.instances[0].calls == []
    assert fake_nexus.instances[0].closed is True


def test_output_cannot_overwrite_command_input_file(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    declarations = tmp_path / "types.h"
    database.touch()
    declarations.write_text("typedef int preserved_type;\n", encoding="utf-8")

    assert (
        main(
            [
                "-c",
                str(database),
                "type",
                "check",
                "--decl-file",
                str(declarations),
                "--out",
                str(declarations),
            ]
        )
        == 1
    )

    assert declarations.read_text(encoding="utf-8") == "typedef int preserved_type;\n"
    assert "must not overwrite the --decl-file input" in capsys.readouterr().err
    assert fake_nexus.instances == []


def test_preview_output_cannot_overwrite_wrapped_input_file(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    declarations = tmp_path / "types.h"
    database.touch()
    declarations.write_text("typedef int preserved_type;\n", encoding="utf-8")

    assert (
        main(
            [
                "preview",
                "-c",
                str(database),
                "--out",
                str(declarations),
                "type",
                "declare",
                "--decl-file",
                str(declarations),
            ]
        )
        == 1
    )

    assert declarations.read_text(encoding="utf-8") == "typedef int preserved_type;\n"
    assert "must not overwrite the wrapped --decl-file input" in capsys.readouterr().err
    assert len(fake_nexus.instances) == 1
    assert fake_nexus.instances[0].calls == []
    assert fake_nexus.instances[0].closed is True


def test_context_path_dispatches_operation_and_closes_session(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    database.touch()

    assert main(["-c", str(database), "--timeout", "12.5", "database", "show", "--json"]) == 0

    session = fake_nexus.instances[0]
    assert (session.locator, session.instance_id, session.timeout, session.closed) == (
        str(database),
        None,
        12.5,
        True,
    )
    assert len(session.calls) == 1
    assert session.calls[0]["op"] == "database_info"
    assert session.calls[0]["params"] == {}
    assert session.calls[0]["preview"] is False
    assert json.loads(capsys.readouterr().out) == {"database": str(database), "record_id": None}


def test_operation_error_remains_primary_when_cli_session_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    database.touch()

    class FailingSession:
        def __init__(self, **kwargs: object) -> None:
            self.options = kwargs

        def execute_operation(self, *args: object, **kwargs: object) -> object:
            raise NexusSessionError("operation failed", kind="operation_failed")

        def close(self) -> None:
            raise NexusSessionError("lease release failed", kind="release_failed")

    monkeypatch.setattr("idac.nexus.NexusSession", FailingSession)

    assert main(["-c", str(database), "database", "show", "--json"]) == 1

    assert capsys.readouterr().err.splitlines() == [
        "operation failed",
        "note: Nexus session finalization also failed: lease release failed",
    ]


def test_keyboard_interrupt_exits_130_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    database.touch()

    class InterruptedSession:
        def __init__(self, **kwargs: object) -> None:
            self.options = kwargs

        def execute_operation(self, *args: object, **kwargs: object) -> object:
            raise KeyboardInterrupt

        def close(self) -> None:
            return None

    monkeypatch.setattr("idac.nexus.NexusSession", InterruptedSession)

    assert main(["-c", str(database), "database", "show", "--json"]) == 130

    assert capsys.readouterr().err.strip() == "interrupted"


def test_exact_instance_and_implicit_ready_selection_reach_public_session(fake_nexus, capsys) -> None:
    assert main(["--instance", "record-42", "database", "show", "--json"]) == 0
    first_output = json.loads(capsys.readouterr().out)
    assert main(["database", "show", "--json"]) == 0
    second_output = json.loads(capsys.readouterr().out)

    assert [(item.locator, item.instance_id, item.closed) for item in fake_nexus.instances] == [
        (None, "record-42", True),
        (None, None, True),
    ]
    assert first_output == {"database": None, "record_id": "record-42"}
    assert second_output == {"database": None, "record_id": None}


def test_mutation_command_and_database_save_use_session_api(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    database.touch()

    assert main(["-c", str(database), "comment", "set", "0x401000", "entry", "--json"]) == 0
    assert main(["-c", str(database), "database", "save", "--json"]) == 0

    operation_call = fake_nexus.instances[0].calls[0]
    assert operation_call["op"] == "comment_set"
    assert operation_call["params"] == {"address": "0x401000", "text": "entry", "scope": "line"}
    assert operation_call["preview"] is False
    assert fake_nexus.instances[1].calls == [{"save": True}]
    assert all(item.closed for item in fake_nexus.instances)
    assert '"saved": true' in capsys.readouterr().out


def test_preview_reuses_wrapper_session_and_never_commits_mutation(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    artifact = tmp_path / "preview.json"
    database.touch()

    assert (
        main(
            [
                "preview",
                "-c",
                str(database),
                "-o",
                str(artifact),
                "comment",
                "set",
                "0x401000",
                "entry",
            ]
        )
        == 0
    )

    assert len(fake_nexus.instances) == 1
    session = fake_nexus.instances[0]
    assert session.closed is True
    assert session.calls[0]["preview"] is True
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["before"] == {"text": None}
    assert payload["after"] == {"text": "entry"}
    assert payload["undo"] == {"mode": "rollback", "persisted": False, "status": "ok"}
    assert "wrote preview data" in capsys.readouterr().err


def test_preview_does_not_publish_success_artifact_before_session_closes(
    tmp_path: Path,
    fake_nexus,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    artifact = tmp_path / "preview.json"
    database.touch()

    def fail_close(self) -> None:
        self.closed = True
        raise NexusSessionError("lease release failed", kind="release_failed")

    monkeypatch.setattr(fake_nexus, "close", fail_close)

    assert (
        main(
            [
                "preview",
                "-c",
                str(database),
                "-o",
                str(artifact),
                "comment",
                "set",
                "0x401000",
                "entry",
            ]
        )
        == 1
    )

    assert not artifact.exists()
    assert capsys.readouterr().err.strip() == "lease release failed"


def test_preview_child_cannot_switch_nexus_target(tmp_path: Path, fake_nexus, capsys) -> None:
    outer = tmp_path / "outer.i64"
    inner = tmp_path / "inner.i64"
    outer.touch()
    inner.touch()

    exit_code = main(
        [
            "preview",
            "-c",
            str(outer),
            "-o",
            str(tmp_path / "preview.json"),
            "comment",
            "set",
            "0x401000",
            "entry",
            "-c",
            str(inner),
        ]
    )

    assert exit_code == 1
    assert "child commands cannot switch Nexus targets" in capsys.readouterr().err
    assert len(fake_nexus.instances) == 1
    assert fake_nexus.instances[0].calls == []


def test_preview_child_cannot_override_wrapper_timeout(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    database.touch()

    exit_code = main(
        [
            "preview",
            "-c",
            str(database),
            "--timeout",
            "12",
            "-o",
            str(tmp_path / "preview.json"),
            "comment",
            "set",
            "0x401000",
            "entry",
            "--timeout",
            "1",
        ]
    )

    assert exit_code == 1
    assert "child commands cannot set --timeout" in capsys.readouterr().err
    assert len(fake_nexus.instances) == 1
    assert fake_nexus.instances[0].timeout == 12.0
    assert fake_nexus.instances[0].calls == []


def test_preview_child_inherits_wrapper_timeout_for_validation(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    artifact = tmp_path / "preview.json"
    database.touch()

    assert (
        main(
            [
                "preview",
                "-c",
                str(database),
                "--timeout",
                "12",
                "-o",
                str(artifact),
                "search",
                "bytes",
                "90",
                "--segment",
                ".text",
            ]
        )
        == 0
    )

    assert len(fake_nexus.instances) == 1
    session = fake_nexus.instances[0]
    assert session.timeout == 12.0
    assert [call["op"] for call in session.calls] == ["search_bytes"]
    assert json.loads(artifact.read_text(encoding="utf-8"))["status"] == "ok"
    capsys.readouterr()


def test_batch_reuses_one_wrapper_session_for_all_children(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "read.idac"
    database.touch()
    batch_file.write_text("database show --json\ndatabase show --json\n", encoding="utf-8")

    assert main(["batch", "-c", str(database), str(batch_file)]) == 0

    assert len(fake_nexus.instances) == 1
    session = fake_nexus.instances[0]
    assert [call["op"] for call in session.calls] == ["database_info", "database_info"]
    assert session.closed is True
    payload = json.loads(capsys.readouterr().out)
    assert payload["commands_succeeded"] == 2
    assert payload["commands_failed"] == 0


def test_batch_children_inherit_wrapper_timeout_for_validation(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "search.idac"
    database.touch()
    batch_file.write_text("search bytes 90 --segment .text\n", encoding="utf-8")

    assert main(["batch", "-c", str(database), "--timeout", "12", str(batch_file)]) == 0

    assert len(fake_nexus.instances) == 1
    session = fake_nexus.instances[0]
    assert session.timeout == 12.0
    assert [call["op"] for call in session.calls] == ["search_bytes"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["commands_succeeded"] == 1
    assert payload["commands_failed"] == 0


def test_batch_child_cannot_override_wrapper_timeout(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "read.idac"
    database.touch()
    batch_file.write_text("database show --timeout 1 --json\n", encoding="utf-8")

    assert main(["batch", "-c", str(database), "--timeout", "12", str(batch_file)]) == 1

    assert len(fake_nexus.instances) == 1
    session = fake_nexus.instances[0]
    assert session.timeout == 12.0
    assert session.calls == []
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["commands_succeeded"] == 0
    assert payload["commands_failed"] == 1
    assert "child commands cannot set --timeout" in payload["results"][0]["stderr"]


def test_batch_without_selector_accepts_context_free_children(tmp_path: Path, fake_nexus, capsys) -> None:
    batch_file = tmp_path / "docs.idac"
    batch_file.write_text("docs --list\n", encoding="utf-8")

    assert main(["batch", str(batch_file)]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["commands_succeeded"] == 1
    assert payload["commands_failed"] == 0


def test_python_exec_is_stateless_and_persist_option_is_removed(tmp_path: Path, fake_nexus, capsys) -> None:
    database = tmp_path / "sample.i64"
    database.touch()

    assert main(["py", "exec", "-c", str(database), "--code", "result = 7", "--json"]) == 0
    call = fake_nexus.instances[0].calls[0]
    assert "result = 7" in call["source"]
    assert json.loads(capsys.readouterr().out) == {
        "result": 7,
        "result_repr": "7",
        "stderr": "",
        "stdout": "hello\n",
    }

    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["py", "exec", "--code", "pass", "--persist"])
    assert exc.value.code == 2


def test_targets_list_uses_public_discovery_seam(monkeypatch, capsys) -> None:
    calls: list[float | None] = []

    def list_targets(*, timeout: float | None = None) -> list[dict[str, Any]]:
        calls.append(timeout)
        return [
            {
                "record_id": "gui-1",
                "state": "ready",
                "detail": None,
                "backend": "gui",
                "pid": 123,
                "idb_path": "/tmp/sample.i64",
                "exe_path": None,
                "managed": False,
                "started_at": 1.0,
            }
        ]

    monkeypatch.setattr("idac.nexus.list_targets", list_targets)

    assert main(["targets", "list", "--timeout", "3", "--json"]) == 0
    assert calls == [3.0]
    assert json.loads(capsys.readouterr().out)[0]["record_id"] == "gui-1"


def test_setup_and_doctor_commands_call_public_services(monkeypatch, capsys) -> None:
    calls: list[tuple[str, Any]] = []

    def setup_gui(*, timeout: float | None = None) -> dict[str, Any]:
        calls.append(("setup", timeout))
        return {"installed": True, "plugin": "ida-nexus", "version": "0.7.0"}

    def run_doctor(*, timeout: float | None = None) -> dict[str, Any]:
        calls.append(("doctor", timeout))
        return {"healthy": True, "status": "ok", "checks": []}

    monkeypatch.setattr("idac.cli.commands.setup.setup_gui", setup_gui)
    monkeypatch.setattr("idac.cli.commands.doctor.run_doctor", run_doctor)

    assert main(["setup", "gui", "--timeout", "9", "--json"]) == 0
    setup_output = json.loads(capsys.readouterr().out)
    assert main(["doctor", "--timeout", "4", "--json"]) == 0
    doctor_output = json.loads(capsys.readouterr().out)
    assert calls == [("setup", 9.0), ("doctor", 4.0)]
    assert setup_output["plugin"] == "ida-nexus"
    assert doctor_output["healthy"] is True


@pytest.mark.parametrize(
    "argv",
    [
        ["database", "open", "sample.i64"],
        ["database", "close"],
        ["targets", "cleanup"],
        ["misc", "plugin", "install"],
    ],
)
def test_removed_commands_are_not_registered(argv: list[str], capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)

    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
