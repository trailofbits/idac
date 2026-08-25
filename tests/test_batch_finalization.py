from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from idac.cli import main
from idac.nexus import NexusSessionError


class RecordingSession:
    instances: ClassVar[list[RecordingSession]] = []

    def __init__(self, locator=None, instance_id=None, timeout=None) -> None:
        self.operations: list[str] = []
        self.closed = False
        self.__class__.instances.append(self)

    def execute_operation(self, op, params, *, preview, operation_label):
        self.operations.append(op)
        return {"name": "sample", "changed": False}

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("suffix", [".json", ".jsonl"])
def test_batch_save_failure_replaces_pending_checkpoint_with_failed_finalization(
    suffix: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "mutate.idac"
    out_path = tmp_path / f"batch{suffix}"
    database.touch()
    batch_file.write_text("comment set 0x401000 entry --json\n", encoding="utf-8")

    class SaveFailingSession:
        instances: ClassVar[list[SaveFailingSession]] = []

        def __init__(
            self,
            locator: str | None = None,
            instance_id: str | None = None,
            timeout: float | None = None,
        ) -> None:
            self.locator = locator
            self.instance_id = instance_id
            self.timeout = timeout
            self.closed = False
            self.checkpoint_at_close: Any = None
            self.__class__.instances.append(self)

        def execute_operation(
            self,
            op: str,
            params: dict[str, Any],
            *,
            preview: bool,
            operation_label: str,
        ) -> dict[str, Any]:
            return {"changed": True}

        def close(self) -> None:
            if self.closed:
                return
            self.closed = True
            if suffix == ".json":
                self.checkpoint_at_close = json.loads(out_path.read_text(encoding="utf-8"))
            else:
                self.checkpoint_at_close = [
                    json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()
                ]
            raise NexusSessionError("headless autosave failed", kind="save_failed")

    monkeypatch.setattr("idac.nexus.NexusSession", SaveFailingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1

    session = SaveFailingSession.instances[0]

    if suffix == ".json":
        checkpoint = session.checkpoint_at_close
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        assert checkpoint["ok"] is False
        assert checkpoint["finalization"] == {"status": "pending"}
        finalization = payload["finalization"]
        assert payload["ok"] is False
        assert payload["commands_succeeded"] == 1
        assert payload["commands_failed"] == 0
    else:
        checkpoint = session.checkpoint_at_close[-1]
        payload = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        assert checkpoint == {"record_type": "batch_finalization", "status": "pending", "ok": False}
        finalization = payload[-1]
        assert finalization["record_type"] == "batch_finalization"
        assert finalization["ok"] is False

    assert finalization == {
        **({"record_type": "batch_finalization"} if suffix == ".jsonl" else {}),
        "status": "failed",
        "stage": "database_save_or_session_close",
        "persistence": "unconfirmed",
        "error_kind": "save_failed",
        "error": "headless autosave failed",
        **({"ok": False} if suffix == ".jsonl" else {}),
    }
    assert "batch finalization failed: headless autosave failed" in capsys.readouterr().err


def test_batch_establishes_wrapper_output_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "mutate.idac"
    out_path = tmp_path / "batch.json"
    database.touch()
    out_path.mkdir()
    batch_file.write_text("comment set 0x401000 entry\n", encoding="utf-8")

    class RecordingSession:
        instances: ClassVar[list[RecordingSession]] = []

        def __init__(self, locator=None, instance_id=None, timeout=None) -> None:
            self.operations: list[str] = []
            self.close_attempts = 0
            self.closed = False
            self.__class__.instances.append(self)

        def execute_operation(self, op, params, *, preview, operation_label):
            self.operations.append(op)
            return {"changed": True}

        def close(self) -> None:
            if self.closed:
                return
            self.closed = True
            self.close_attempts += 1

    monkeypatch.setattr("idac.nexus.NexusSession", RecordingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1
    session = RecordingSession.instances[0]
    assert session.operations == []
    assert "Is a directory" in capsys.readouterr().err


def test_batch_wrapper_output_cannot_overwrite_child_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    declarations = tmp_path / "types.h"
    batch_file = tmp_path / "read.idac"
    database.touch()
    declarations.write_text("typedef int preserved_type;\n", encoding="utf-8")
    batch_file.write_text("type check --decl-file types.h\n", encoding="utf-8")

    class RecordingSession:
        instances: ClassVar[list[RecordingSession]] = []

        def __init__(self, **_kwargs: object) -> None:
            self.calls: list[str] = []
            self.closed = False
            self.__class__.instances.append(self)

        def execute_operation(self, op, params, *, preview, operation_label):
            self.calls.append(op)
            return {"success": True}

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("idac.nexus.NexusSession", RecordingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(declarations)]) == 1

    assert declarations.read_text(encoding="utf-8") == "typedef int preserved_type;\n"
    assert "must not overwrite the line 1 --decl-file input" in capsys.readouterr().err
    assert len(RecordingSession.instances) == 1
    assert RecordingSession.instances[0].calls == []


@pytest.mark.parametrize(
    ("command", "expected_error"),
    [
        (
            "comment set 0x401000 entry --out step.json\n",
            "mutating batch child commands cannot set --out",
        ),
        (
            "preview --out preview.json comment set 0x401000 entry --out step.json\n",
            "mutating commands wrapped by batch preview cannot set --out",
        ),
    ],
)
def test_batch_rejects_mutating_child_output_before_dispatch(
    command: str,
    expected_error: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "mutate.idac"
    out_path = tmp_path / "batch.json"
    database.touch()
    batch_file.write_text(command, encoding="utf-8")

    class RecordingSession:
        instances: ClassVar[list[RecordingSession]] = []

        def __init__(self, locator=None, instance_id=None, timeout=None) -> None:
            self.operations: list[str] = []
            self.closed = False
            self.__class__.instances.append(self)

        def execute_operation(self, op, params, *, preview, operation_label):
            self.operations.append(op)
            return {"changed": True}

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("idac.nexus.NexusSession", RecordingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1
    session = RecordingSession.instances[0]
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert session.operations == []
    assert payload["results"][0]["status"] == "failed"
    assert expected_error in payload["results"][0]["stderr"]
    assert expected_error in capsys.readouterr().err


def test_batch_interrupt_closes_and_writes_terminal_record_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "mutate.idac"
    out_path = tmp_path / "batch.json"
    database.touch()
    batch_file.write_text("comment set 0x401000 entry\n", encoding="utf-8")

    class InterruptingSession:
        instances: ClassVar[list[InterruptingSession]] = []

        def __init__(self, locator=None, instance_id=None, timeout=None) -> None:
            self.close_attempts = 0
            self.closed = False
            self.__class__.instances.append(self)

        def execute_operation(self, op, params, *, preview, operation_label):
            raise KeyboardInterrupt

        def close(self) -> None:
            if self.closed:
                return
            self.closed = True
            self.close_attempts += 1

    monkeypatch.setattr("idac.nexus.NexusSession", InterruptingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 130
    session = InterruptingSession.instances[0]
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert session.close_attempts == 1
    assert payload["finalization"] == {
        "status": "interrupted",
        "stage": "batch_execution",
        "error_kind": "keyboard_interrupt",
        "error": "interrupted by user",
        "session_finalization": {"status": "ok"},
    }
    assert payload["results"][0]["status"] == "interrupted"
    assert payload["results"][0]["exit_code"] == 130
    stderr = capsys.readouterr().err
    assert "batch interrupted: interrupted by user" in stderr
    assert "Traceback" not in stderr


def test_batch_preserves_unexpected_execution_and_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "mutate.idac"
    out_path = tmp_path / "batch.json"
    database.touch()
    batch_file.write_text("comment set 0x401000 entry\n", encoding="utf-8")

    class FailingSession:
        instances: ClassVar[list[FailingSession]] = []

        def __init__(self, locator=None, instance_id=None, timeout=None) -> None:
            self.close_attempts = 0
            self.closed = False
            self.__class__.instances.append(self)

        def execute_operation(self, op, params, *, preview, operation_label):
            raise RuntimeError("dispatch exploded")

        def close(self) -> None:
            if self.closed:
                return
            self.closed = True
            self.close_attempts += 1
            raise NexusSessionError("autosave exploded", kind="save_failed")

    monkeypatch.setattr("idac.nexus.NexusSession", FailingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1
    session = FailingSession.instances[0]
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    finalization = payload["finalization"]
    assert session.close_attempts == 1
    assert finalization["stage"] == "batch_execution"
    assert finalization["error_kind"] == "RuntimeError"
    assert finalization["error"] == "dispatch exploded"
    assert finalization["session_finalization"] == {
        "status": "failed",
        "stage": "database_save_or_session_close",
        "persistence": "unconfirmed",
        "error_kind": "save_failed",
        "error": "autosave exploded",
    }
    stderr = capsys.readouterr().err
    assert "dispatch exploded" in stderr
    assert "batch session finalization also failed: autosave exploded" in stderr
    assert "Traceback" not in stderr


@pytest.mark.parametrize("protected", ["context", "batch_file", "context_symlink"])
def test_batch_wrapper_output_cannot_overwrite_inputs(
    protected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    RecordingSession.instances.clear()
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "read.idac"
    database.write_bytes(b"database sentinel")
    batch_file.write_text("database show\n", encoding="utf-8")
    if protected == "context":
        out_path = database
    elif protected == "batch_file":
        out_path = batch_file
    else:
        out_path = tmp_path / "database-output.json"
        out_path.symlink_to(database)
    database_before = database.read_bytes()
    batch_before = batch_file.read_text(encoding="utf-8")
    monkeypatch.setattr("idac.nexus.NexusSession", RecordingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1
    assert all(session.operations == [] for session in RecordingSession.instances)
    assert database.read_bytes() == database_before
    assert batch_file.read_text(encoding="utf-8") == batch_before
    assert "must not overwrite" in capsys.readouterr().err


@pytest.mark.parametrize("child_output", ["batch.json", "sample.i64"])
def test_read_only_child_output_cannot_overwrite_journal_or_context(
    child_output: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    RecordingSession.instances.clear()
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "read.idac"
    out_path = tmp_path / "batch.json"
    database.write_bytes(b"database sentinel")
    batch_file.write_text(f"database show --out {child_output}\n", encoding="utf-8")
    monkeypatch.setattr("idac.nexus.NexusSession", RecordingSession)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert RecordingSession.instances[0].operations == []
    assert database.read_bytes() == b"database sentinel"
    assert payload["commands_total"] == 1
    assert "must not overwrite" in payload["results"][0]["stderr"]
    capsys.readouterr()


def test_batch_preserves_close_failure_notes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "read.idac"
    out_path = tmp_path / "batch.json"
    database.touch()
    batch_file.write_text("database show\n", encoding="utf-8")

    class NotedCloseFailure(RecordingSession):
        def close(self) -> None:
            if self.closed:
                return
            self.closed = True
            error = NexusSessionError("autosave exploded", kind="save_failed")
            error.add_note("lease release also failed: connection refused")
            raise error

    NotedCloseFailure.instances.clear()
    monkeypatch.setattr("idac.nexus.NexusSession", NotedCloseFailure)

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1
    finalization = json.loads(out_path.read_text(encoding="utf-8"))["finalization"]
    assert finalization["notes"] == ["lease release also failed: connection refused"]
    assert "batch finalization detail: lease release also failed" in capsys.readouterr().err


def test_batch_lint_rejects_mutating_child_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    RecordingSession.instances.clear()
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "mutate.idac"
    out_path = tmp_path / "lint.json"
    database.touch()
    batch_file.write_text("comment set 0x401000 entry --out step.json\n", encoding="utf-8")
    monkeypatch.setattr("idac.nexus.NexusSession", RecordingSession)

    assert main(["batch", "--lint", "-c", str(database), str(batch_file), "--out", str(out_path)]) == 1
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["mode"] == "lint"
    assert "mutating batch child commands cannot set --out" in payload["errors"][0]["message"]
    assert RecordingSession.instances[0].operations == []
    capsys.readouterr()
