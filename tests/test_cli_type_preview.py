from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from idac.cli import main


@pytest.fixture
def failed_type_preview_session(monkeypatch: pytest.MonkeyPatch) -> None:
    class Session:
        def __init__(self, locator=None, instance_id=None, timeout=None) -> None:
            self.handle = SimpleNamespace(instance=SimpleNamespace(idb_path=locator, exe_path=None))
            self.closed = False

        def execute_operation(self, op, params, *, preview, operation_label) -> dict[str, Any]:
            if op == "type_declare":
                return {
                    "before": {"type_count": 0},
                    "after": {"type_count": 0},
                    "result": {
                        "success": False,
                        "errors": 2,
                        "diagnostics": [{"line": 1, "message": "base class is incomplete"}],
                    },
                    "preview_mode": "undo",
                    "persisted": False,
                }
            return {"name": "later_type"}

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("idac.nexus.NexusSession", Session)


def test_type_declare_preview_reports_parser_failure(
    failed_type_preview_session: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    out_path = tmp_path / "preview.json"
    database.touch()

    assert (
        main(["preview", "-c", str(database), "--out", str(out_path), "type", "declare", "--decl", "struct Broken;"])
        == 1
    )

    preview = json.loads(out_path.read_text(encoding="utf-8"))
    assert preview["status"] == "failed"
    assert preview["result"]["success"] is False
    assert preview["result"]["errors"] == 2
    assert preview["undo"] == {"status": "ok", "mode": "undo", "persisted": False}
    assert "type declare failed: 2 parser error(s)" in preview["stderr"]
    assert "line 1: base class is incomplete" in preview["stderr"]
    assert "type declare failed: 2 parser error(s)" in capsys.readouterr().err


def test_batch_fail_fast_stops_after_failed_type_declare_preview(
    failed_type_preview_session: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "sample.i64"
    batch_file = tmp_path / "preview.idac"
    out_path = tmp_path / "batch.json"
    database.touch()
    batch_file.write_text(
        "preview type declare --decl 'struct Broken;'\ntype show later_type\n",
        encoding="utf-8",
    )

    assert main(["batch", "-c", str(database), str(batch_file), "--out", str(out_path), "--fail-fast"]) == 1

    batch = json.loads(out_path.read_text(encoding="utf-8"))
    assert batch["ok"] is False
    assert batch["commands_total"] == 1
    assert batch["commands_failed"] == 1
    assert batch["results"][0]["status"] == "failed"
    assert batch["results"][0]["result"]["status"] == "failed"
    assert batch["results"][0]["result"]["result"]["errors"] == 2
    assert "type declare failed: 2 parser error(s)" in batch["results"][0]["stderr"]
    assert "type declare failed: 2 parser error(s)" in capsys.readouterr().err
