from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from pathlib import Path

import pytest
from ida_nexus import DatabaseHandle, find_database_owner, wait_database_released

from idac.nexus import NexusSession
from tests.helpers import run_cli, run_cli_json


def _read_snapshot_comment(snapshot: Path, address: str) -> str | None:
    """Read a saved copy in a fresh worker, then terminate that worker without saving."""

    try:
        with NexusSession(locator=snapshot, timeout=120.0) as session:
            result = session.execute_operation(
                "comment_get",
                {"address": address, "scope": "line", "repeatable": False},
            )
        assert isinstance(result, dict)
        comment = result.get("comment")
        assert comment is None or isinstance(comment, str)
        return comment
    finally:
        owner = find_database_owner(snapshot, timeout=5.0)
        if owner is not None:
            handle = DatabaseHandle.attach(owner, keepalive=0.0)
            try:
                handle.shutdown_database(save=False)
            finally:
                handle.close()
            assert wait_database_released(owner, timeout=30.0)


@pytest.mark.nexus_gui_live
def test_gui_attach_preview_save_close_and_reattach_lifecycle(tmp_path: Path) -> None:
    record_id = os.environ.get("IDAC_NEXUS_GUI_RECORD_ID", "").strip()
    assert record_id, "set IDAC_NEXUS_GUI_RECORD_ID to a disposable READY GUI database record"
    idac_cmd = [sys.executable, "-m", "idac"]
    cli_env = dict(os.environ)
    targets = run_cli_json(idac_cmd, cli_env, "targets", "list", "--timeout", "2")
    assert isinstance(targets, list)
    matches = [target for target in targets if target["record_id"] == record_id]
    assert len(matches) == 1, f"GUI Nexus record {record_id!r} was not found"
    assert matches[0]["state"] == "ready" and matches[0]["backend"] == "gui", (
        f"Nexus record {record_id!r} is not a READY GUI database"
    )
    idb_path = matches[0].get("idb_path")
    assert isinstance(idb_path, str) and idb_path
    gui_database = Path(idb_path).expanduser().resolve()
    assert gui_database.is_file() and gui_database.suffix.lower() == ".i64", (
        "the disposable GUI target must be a saved .i64 database"
    )

    address: str | None = None
    original_comment: str | None = None
    original_captured = False
    sentinel = f"idac GUI lifecycle {uuid.uuid4().hex}"
    try:
        baseline_snapshot = tmp_path / "gui-baseline-snapshot.i64"
        shutil.copy2(gui_database, baseline_snapshot)
        info = run_cli_json(
            idac_cmd,
            cli_env,
            "database",
            "show",
            "--instance",
            record_id,
            "--timeout",
            "10",
        )
        assert isinstance(info, dict)
        selected_address = info.get("main_ea") or info.get("start_ea") or info.get("entry_ea")
        assert isinstance(selected_address, str) and selected_address
        address = selected_address
        before = run_cli_json(
            idac_cmd,
            cli_env,
            "comment",
            "show",
            address,
            "--instance",
            record_id,
            "--timeout",
            "10",
        )
        assert isinstance(before, dict)
        original = before.get("comment")
        assert original is None or isinstance(original, str)
        original_comment = original
        original_captured = True
        disk_comment_before = _read_snapshot_comment(baseline_snapshot, address)

        preview_path = tmp_path / "gui-preview.json"
        preview_proc = run_cli(
            idac_cmd,
            cli_env,
            "preview",
            "--instance",
            record_id,
            "--timeout",
            "10",
            "--out",
            preview_path,
            "comment",
            "set",
            address,
            sentinel,
        )
        assert preview_proc.returncode == 0, preview_proc.stderr or preview_proc.stdout
        preview = json.loads(preview_path.read_text(encoding="utf-8"))
        assert preview["before"] == before
        assert preview["after"]["comment"] == sentinel
        assert (
            run_cli_json(
                idac_cmd,
                cli_env,
                "comment",
                "show",
                address,
                "--instance",
                record_id,
                "--timeout",
                "10",
            )
            == before
        )

        changed = run_cli_json(
            idac_cmd,
            cli_env,
            "comment",
            "set",
            address,
            sentinel,
            "--instance",
            record_id,
            "--timeout",
            "10",
        )
        assert isinstance(changed, dict) and changed["comment"] == sentinel

        assert address is not None
        unsaved_snapshot = tmp_path / "gui-unsaved-snapshot.i64"
        shutil.copy2(gui_database, unsaved_snapshot)
        assert _read_snapshot_comment(unsaved_snapshot, address) == disk_comment_before

        live_change = run_cli_json(
            idac_cmd,
            cli_env,
            "comment",
            "show",
            address,
            "--instance",
            record_id,
            "--timeout",
            "10",
        )
        assert isinstance(live_change, dict) and live_change["comment"] == sentinel
        saved = run_cli_json(
            idac_cmd,
            cli_env,
            "database",
            "save",
            "--instance",
            record_id,
            "--timeout",
            "10",
        )
        assert isinstance(saved, dict) and saved["saved"] is True

        saved_snapshot = tmp_path / "gui-saved-snapshot.i64"
        shutil.copy2(gui_database, saved_snapshot)
        assert _read_snapshot_comment(saved_snapshot, address) == sentinel
    finally:
        if original_captured and address is not None:
            action = (
                ["comment", "delete", address]
                if original_comment is None
                else [
                    "comment",
                    "set",
                    address,
                    original_comment,
                ]
            )
            restored = run_cli_json(
                idac_cmd,
                cli_env,
                *action,
                "--instance",
                record_id,
                "--timeout",
                "10",
            )
            assert isinstance(restored, dict)
            run_cli_json(
                idac_cmd,
                cli_env,
                "database",
                "save",
                "--instance",
                record_id,
                "--timeout",
                "10",
            )

    assert original_captured and address is not None
    final_readback = run_cli_json(
        idac_cmd,
        cli_env,
        "comment",
        "show",
        address,
        "--instance",
        record_id,
        "--timeout",
        "10",
    )
    assert isinstance(final_readback, dict) and final_readback["comment"] == original_comment

    restored_snapshot = tmp_path / "gui-restored-snapshot.i64"
    shutil.copy2(gui_database, restored_snapshot)
    assert _read_snapshot_comment(restored_snapshot, address) == original_comment
