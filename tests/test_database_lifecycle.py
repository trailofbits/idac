from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from idac.cli import main
from idac.cli.commands import database as database_commands


@pytest.mark.parametrize("protected", ["input", "sidecar"])
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink"])
def test_open_rejects_known_output_alias_before_starting_host(
    protected: str, alias: str, tmp_path: Path, monkeypatch, capsys
) -> None:
    binary = tmp_path / "input.bin"
    database = Path(f"{binary}.i64")
    binary.write_bytes(b"binary sentinel")
    database.write_bytes(b"database sentinel")
    output = binary if protected == "input" else database
    if alias != "direct":
        target = output
        output = tmp_path / "output.json"
        if alias == "symlink":
            output.symlink_to(target)
        else:
            output.hardlink_to(target)

    def unexpected_start(*args, **kwargs):
        pytest.fail("an output collision must not start a host")

    monkeypatch.setattr(database_commands, "start_host", unexpected_start)

    assert main(["database", "open", str(binary), "--out", str(output)]) == 1
    assert "--out must not overwrite" in capsys.readouterr().err
    assert binary.read_bytes() == b"binary sentinel"
    assert database.read_bytes() == b"database sentinel"


@pytest.mark.parametrize("command", ["open", "close"])
@pytest.mark.parametrize("protected", ["database", "idb_path", "exe_path"])
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink"])
def test_lifecycle_output_preserves_resolved_host_files(
    command: str, protected: str, alias: str, tmp_path: Path, monkeypatch, capsys
) -> None:
    paths = {
        "database": tmp_path / "original.bin",
        "idb_path": tmp_path / "relocated.i64",
        "exe_path": tmp_path / "input.bin",
    }
    for key, path in paths.items():
        path.write_bytes(key.encode())
    selected = tmp_path / "selected.i64"
    selected.write_bytes(b"selected database")
    state = {
        "host_id": "a" * 32,
        "record_id": "host-record",
        "status": "ready",
        **{key: str(path) for key, path in paths.items()},
    }
    output = paths[protected]
    if alias != "direct":
        target = output
        output = tmp_path / "output.json"
        if alias == "symlink":
            output.symlink_to(target)
        else:
            output.hardlink_to(target)

    def open_host(*args, **kwargs):
        kwargs["validate_state"](state)
        return state

    def unexpected_close(*args, **kwargs):
        pytest.fail("an output collision must not shut down a host")

    monkeypatch.setattr(database_commands, "start_host", open_host)
    monkeypatch.setattr(database_commands, "stop_host", unexpected_close)
    monkeypatch.setattr(database_commands, "host_status", lambda host_id: state)
    monkeypatch.setattr(
        database_commands,
        "HostedCommand",
        SimpleNamespace(for_instance=lambda record_id: SimpleNamespace(directory=tmp_path / state["host_id"])),
    )
    selector = [str(selected)] if command == "open" else ["--instance", state["record_id"]]

    assert main(["database", command, *selector, "--out", str(output)]) == 1
    assert "--out must not overwrite" in capsys.readouterr().err
    for key, path in paths.items():
        assert path.read_bytes() == key.encode()
    assert selected.read_bytes() == b"selected database"


@pytest.mark.parametrize("command", ["open", "close"])
def test_lifecycle_can_write_an_unrelated_output(command: str, tmp_path: Path, monkeypatch, capsys) -> None:
    database = tmp_path / "sample.i64"
    database.write_bytes(b"database sentinel")
    state = {"host_id": "a" * 32, "record_id": "host-record", "database": str(database), "status": "ready"}
    monkeypatch.setattr(database_commands, "start_host", lambda *args, **kwargs: state)
    monkeypatch.setattr(database_commands, "stop_host", lambda *args, **kwargs: {**state, "status": "stopped"})
    monkeypatch.setattr(database_commands, "host_status", lambda host_id: state)
    monkeypatch.setattr(
        database_commands,
        "HostedCommand",
        SimpleNamespace(for_instance=lambda record_id: SimpleNamespace(directory=tmp_path / state["host_id"])),
    )
    output = tmp_path / "output.json"
    selector = [str(database)] if command == "open" else ["--instance", state["record_id"]]

    assert main(["database", command, *selector, "--out", str(output)]) == 0
    result = json.loads(output.read_text())
    assert result["record_id"] == state["record_id"]
    assert "host_id" not in result
    assert result["status"] == ("ready" if command == "open" else "stopped")
    assert database.read_bytes() == b"database sentinel"


def test_open_protects_original_input_path_even_when_the_file_is_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    database = tmp_path / "sample.i64"
    database.write_bytes(b"database sentinel")
    binary = tmp_path / "missing.bin"
    state = {"host_id": "a" * 32, "database": str(database), "exe_path": str(binary), "status": "ready"}

    def open_host(*args, **kwargs):
        kwargs["validate_state"](state)
        return state

    monkeypatch.setattr(database_commands, "start_host", open_host)

    assert main(["database", "open", str(database), "--out", str(binary)]) == 1
    assert "--out must not overwrite" in capsys.readouterr().err
    assert not binary.exists()
    assert database.read_bytes() == b"database sentinel"
