from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _flatten_args(*args: object) -> list[str]:
    flattened: list[str] = []
    for arg in args:
        if isinstance(arg, (list, tuple)):
            flattened.extend(str(item) for item in arg)
            continue
        flattened.append(str(arg))
    return flattened


def run_cli(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    *args: object,
    input_text: str | None = None,
    use_json: bool = False,
) -> subprocess.CompletedProcess[str]:
    format_args = ["--format", "json"] if use_json else []
    return subprocess.run(
        [*idac_cmd, *_flatten_args(*args), *format_args],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
        input=input_text,
    )


def run_cli_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    *args: object,
    input_text: str | None = None,
) -> object:
    proc = run_cli(idac_cmd, idac_env, *args, input_text=input_text, use_json=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return json.loads(proc.stdout)


def run_idalib(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *args: object,
    input_text: str | None = None,
    use_json: bool = False,
) -> subprocess.CompletedProcess[str]:
    open_proc = subprocess.run(
        [*idac_cmd, "database", "open", str(database), "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
    )
    assert open_proc.returncode == 0, open_proc.stderr or open_proc.stdout
    format_args = ["--format", "json"] if use_json else []
    return subprocess.run(
        [
            *idac_cmd,
            *_flatten_args(*args),
            "-c",
            f"db:{database}",
            *format_args,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
        input=input_text,
    )


def run_idalib_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *args: object,
    input_text: str | None = None,
) -> object:
    proc = run_idalib(idac_cmd, idac_env, database, *args, input_text=input_text, use_json=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return json.loads(proc.stdout)


def run_idalib_text(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *args: object,
    input_text: str | None = None,
) -> str:
    proc = run_idalib(idac_cmd, idac_env, database, *args, input_text=input_text, use_json=False)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return proc.stdout


def preview_snapshot(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *,
    read_args: list[object] | tuple[object, ...],
    preview_args: list[object] | tuple[object, ...],
) -> dict[str, object]:
    before = run_idalib_json(idac_cmd, idac_env, database, *read_args)
    preview = run_idalib_json(idac_cmd, idac_env, database, *preview_args, "--preview")
    after_preview = run_idalib_json(idac_cmd, idac_env, database, *read_args)
    return {
        "before": before,
        "preview": preview,
        "after_preview": after_preview,
    }


def preview_round_trip(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *,
    read_args: list[object] | tuple[object, ...],
    preview_args: list[object] | tuple[object, ...] | None = None,
    persist_args: list[object] | tuple[object, ...],
    after_persist_args: list[object] | tuple[object, ...] | None = None,
) -> dict[str, object]:
    preview_result = preview_snapshot(
        idac_cmd,
        idac_env,
        database,
        read_args=read_args,
        preview_args=persist_args if preview_args is None else preview_args,
    )
    persisted = run_idalib_json(idac_cmd, idac_env, database, *persist_args)
    after_persist = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        *(read_args if after_persist_args is None else after_persist_args),
    )
    return {
        **preview_result,
        "persisted": persisted,
        "after_persist": after_persist,
    }


def run_preview_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    out_path: Path,
    *args: object,
) -> tuple[subprocess.CompletedProcess[str], object]:
    proc = run_cli(idac_cmd, idac_env, "preview", "-o", str(out_path), "-c", f"db:{database}", *args)
    assert out_path.exists(), proc.stderr or proc.stdout
    return proc, json.loads(out_path.read_text(encoding="utf-8"))


def preview_snapshot_cli2(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    tmp_path: Path,
    *,
    read_args: list[object] | tuple[object, ...],
    preview_args: list[object] | tuple[object, ...],
    filename: str = "preview.json",
) -> dict[str, object]:
    before = run_idalib_json(idac_cmd, idac_env, database, *read_args)
    proc, preview = run_preview_json(idac_cmd, idac_env, database, tmp_path / filename, *preview_args)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    after_preview = run_idalib_json(idac_cmd, idac_env, database, *read_args)
    return {
        "before": before,
        "preview": preview,
        "after_preview": after_preview,
    }


def preview_round_trip_cli2(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    tmp_path: Path,
    *,
    read_args: list[object] | tuple[object, ...],
    persist_args: list[object] | tuple[object, ...],
    preview_args: list[object] | tuple[object, ...] | None = None,
    after_persist_args: list[object] | tuple[object, ...] | None = None,
    filename: str = "preview.json",
) -> dict[str, object]:
    preview_result = preview_snapshot_cli2(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=read_args,
        preview_args=persist_args if preview_args is None else preview_args,
        filename=filename,
    )
    persisted = run_idalib_json(idac_cmd, idac_env, database, *persist_args)
    after_persist = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        *(read_args if after_persist_args is None else after_persist_args),
    )
    return {
        **preview_result,
        "persisted": persisted,
        "after_persist": after_persist,
    }


__all__ = [
    "preview_round_trip",
    "preview_round_trip_cli2",
    "preview_snapshot",
    "preview_snapshot_cli2",
    "run_cli",
    "run_cli_json",
    "run_idalib",
    "run_idalib_json",
    "run_idalib_text",
    "run_preview_json",
]
