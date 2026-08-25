from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

_PSEUDOCODE_STRING_OR_NAMED_CALL_ARGUMENT_RE = re.compile(
    r"""
    "(?:\\.|[^"\\])*"
    | '(?:\\.|[^'\\])*'
    | //[^\r\n]*
    | /\*.*?\*/
    | (?<=[(,])(?P<whitespace>\s*)[A-Za-z_][A-Za-z0-9_]*:(?!:)\s*
    """,
    re.DOTALL | re.VERBOSE,
)


def _flatten_args(*args: object) -> list[str]:
    flattened: list[str] = []
    for arg in args:
        if isinstance(arg, (list, tuple)):
            flattened.extend(str(item) for item in arg)
            continue
        flattened.append(str(arg))
    return flattened


def normalize_pseudocode_call_arguments(text: str) -> str:
    """Remove optional argument-name annotations from Hex-Rays calls."""

    def replace(match: re.Match[str]) -> str:
        if match.group("whitespace") is None:
            return match.group()
        return match.group("whitespace")

    return _PSEUDOCODE_STRING_OR_NAMED_CALL_ARGUMENT_RE.sub(replace, text)


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


def run_nexus(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *args: object,
    input_text: str | None = None,
    use_json: bool = False,
) -> subprocess.CompletedProcess[str]:
    format_args = ["--format", "json"] if use_json else []
    return subprocess.run(
        [
            *idac_cmd,
            *_flatten_args(*args),
            "-c",
            str(database),
            *format_args,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=idac_env,
        input=input_text,
    )


def run_nexus_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *args: object,
    input_text: str | None = None,
) -> object:
    proc = run_nexus(idac_cmd, idac_env, database, *args, input_text=input_text, use_json=True)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return json.loads(proc.stdout)


def run_nexus_text(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    *args: object,
    input_text: str | None = None,
) -> str:
    proc = run_nexus(idac_cmd, idac_env, database, *args, input_text=input_text, use_json=False)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return proc.stdout


def run_preview_json(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    out_path: Path,
    *args: object,
) -> tuple[subprocess.CompletedProcess[str], object]:
    proc = run_cli(idac_cmd, idac_env, "preview", "-o", str(out_path), "-c", str(database), *args)
    assert out_path.exists(), proc.stderr or proc.stdout
    return proc, json.loads(out_path.read_text(encoding="utf-8"))


def preview_snapshot(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    database: Path,
    tmp_path: Path,
    *,
    read_args: list[object] | tuple[object, ...],
    preview_args: list[object] | tuple[object, ...],
    filename: str = "preview.json",
) -> dict[str, object]:
    before = run_nexus_json(idac_cmd, idac_env, database, *read_args)
    proc, preview = run_preview_json(idac_cmd, idac_env, database, tmp_path / filename, *preview_args)
    assert proc.returncode == 0, proc.stderr or proc.stdout
    after_preview = run_nexus_json(idac_cmd, idac_env, database, *read_args)
    return {
        "before": before,
        "preview": preview,
        "after_preview": after_preview,
    }


def preview_round_trip(
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
    preview_result = preview_snapshot(
        idac_cmd,
        idac_env,
        database,
        tmp_path,
        read_args=read_args,
        preview_args=persist_args if preview_args is None else preview_args,
        filename=filename,
    )
    persisted = run_nexus_json(idac_cmd, idac_env, database, *persist_args)
    after_persist = run_nexus_json(
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
    "normalize_pseudocode_call_arguments",
    "preview_round_trip",
    "preview_snapshot",
    "run_cli",
    "run_cli_json",
    "run_nexus",
    "run_nexus_json",
    "run_nexus_text",
    "run_preview_json",
]
