from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from ..output import DEFAULT_INLINE_CHAR_LIMIT, OutputTooLargeError, resolve_output_format, write_output_result
from .renderers import TEXT_RENDERERS, render_doctor
from .result import CommandResult

SUMMARY_CHAR_LIMIT = 1200
_NO_INLINE_LIMIT = 10**9

_LIST_COUNT_LABELS: dict[str, str] = {
    "list_targets": "target",
    "segment_list": "segment",
    "function_list": "function",
    "type_list": "type",
    "struct_list": "struct",
    "enum_list": "enum",
    "class_list": "class",
    "class_candidates": "candidate",
    "strings": "string",
    "imports": "import module",
}

_DICT_COUNT_FIELDS: dict[str, tuple[str, str]] = {
    "search_bytes": ("results", "match"),
    "local_list": ("locals", "local"),
    "local_rename": ("locals", "local"),
    "local_retype": ("locals", "local"),
    "local_update": ("locals", "local"),
    "function_stackvars": ("stackvars", "stack variable"),
    "function_callers": ("edges", "call edge"),
    "function_callees": ("edges", "call edge"),
    "class_fields": ("fields", "field"),
    "bookmark_get": ("bookmarks", "bookmark"),
}


def _terminal_color_enabled(*, fmt: str, out_path: Path | None) -> bool:
    setting = os.environ.get("IDAC_COLOR", "").strip().lower()
    if setting in {"0", "false", "never", "no", "off"}:
        return False
    if setting in {"1", "true", "always", "yes", "on"}:
        return fmt == "text" and out_path is None
    if "NO_COLOR" in os.environ:
        return False
    return fmt == "text" and out_path is None and sys.stdout.isatty()


def _render_value(render_op: str, value: Any, fmt: str, *, color: bool = False) -> Any:
    if fmt != "text":
        return value
    if render_op == "doctor":
        return render_doctor(value, color=color)
    renderer = TEXT_RENDERERS.get(render_op)
    if renderer is None:
        return value
    return renderer(value)


def _summary_prefix(text: str) -> str:
    snippet = text[:SUMMARY_CHAR_LIMIT]
    if snippet.endswith("\n"):
        return snippet
    return snippet + "\n"


def _pluralize(noun: str, count: int) -> str:
    if count == 1:
        return noun
    if " " in noun:
        prefix, last = noun.rsplit(" ", 1)
        return f"{prefix} {_pluralize(last, count)}"
    if noun.endswith(("s", "x", "z", "ch", "sh")):
        return noun + "es"
    if noun.endswith("y") and len(noun) > 1 and noun[-2].lower() not in "aeiou":
        return noun[:-1] + "ies"
    return noun + "s"


def _result_count_summary(result: CommandResult) -> tuple[int, str] | None:
    if result.render_op in _LIST_COUNT_LABELS and isinstance(result.value, list):
        return len(result.value), _LIST_COUNT_LABELS[result.render_op]

    dict_summary = _DICT_COUNT_FIELDS.get(result.render_op)
    if dict_summary is not None and isinstance(result.value, dict):
        field, noun = dict_summary
        rows = result.value.get(field)
        if isinstance(rows, list):
            return len(rows), noun

    if result.render_op == "decompile_bulk" and isinstance(result.value, dict):
        return int(result.value.get("functions_total") or 0), "function"

    if result.render_op == "batch" and isinstance(result.value, dict):
        return int(result.value.get("commands_total") or 0), "command"

    return None


def artifact_notice(result: CommandResult, artifact: dict[str, Any]) -> str | None:
    path = artifact.get("artifact_path")
    if not isinstance(path, str) or not path:
        return None

    if result.render_op == "preview":
        return f"wrote preview data to {path}; inspect that file for the full result"

    if result.render_op == "decompile":
        return f"wrote decompile text to {path}; inspect that file for the full result"

    if result.render_op == "disasm":
        return f"wrote disassembly to {path}; inspect that file for the full result"

    if result.render_op == "ctree":
        return f"wrote ctree output to {path}; inspect that file for the full result"

    if result.render_op == "decompile_bulk":
        count = int(result.value.get("functions_total") or 0) if isinstance(result.value, dict) else 0
        noun = _pluralize("function", count)
        return f"wrote decompile summary for {count} {noun} to {path}; inspect that file for the full result"

    if result.render_op == "batch":
        count = int(result.value.get("commands_total") or 0) if isinstance(result.value, dict) else 0
        noun = _pluralize("command", count)
        return f"wrote batch log for {count} {noun} to {path}; inspect that file for the full result"

    count_summary = _result_count_summary(result)
    if count_summary is not None:
        count, noun = count_summary
        return f"wrote {count} {_pluralize(noun, count)} to {path}; inspect that file for the full result"

    return f"wrote result to {path}; inspect that file for the full result"


def _inline_limit_hint(result: CommandResult, *, out_flag: str) -> str | None:
    if result.render_op == "decompile":
        return "rerun with `-o <path>` to write the full decompile to a file"
    if result.render_op == "disasm":
        return "rerun with `-o <path>` to write the full disassembly to a file"
    if result.render_op == "ctree":
        return "rerun with `-o <path>` to write the full ctree output to a file"
    if result.render_op in {"local_list", "local_rename", "local_retype", "local_update"}:
        return "rerun with `--json --out <path>` to inspect the full locals table"
    if result.render_op == "docs":
        return "rerun with `--out <path>` to write the full docs output to a file"

    count_summary = _result_count_summary(result)
    if count_summary is not None:
        return f"rerun with `{out_flag} <path>` to inspect the full result"
    return None


def emit_result(
    result: CommandResult,
    *,
    fmt: str,
    out_path: Path | None,
    out_flag: str = "--out",
    inline_limit: int = DEFAULT_INLINE_CHAR_LIMIT,
) -> list[dict[str, Any]]:
    effective_fmt = resolve_output_format(fmt, out_path)
    rendered_value = _render_value(
        result.render_op,
        result.value,
        effective_fmt,
        color=_terminal_color_enabled(fmt=effective_fmt, out_path=out_path),
    )
    output = write_output_result(
        rendered_value,
        fmt=effective_fmt,
        out_path=out_path,
        stem=result.render_op,
        inline_char_limit=_NO_INLINE_LIMIT,
    )
    if output.artifact is not None:
        return [output.artifact]
    if len(output.rendered) > inline_limit:
        sys.stdout.write(_summary_prefix(output.rendered))
        raise OutputTooLargeError(
            chars=len(output.rendered),
            limit=inline_limit,
            out_flag=out_flag,
            hint=_inline_limit_hint(result, out_flag=out_flag),
        )
    sys.stdout.write(output.rendered)
    return []


def json_or_jsonl_from_path(path: Path | None, *, default: str = "json") -> str:
    if path is None:
        return default
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return "jsonl"
    return "json"
