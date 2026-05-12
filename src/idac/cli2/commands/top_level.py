from __future__ import annotations

import argparse
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...output import write_output_result
from ...transport import BackendError
from ..argparse_utils import add_command, add_context_options, add_output_options
from ..commands.common import send_op
from ..errors import CliUserError
from ..result import CommandResult

_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_FILENAME_STEM = 180


@dataclass(frozen=True)
class DecompileManyRequest:
    pattern: str | None
    extra_patterns: tuple[str, ...]
    file: Path | None
    out_file: Path | None
    out_dir: Path | None
    regex: bool
    ignore_case: bool
    no_cache: bool
    include_disasm: bool
    include_ctree: bool


@dataclass(frozen=True)
class ArtifactStem:
    stem: str
    truncated: bool


def _decompilemany_request(args: argparse.Namespace) -> DecompileManyRequest:
    patterns = tuple(item for item in args.patterns if item)
    pattern = patterns[0] if patterns else None
    extra_patterns = patterns[1:]
    return DecompileManyRequest(
        pattern=pattern,
        extra_patterns=extra_patterns,
        file=args.file,
        out_file=args.out_file,
        out_dir=args.out_dir,
        regex=args.regex,
        ignore_case=args.ignore_case,
        no_cache=args.no_cache,
        include_disasm=bool(args.disasm),
        include_ctree=bool(args.ctree),
    )


def _safe_filename_name(name: str) -> str:
    return _SAFE_FILENAME_RE.sub("_", name).strip("._-") or "function"


def _safe_address(address: str) -> str:
    return _SAFE_FILENAME_RE.sub("_", address).strip("._-") or "ea"


def _identity_digest(*, name: str, address: str, identifier: str) -> str:
    text = "\0".join((name, address, identifier))
    return f"{zlib.crc32(text.encode('utf-8')) & 0xFFFFFFFF:08x}"


def _stem_for_function(name: str, address: str, identifier: str) -> ArtifactStem:
    safe_name = _safe_filename_name(name)
    safe_address = _safe_address(address)
    full_stem = f"{safe_name}_{safe_address}"
    if len(full_stem) <= _MAX_FILENAME_STEM:
        return ArtifactStem(full_stem, False)

    suffix = f"_{_identity_digest(name=name, address=address, identifier=identifier)}_{safe_address}"
    available = max(24, _MAX_FILENAME_STEM - len(suffix) - 1)
    head_len = max(12, (available * 2) // 3)
    tail_len = max(8, available - head_len)
    head = safe_name[:head_len].rstrip("._-") or safe_name[:head_len]
    tail = safe_name[-tail_len:].lstrip("._-") or safe_name[-tail_len:]
    return ArtifactStem(f"{head}_{tail}{suffix}", True)


def _decompilemany_targets(args: argparse.Namespace) -> list[dict[str, Any]]:
    request = _decompilemany_request(args)
    if request.extra_patterns:
        examples = " ".join((request.pattern or "", *request.extra_patterns[:3])).strip()
        suffix = f": {examples}" if examples else ""
        raise CliUserError(
            "decompilemany accepts one FUNCTION_FILTER, not multiple exact function names"
            f"{suffix}. For multiple exact functions, write one function name or address per line "
            "and pass --functions-file/--file <path>."
        )
    if request.pattern not in (None, "") and request.file is not None:
        raise CliUserError("decompilemany accepts either FUNCTION_FILTER or --functions-file/--file, not both")
    if request.pattern in (None, "") and request.file is None:
        raise CliUserError("decompilemany requires either FUNCTION_FILTER or --functions-file/--file")
    if request.file is not None:
        rows: list[str] = []
        for raw_line in request.file.read_text(encoding="utf-8").splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            rows.append(stripped)
        seen: set[str] = set()
        items: list[dict[str, Any]] = []
        for identifier in rows:
            function_result = send_op(
                args,
                op="function_show",
                params={"identifier": identifier},
                render_op="function_show",
            )
            value = function_result.value
            if not isinstance(value, dict):
                continue
            address = str(value.get("address") or "")
            if address in seen:
                continue
            seen.add(address)
            items.append(
                {
                    "identifier": identifier,
                    "name": str(value.get("name") or identifier),
                    "address": address,
                }
            )
        return items

    rows_result = send_op(
        args,
        op="function_list",
        params={
            "pattern": request.pattern,
            "regex": request.regex,
            "ignore_case": request.ignore_case,
        },
        render_op="function_list",
    )
    rows = rows_result.value
    if not isinstance(rows, list):
        return []
    return [
        {
            "identifier": str(item.get("name") or item.get("address") or ""),
            "name": str(item.get("name") or item.get("address") or "function"),
            "address": str(item.get("address") or ""),
        }
        for item in rows
        if isinstance(item, dict)
    ]


def _run_single_decompile(
    args: argparse.Namespace,
    *,
    identifier: str,
) -> dict[str, Any]:
    request = _decompilemany_request(args)
    result = send_op(
        args,
        op="decompile",
        params={"identifier": identifier, "no_cache": request.no_cache},
        render_op="decompile",
        preview=False,
    )
    value = result.value
    if not isinstance(value, dict) or not isinstance(value.get("text"), str):
        raise RuntimeError("decompile returned an unexpected result shape")
    return value


def _run_single_text_op(
    args: argparse.Namespace,
    *,
    op: str,
    identifier: str,
) -> dict[str, Any]:
    result = send_op(
        args,
        op=op,
        params={"identifier": identifier},
        render_op=op,
        preview=False,
    )
    value = result.value
    if not isinstance(value, dict) or not isinstance(value.get("text"), str):
        raise RuntimeError(f"{op} returned an unexpected result shape")
    return value


def run_decompile(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="decompile",
        params={"identifier": args.function, "no_cache": bool(args.no_cache)},
        render_op="decompile",
    )


def run_disasm(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="disasm", params={"identifier": args.function}, render_op="disasm")


def run_ctree(args: argparse.Namespace) -> CommandResult:
    params: dict[str, Any] = {"identifier": args.function, "level": args.level}
    if args.maturity:
        params["maturity"] = args.maturity
    return send_op(args, op="ctree", params=params, render_op="ctree")


def run_xrefs(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="xrefs", params={"identifier": args.identifier}, render_op="xrefs")


def run_imports(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="imports", params={}, render_op="imports")


def run_decompilemany(args: argparse.Namespace) -> CommandResult:
    request = _decompilemany_request(args)
    if request.out_file is not None and (request.include_disasm or request.include_ctree):
        raise CliUserError("decompilemany --disasm/--ctree require --out-dir")
    targets = _decompilemany_targets(args)
    if not targets:
        raise CliUserError("no functions matched")

    entries: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    succeeded = 0
    failed = 0
    combined_sections: list[str] = []
    out_dir = None
    if request.out_dir is not None:
        out_dir = request.out_dir
        out_dir.mkdir(parents=True, exist_ok=True)
    for item in targets:
        identifier = str(item["identifier"])
        disasm_payload: dict[str, Any] | None = None
        ctree_payload: dict[str, Any] | None = None
        try:
            payload = _run_single_decompile(args, identifier=identifier)
            if request.include_disasm:
                disasm_payload = _run_single_text_op(args, op="disasm", identifier=identifier)
            if request.include_ctree:
                ctree_payload = _run_single_text_op(args, op="ctree", identifier=identifier)
        except (BackendError, CliUserError) as exc:
            failed += 1
            entries.append(
                {
                    "identifier": identifier,
                    "name": item["name"],
                    "address": item["address"],
                    "ok": False,
                    "error": str(exc) or exc.__class__.__name__,
                }
            )
            continue
        text = str(payload["text"])
        succeeded += 1
        entry = {
            "identifier": identifier,
            "name": item["name"],
            "address": item["address"],
            "ok": True,
            "chars": len(text),
        }
        if out_dir is None:
            combined_sections.append(text)
        else:
            stem_info = _stem_for_function(str(item["name"]), str(item["address"]), identifier)
            stem = stem_info.stem
            entry_artifacts: dict[str, str] = {}
            artifact_path = out_dir / f"{stem}.c"
            output = write_output_result(text, fmt="text", out_path=artifact_path, stem="decompile")
            artifact = dict(output.artifact or {})
            artifact.update({"kind": "decompile", "identifier": identifier, "chars": len(text)})
            artifacts.append(artifact)
            entry_artifacts["decompile"] = str(artifact_path)
            entry["artifact_path"] = str(artifact_path)
            entry["artifact_stem"] = stem
            if stem_info.truncated:
                entry["filename_truncated"] = True
            if disasm_payload is not None:
                disasm_text = str(disasm_payload["text"])
                disasm_path = out_dir / f"{stem}.asm"
                output = write_output_result(disasm_text, fmt="text", out_path=disasm_path, stem="disasm")
                artifact = dict(output.artifact or {})
                artifact.update({"kind": "disasm", "identifier": identifier, "chars": len(disasm_text)})
                artifacts.append(artifact)
                entry_artifacts["disasm"] = str(disasm_path)
                entry["disasm_chars"] = len(disasm_text)
            if ctree_payload is not None:
                ctree_text = str(ctree_payload["text"])
                ctree_path = out_dir / f"{stem}.ctree"
                output = write_output_result(ctree_text, fmt="text", out_path=ctree_path, stem="ctree")
                artifact = dict(output.artifact or {})
                artifact.update({"kind": "ctree", "identifier": identifier, "chars": len(ctree_text)})
                artifacts.append(artifact)
                entry_artifacts["ctree"] = str(ctree_path)
                entry["ctree_chars"] = len(ctree_text)
            entry["artifacts"] = entry_artifacts
        entries.append(entry)

    if out_dir is None:
        artifact_path = request.out_file
        if artifact_path is None:
            raise CliUserError("decompilemany requires --out-file or --out-dir")
        combined = "\n\n\n".join(combined_sections)
        output = write_output_result(
            combined,
            fmt="text",
            out_path=artifact_path,
            stem="decompile_bulk",
            force_fmt=True,
        )
        artifact = dict(output.artifact or {})
        artifact["kind"] = "combined_text"
        artifacts.append(artifact)
        summary = {
            "ok": failed == 0,
            "pattern": request.pattern,
            "file": None if request.file is None else str(request.file),
            "out_file": str(artifact_path),
            "functions_total": len(targets),
            "functions_succeeded": succeeded,
            "functions_failed": failed,
            "functions": entries,
        }
        stderr_lines = _decompilemany_failure_lines(summary)
        return CommandResult(
            render_op="decompile_bulk",
            value=summary,
            exit_code=0 if failed == 0 else 1,
            stderr_lines=stderr_lines,
            artifacts=artifacts,
        )

    manifest = {
        "ok": failed == 0,
        "pattern": request.pattern,
        "file": None if request.file is None else str(request.file),
        "out_dir": str(out_dir),
        "functions_total": len(targets),
        "functions_succeeded": succeeded,
        "functions_failed": failed,
        "functions": entries,
    }
    manifest_path = out_dir / "manifest.json"
    output = write_output_result(manifest, fmt="json", out_path=manifest_path, stem="decompile_manifest")
    artifact = dict(output.artifact or {})
    artifact["kind"] = "manifest"
    artifacts.append(artifact)
    summary = dict(manifest)
    summary["manifest_path"] = str(manifest_path)
    stderr_lines = _decompilemany_failure_lines(summary)
    return CommandResult(
        render_op="decompile_bulk",
        value=summary,
        exit_code=0 if failed == 0 else 1,
        stderr_lines=stderr_lines,
        artifacts=artifacts,
    )


def _decompilemany_failure_lines(summary: dict[str, Any]) -> list[str]:
    failed = int(summary.get("functions_failed") or 0)
    if failed <= 0:
        return []
    total = int(summary.get("functions_total") or 0)
    lines = [f"decompilemany failed for {failed}/{total} function(s)"]
    functions = summary.get("functions")
    if not isinstance(functions, list):
        return lines
    shown = 0
    for item in functions:
        if not isinstance(item, dict) or item.get("ok") is not False:
            continue
        identifier = str(item.get("identifier") or item.get("name") or item.get("address") or "<unknown>")
        error = str(item.get("error") or "failed").strip()
        lines.append(f"{identifier}: {error}")
        shown += 1
        if shown >= 10:
            break
    if failed > shown:
        lines.append(f"... {failed - shown} more failure(s)")
    return lines


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "decompile", help_text="Decompile one function")
    add_context_options(parser)
    add_output_options(parser, default_format="text")
    parser.add_argument("function", help="Function name or address")
    parser.add_argument(
        "--no-cache",
        "--f5",
        dest="no_cache",
        action="store_true",
        help="Force a fresh Hex-Rays decompilation instead of reusing cached pseudocode",
    )
    parser.set_defaults(
        run=run_decompile, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    parser = add_command(
        root_parser,
        subparsers,
        "decompilemany",
        help_text="Decompile functions selected by name filter or target file",
    )
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = """examples:
  # Decompile every function whose name contains Handler_
  idac decompilemany Handler_ --out-dir .idac/tmp/decomp -c db:sample.i64

  # Decompile an explicit set of functions
  printf '%s\\n' main sub_401000 0x401234 > funcs.txt
  idac decompilemany --functions-file funcs.txt --out-dir .idac/tmp/decomp -c db:sample.i64

  # Write explicit functions into one combined output file
  idac decompilemany --functions-file funcs.txt --out-file .idac/tmp/decompile.c -c db:sample.i64
"""
    add_context_options(parser)
    add_output_options(parser, default_format="text")
    selection = parser.add_argument_group("selection")
    selection.add_argument(
        "patterns",
        nargs="*",
        metavar="FUNCTION_FILTER",
        help=(
            "Select functions by name substring; with --regex, treat as a regex. "
            "This is not a list of function names; use --file for multiple exact functions."
        ),
    )
    selection.add_argument(
        "--file",
        "--functions-file",
        dest="file",
        type=Path,
        help=(
            "Read exact function identifiers from this file, one per line. "
            "Identifiers may be function names or addresses; blank lines and # comments are ignored. "
            "Use this for multiple explicit functions."
        ),
    )
    output_group = parser.add_argument_group("artifact output")
    out_mode = output_group.add_mutually_exclusive_group(required=True)
    out_mode.add_argument("--out-file", type=Path, help="Write all selected pseudocode into one combined text file")
    out_mode.add_argument("--out-dir", type=Path, help="Write one .c file per selected function plus manifest.json")
    parser.add_argument(
        "--regex",
        action="store_true",
        help="Interpret FUNCTION_FILTER as a regular expression",
    )
    parser.add_argument(
        "-i",
        "--ignore-case",
        action="store_true",
        help="Match FUNCTION_FILTER without case sensitivity",
    )
    parser.add_argument(
        "--no-cache",
        "--f5",
        dest="no_cache",
        action="store_true",
        help="Force a fresh Hex-Rays decompilation instead of reusing cached pseudocode",
    )
    parser.add_argument(
        "--disasm",
        action="store_true",
        help="With --out-dir, also write one .asm disassembly artifact per selected function",
    )
    parser.add_argument(
        "--ctree",
        action="store_true",
        help="With --out-dir, also write one .ctree Hex-Rays ctree artifact per selected function",
    )
    parser.set_defaults(
        run=run_decompilemany,
        context_policy="standard",
        allow_batch=True,
        allow_preview=True,
        _mutating_command=False,
    )

    parser = add_command(root_parser, subparsers, "disasm", help_text="Disassemble a function")
    add_context_options(parser)
    add_output_options(parser, default_format="text")
    parser.add_argument("function", help="Function name or address")
    parser.set_defaults(
        run=run_disasm, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    parser = add_command(root_parser, subparsers, "ctree", help_text="Inspect Hex-Rays ctree or microcode")
    add_context_options(parser)
    add_output_options(parser, default_format="text")
    parser.add_argument("function", help="Function name or address")
    parser.add_argument("--level", choices=("ctree", "micro"), default="ctree", help="Inspect ctree or microcode")
    parser.add_argument(
        "--maturity",
        choices=("generated", "preoptimized", "locopt", "calls", "glbopt1", "glbopt2", "glbopt3", "lvars"),
        help="Requested microcode maturity when --level micro is used",
    )
    parser.set_defaults(
        run=run_ctree, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    parser = add_command(root_parser, subparsers, "xrefs", help_text="Show cross-references")
    add_context_options(parser)
    add_output_options(parser, default_format="text")
    parser.add_argument("identifier", help="Function name, symbol, or address")
    parser.set_defaults(
        run=run_xrefs, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    parser = add_command(root_parser, subparsers, "imports", help_text="List imports")
    add_context_options(parser)
    add_output_options(parser, default_format="text")
    parser.set_defaults(
        run=run_imports, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )
