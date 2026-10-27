from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..argparse_utils import add_command, add_context_options, add_output_options
from ..errors import CliUserError
from ..result import CommandResult
from .common import command_result

_CONVENIENCE_MODULES = (
    "idaapi",
    "ida_auto",
    "ida_bytes",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_idc",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_moves",
    "ida_name",
    "ida_nalt",
    "ida_range",
    "ida_segment",
    "ida_strlist",
    "ida_typeinf",
    "ida_ua",
    "ida_undo",
    "ida_xref",
    "idautils",
    "idc",
)


def _nexus_python_source(user_code: str, filename: str) -> str:
    """Wrap user code in a stateless JSON-safe Nexus call."""

    return f"""\
import importlib as _idac_importlib
import json as _idac_json
for _idac_module_name in {_CONVENIENCE_MODULES!r}:
    try:
        globals()[_idac_module_name] = _idac_importlib.import_module(_idac_module_name)
    except (ImportError, OSError):
        pass
__file__ = {filename!r}
result = None
exec(compile({user_code!r}, {filename!r}, "exec"), globals(), globals())
_idac_result = result
try:
    _idac_json.dumps(_idac_result)
except (TypeError, ValueError):
    _idac_json_result = None
else:
    _idac_json_result = _idac_result
{{"result": _idac_json_result, "result_repr": repr(_idac_result)}}
"""


def _exec(args: argparse.Namespace) -> CommandResult:
    filename = "<idac py exec>"
    if args.code is not None:
        code = str(args.code)
    elif args.stdin:
        code = sys.stdin.read()
    else:
        path = Path(args.script)
        if not path.is_file():
            raise CliUserError(f"script file not found: {path}")
        path = path.resolve()
        filename = str(path)
        code = path.read_text(encoding="utf-8")
    if not code.strip():
        raise CliUserError("Python input must not be empty")

    session = getattr(args, "_nexus_session", None)
    if session is None:
        raise CliUserError("py exec requires a Nexus context")
    execution = session.execute_python(
        _nexus_python_source(code, filename),
        filename=filename,
        operation_label="idac: py exec",
    )
    value = execution.get("result")
    if not isinstance(value, dict):
        raise CliUserError("Nexus returned an invalid Python result")
    value = dict(value)
    value["stdout"] = str(execution.get("stdout") or "")
    value["stderr"] = str(execution.get("stderr") or "")
    return command_result("python_exec", value)


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "py", help_text="Execute stateless Python through ida-nexus")
    py_subparsers = parser.add_subparsers(dest="py_command")

    child = add_command(parser, py_subparsers, "exec", help_text="Execute Python code")
    add_context_options(child)
    add_output_options(child, default_format="text")
    mode = child.add_mutually_exclusive_group(required=True)
    mode.add_argument("--code", help="Execute inline Python code")
    mode.add_argument("--stdin", action="store_true", help="Read Python code from stdin")
    mode.add_argument("--script", type=Path, help="Read Python code from this local file")
    child.set_defaults(
        run=_exec,
        allow_batch=True,
        allow_preview=False,
        _mutating_command=True,
        _input_path_attrs=("script",),
    )


__all__ = ["register"]
