from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from ..argparse_utils import add_command, add_context_options, add_output_options
from ..commands.common import send_op
from ..errors import CliUserError
from ..result import CommandResult


@dataclass(frozen=True)
class PythonExecRequest:
    script: str
    persist: bool

    def to_params(self) -> dict[str, object]:
        params: dict[str, object] = {"script": self.script}
        if self.persist:
            params["persist"] = True
        return params


def _python_exec_request(args: argparse.Namespace) -> PythonExecRequest:
    if args.code:
        script = str(args.code)
    elif args.stdin:
        script = sys.stdin.read()
    elif args.script:
        script = args.script.read_text(encoding="utf-8")
    else:
        raise CliUserError("missing Python input")
    return PythonExecRequest(script=script, persist=bool(args.persist))


def _exec(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="python_exec", params=_python_exec_request(args).to_params(), render_op="python_exec")


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "py", help_text="Execute Python in the backend runtime")
    py_subparsers = parser.add_subparsers(dest="py_command")

    child = add_command(parser, py_subparsers, "exec", help_text="Execute Python code")
    add_context_options(child)
    add_output_options(child, default_format="text")
    mode = child.add_mutually_exclusive_group(required=True)
    mode.add_argument("--code", help="Execute inline Python code")
    mode.add_argument("--stdin", action="store_true", help="Read Python code from stdin")
    mode.add_argument("--script", type=Path, help="Read Python code from this file")
    child.add_argument(
        "--persist",
        action="store_true",
        help="Reuse the same Python globals across later py exec commands in the current session",
    )
    child.set_defaults(
        run=_exec, context_policy="standard", allow_batch=True, allow_preview=False, _mutating_command=True
    )
