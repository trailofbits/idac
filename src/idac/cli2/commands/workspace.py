from __future__ import annotations

import argparse
from pathlib import Path

from ...workspace import initialize_workspace
from ..argparse_utils import add_command, add_output_options
from ..commands.common import command_result
from ..result import CommandResult


def _init(args: argparse.Namespace) -> CommandResult:
    return command_result("workspace_init", initialize_workspace(Path(args.dest), force=bool(args.force)))


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(
        root_parser, subparsers, "workspace", help_text="Initialize or manage reverse-engineering workspaces"
    )
    workspace_subparsers = parser.add_subparsers(dest="workspace_command")

    child = add_command(parser, workspace_subparsers, "init", help_text="Initialize a reverse-engineering workspace")
    add_output_options(child, default_format="text")
    child.add_argument("dest", nargs="?", default=".", help="Directory to initialize")
    child.add_argument(
        "--force", action="store_true", help="Overwrite user-tunable config when the workspace already exists"
    )
    child.set_defaults(run=_init, context_policy="none", allow_batch=True, allow_preview=False, _mutating_command=False)
