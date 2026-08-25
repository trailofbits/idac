from __future__ import annotations

import argparse
from pathlib import Path

from ...workspace import initialize_workspace
from ..argparse_utils import add_command, add_output_options
from ..commands.common import LocalCommandBinding, run_bound_local_command


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(
        root_parser, subparsers, "workspace", help_text="Initialize or manage reverse-engineering workspaces"
    )
    workspace_subparsers = parser.add_subparsers(dest="workspace_command")

    child = add_command(parser, workspace_subparsers, "init", help_text="Initialize a reverse-engineering workspace")
    add_output_options(child, default_format="text")
    child.add_argument("dest", nargs="?", type=Path, default=Path("."), help="Directory to initialize")
    child.add_argument(
        "--force", action="store_true", help="Overwrite user-tunable config when the workspace already exists"
    )
    child.set_defaults(
        run=run_bound_local_command,
        _local_command_binding=LocalCommandBinding(
            "workspace_init",
            initialize_workspace,
            positional_attrs=("dest",),
            keyword_attrs=(("force", "force"),),
        ),
        allow_batch=True,
        allow_preview=False,
    )
