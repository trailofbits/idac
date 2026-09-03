from __future__ import annotations

import argparse

from ...setup import setup_gui
from ..argparse_utils import add_command, add_output_options, positive_timeout
from .common import LocalCommandBinding, run_bound_local_command


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "setup", help_text="Install pinned idac integrations")
    setup_subparsers = parser.add_subparsers(dest="setup_command")

    child = add_command(parser, setup_subparsers, "gui", help_text="Install ida-nexus v0.7.0 through ida-hcli")
    add_output_options(child, default_format="json")
    child.add_argument("--timeout", type=positive_timeout, help="Installer timeout in seconds")
    child.set_defaults(
        run=run_bound_local_command,
        _local_command_binding=LocalCommandBinding("setup_gui", setup_gui, keyword_attrs=(("timeout", "timeout"),)),
        allow_batch=False,
        allow_preview=False,
        _accepts_timeout=True,
    )


__all__ = ["register"]
