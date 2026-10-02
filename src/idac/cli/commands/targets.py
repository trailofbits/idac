from __future__ import annotations

import argparse

from ... import nexus
from ..argparse_utils import add_command, add_output_options, positive_timeout
from .common import LocalCommandBinding, run_bound_local_command


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "targets", help_text="List ida-nexus database instances")
    targets_subparsers = parser.add_subparsers(dest="targets_command")

    child = add_command(parser, targets_subparsers, "list", help_text="List discovered Nexus instances")
    add_output_options(child, default_format="text")
    child.add_argument("--timeout", type=positive_timeout, help="Discovery probe timeout in seconds")
    child.set_defaults(
        run=run_bound_local_command,
        _local_command_binding=LocalCommandBinding(
            "list_targets", nexus.list_targets, keyword_attrs=(("timeout", "timeout"),)
        ),
        allow_batch=True,
        allow_preview=False,
        _accepts_timeout=True,
    )


__all__ = ["register"]
