from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_context_options, add_output_options
from .common import OperationBinding, bind_operation, run_bound_operation


def _reanalyze_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {"identifier": args.identifier}
    if args.end:
        params["end"] = args.end
    return params


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "misc", help_text="Miscellaneous IDA operations")
    misc_subparsers = parser.add_subparsers(dest="misc_command")

    child = add_command(parser, misc_subparsers, "rename", help_text="Rename an item")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Function name, symbol, or address")
    child.add_argument("new_name", help="Replacement name")
    child.set_defaults(
        run=run_bound_operation,
        allow_batch=False,
        allow_preview=True,
    )
    bind_operation(
        child,
        OperationBinding("name_set", parameter_attrs=(("identifier", "identifier"), ("new_name", "new_name"))),
    )

    child = add_command(parser, misc_subparsers, "reanalyze", help_text="Re-run IDA analysis on a function or range")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Function name, symbol, or address")
    child.add_argument("--end", help="Optional end address for range reanalysis")
    child.set_defaults(
        run=run_bound_operation,
        allow_batch=True,
        allow_preview=False,
    )
    bind_operation(child, OperationBinding("reanalyze", params_builder=_reanalyze_params))


__all__ = ["register"]
