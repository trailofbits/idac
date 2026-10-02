from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_standard_command
from ..commands.common import OperationBinding, bind_operation, parse_bookmark_slot, run_bound_operation


def _bookmark_slot_params(args: argparse.Namespace) -> dict[str, object]:
    return {"slot": parse_bookmark_slot(args.slot)}


def _bookmark_add_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {"address": str(args.identifier)}
    if args.comment is not None:
        params["comment"] = args.comment
    return params


def _bookmark_set_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {"slot": parse_bookmark_slot(args.slot), "address": str(args.identifier)}
    if args.comment is not None:
        params["comment"] = args.comment
    return params


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "bookmark", help_text="Bookmark operations")
    bookmark_subparsers = parser.add_subparsers(dest="bookmark_command")

    child = add_standard_command(
        parser,
        bookmark_subparsers,
        "list",
        help_text="List bookmarks",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("bookmark_get"))

    child = add_standard_command(
        parser,
        bookmark_subparsers,
        "show",
        help_text="Show one bookmark",
        run=run_bound_operation,
    )
    bind_operation(child, OperationBinding("bookmark_get", params_builder=_bookmark_slot_params))
    child.add_argument("slot", help="Bookmark slot number")

    child = add_standard_command(
        parser,
        bookmark_subparsers,
        "add",
        help_text="Add a bookmark in the first free slot",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("bookmark_add", params_builder=_bookmark_add_params))
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("--comment", help="Optional bookmark comment")

    child = add_standard_command(
        parser,
        bookmark_subparsers,
        "set",
        help_text="Set a bookmark",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("bookmark_set", params_builder=_bookmark_set_params))
    child.add_argument("slot", help="Bookmark slot number")
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("--comment", help="Optional bookmark comment")

    child = add_standard_command(
        parser,
        bookmark_subparsers,
        "delete",
        help_text="Delete a bookmark",
        run=run_bound_operation,
        default_format="json",
    )
    bind_operation(child, OperationBinding("bookmark_delete", params_builder=_bookmark_slot_params))
    child.add_argument("slot", help="Bookmark slot number")
