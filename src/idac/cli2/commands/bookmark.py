from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_standard_command
from ..commands.common import parse_bookmark_slot, send_op
from ..result import CommandResult


def _bookmark_show_params(args: argparse.Namespace) -> dict[str, object]:
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


def _bookmark_delete_params(args: argparse.Namespace) -> dict[str, object]:
    return {"slot": parse_bookmark_slot(args.slot)}


def _list(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_get", params={})


def _show(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_get", params=_bookmark_show_params(args))


def _add(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_add", params=_bookmark_add_params(args))


def _set(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_set", params=_bookmark_set_params(args))


def _delete(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_delete", params=_bookmark_delete_params(args))


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "bookmark", help_text="Bookmark operations")
    bookmark_subparsers = parser.add_subparsers(dest="bookmark_command")

    add_standard_command(parser, bookmark_subparsers, "list", help_text="List bookmarks", run=_list)

    child = add_standard_command(parser, bookmark_subparsers, "show", help_text="Show one bookmark", run=_show)
    child.add_argument("slot", help="Bookmark slot number")

    child = add_standard_command(
        parser,
        bookmark_subparsers,
        "add",
        help_text="Add a bookmark in the first free slot",
        run=_add,
        mutating=True,
        default_format="json",
    )
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("--comment", help="Optional bookmark comment")

    child = add_standard_command(
        parser, bookmark_subparsers, "set", help_text="Set a bookmark", run=_set, mutating=True, default_format="json"
    )
    child.add_argument("slot", help="Bookmark slot number")
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("--comment", help="Optional bookmark comment")

    child = add_standard_command(
        parser,
        bookmark_subparsers,
        "delete",
        help_text="Delete a bookmark",
        run=_delete,
        mutating=True,
        default_format="json",
    )
    child.add_argument("slot", help="Bookmark slot number")
