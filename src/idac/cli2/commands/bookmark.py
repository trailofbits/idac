from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_context_options, add_output_options
from ..commands.common import parse_bookmark_slot, send_op
from ..invocation import Invocation
from ..result import CommandResult


def _show_params(args: argparse.Namespace) -> dict[str, object]:
    return {"slot": parse_bookmark_slot(args.slot)}


def _add_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {"address": str(args.identifier)}
    if args.comment is not None:
        params["comment"] = args.comment
    return params


def _set_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {"slot": parse_bookmark_slot(args.slot), "address": str(args.identifier)}
    if args.comment is not None:
        params["comment"] = args.comment
    return params


def _delete_params(args: argparse.Namespace) -> dict[str, object]:
    return {"slot": parse_bookmark_slot(args.slot)}


def _list(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="bookmark_get", params={}, render_op="bookmark_get")


def _show(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="bookmark_get", params=_show_params(invocation.args), render_op="bookmark_get")


def _add(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="bookmark_add", params=_add_params(invocation.args), render_op="bookmark_add")


def _set(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="bookmark_set", params=_set_params(invocation.args), render_op="bookmark_set")


def _delete(invocation: Invocation) -> CommandResult:
    return send_op(
        invocation,
        op="bookmark_delete",
        params=_delete_params(invocation.args),
        render_op="bookmark_delete",
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "bookmark", help_text="Bookmark operations")
    bookmark_subparsers = parser.add_subparsers(dest="bookmark_command")

    child = add_command(parser, bookmark_subparsers, "list", help_text="List bookmarks")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.set_defaults(
        run=_list, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, bookmark_subparsers, "show", help_text="Show one bookmark")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("slot", help="Bookmark slot number")
    child.set_defaults(
        run=_show, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, bookmark_subparsers, "add", help_text="Add a bookmark in the first free slot")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("--comment", help="Optional bookmark comment")
    child.set_defaults(
        run=_add, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    child = add_command(parser, bookmark_subparsers, "set", help_text="Set a bookmark")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("slot", help="Bookmark slot number")
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("--comment", help="Optional bookmark comment")
    child.set_defaults(
        run=_set, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    child = add_command(parser, bookmark_subparsers, "delete", help_text="Delete a bookmark")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("slot", help="Bookmark slot number")
    child.set_defaults(
        run=_delete, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )
