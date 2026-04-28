from __future__ import annotations

import argparse
from dataclasses import dataclass

from ..argparse_utils import add_command, add_context_options, add_output_options
from ..commands.common import parse_bookmark_slot, send_op
from ..result import CommandResult


@dataclass(frozen=True)
class BookmarkShowRequest:
    slot: int

    def to_params(self) -> dict[str, object]:
        return {"slot": self.slot}


@dataclass(frozen=True)
class BookmarkAddRequest:
    address: str
    comment: str | None

    def to_params(self) -> dict[str, object]:
        params: dict[str, object] = {"address": self.address}
        if self.comment is not None:
            params["comment"] = self.comment
        return params


@dataclass(frozen=True)
class BookmarkSetRequest:
    slot: int
    address: str
    comment: str | None

    def to_params(self) -> dict[str, object]:
        params: dict[str, object] = {"slot": self.slot, "address": self.address}
        if self.comment is not None:
            params["comment"] = self.comment
        return params


@dataclass(frozen=True)
class BookmarkDeleteRequest:
    slot: int

    def to_params(self) -> dict[str, object]:
        return {"slot": self.slot}


def _bookmark_show_request(args: argparse.Namespace) -> BookmarkShowRequest:
    return BookmarkShowRequest(slot=parse_bookmark_slot(args.slot))


def _bookmark_add_request(args: argparse.Namespace) -> BookmarkAddRequest:
    return BookmarkAddRequest(address=str(args.identifier), comment=args.comment)


def _bookmark_set_request(args: argparse.Namespace) -> BookmarkSetRequest:
    return BookmarkSetRequest(slot=parse_bookmark_slot(args.slot), address=str(args.identifier), comment=args.comment)


def _bookmark_delete_request(args: argparse.Namespace) -> BookmarkDeleteRequest:
    return BookmarkDeleteRequest(slot=parse_bookmark_slot(args.slot))


def _list(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_get", params={}, render_op="bookmark_get")


def _show(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="bookmark_get",
        params=_bookmark_show_request(args).to_params(),
        render_op="bookmark_get",
    )


def _add(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_add", params=_bookmark_add_request(args).to_params(), render_op="bookmark_add")


def _set(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="bookmark_set", params=_bookmark_set_request(args).to_params(), render_op="bookmark_set")


def _delete(args: argparse.Namespace) -> CommandResult:
    return send_op(
        args,
        op="bookmark_delete",
        params=_bookmark_delete_request(args).to_params(),
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
