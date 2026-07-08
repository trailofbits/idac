from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_standard_command
from ..commands.common import send_op
from ..errors import CliUserError
from ..result import CommandResult


def _comment_scope(args: argparse.Namespace) -> str:
    scope = str(getattr(args, "scope", "line"))
    if scope in {"anterior", "posterior"} and args.repeatable:
        raise CliUserError("--repeatable is only valid for line or function comments")
    return scope


def _comment_lookup_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {"address": str(args.identifier), "scope": _comment_scope(args)}
    if args.repeatable:
        params["repeatable"] = True
    return params


def _comment_change_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {
        "address": str(args.identifier),
        "text": str(args.text),
        "scope": _comment_scope(args),
    }
    if args.repeatable:
        params["repeatable"] = True
    return params


def _add_comment_target_options(parser: argparse.ArgumentParser) -> None:
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument(
        "--scope",
        choices=("line", "function", "anterior", "posterior"),
        default=argparse.SUPPRESS,
        help="Comment scope",
    )
    scope_group.add_argument(
        "--anterior",
        dest="scope",
        action="store_const",
        const="anterior",
        default=argparse.SUPPRESS,
        help="Use anterior extra comments",
    )
    scope_group.add_argument(
        "--posterior",
        dest="scope",
        action="store_const",
        const="posterior",
        default=argparse.SUPPRESS,
        help="Use posterior extra comments",
    )
    parser.add_argument(
        "--repeatable",
        action="store_true",
        help="Use the repeatable slot for line/function comments",
    )


def _show(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="comment_get", params=_comment_lookup_params(args))


def _set(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="comment_set", params=_comment_change_params(args))


def _delete(args: argparse.Namespace) -> CommandResult:
    return send_op(args, op="comment_delete", params=_comment_lookup_params(args))


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "comment", help_text="Comment operations")
    comment_subparsers = parser.add_subparsers(dest="comment_command")

    child = add_standard_command(parser, comment_subparsers, "show", help_text="Show a comment", run=_show)
    child.add_argument("identifier", help="Address or symbol")
    _add_comment_target_options(child)

    child = add_standard_command(
        parser, comment_subparsers, "set", help_text="Set a comment", run=_set, mutating=True, default_format="json"
    )
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("text", help="Comment text")
    _add_comment_target_options(child)

    child = add_standard_command(
        parser,
        comment_subparsers,
        "delete",
        help_text="Delete a comment",
        run=_delete,
        mutating=True,
        default_format="json",
    )
    child.add_argument("identifier", help="Address or symbol")
    _add_comment_target_options(child)
