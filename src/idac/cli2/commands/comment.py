from __future__ import annotations

import argparse

from ..argparse_utils import add_command, add_context_options, add_output_options
from ..commands.common import send_op
from ..errors import CliUserError
from ..invocation import Invocation
from ..result import CommandResult


def _comment_scope(args: argparse.Namespace) -> str:
    scope = str(getattr(args, "scope", "line"))
    if scope in {"anterior", "posterior"} and args.repeatable:
        raise CliUserError("--repeatable is only valid for line or function comments")
    return scope


def _lookup_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {"address": str(args.identifier), "scope": _comment_scope(args)}
    if args.repeatable:
        params["repeatable"] = True
    return params


def _change_params(args: argparse.Namespace) -> dict[str, object]:
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


def _show(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="comment_get", params=_lookup_params(invocation.args), render_op="comment_get")


def _set(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="comment_set", params=_change_params(invocation.args), render_op="comment_set")


def _delete(invocation: Invocation) -> CommandResult:
    return send_op(invocation, op="comment_delete", params=_lookup_params(invocation.args), render_op="comment_delete")


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "comment", help_text="Comment operations")
    comment_subparsers = parser.add_subparsers(dest="comment_command")

    child = add_command(parser, comment_subparsers, "show", help_text="Show a comment")
    add_context_options(child)
    add_output_options(child, default_format="text")
    child.add_argument("identifier", help="Address or symbol")
    _add_comment_target_options(child)
    child.set_defaults(
        run=_show, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, comment_subparsers, "set", help_text="Set a comment")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Address or symbol")
    child.add_argument("text", help="Comment text")
    _add_comment_target_options(child)
    child.set_defaults(
        run=_set, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )

    child = add_command(parser, comment_subparsers, "delete", help_text="Delete a comment")
    add_context_options(child)
    add_output_options(child, default_format="json")
    child.add_argument("identifier", help="Address or symbol")
    _add_comment_target_options(child)
    child.set_defaults(
        run=_delete, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=True
    )
