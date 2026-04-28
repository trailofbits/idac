from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from .errors import CliUserError


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("--timeout must be greater than 0")
    return timeout


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return parsed


def _children(parser: argparse.ArgumentParser) -> list[tuple[argparse.ArgumentParser, bool]]:
    return list(getattr(parser, "_idac_children", []))


def _append_child(parent: argparse.ArgumentParser, child: argparse.ArgumentParser, *, hidden: bool) -> None:
    children = _children(parent)
    children.append((child, hidden))
    parent._idac_children = children


def render_full_help(parser: argparse.ArgumentParser, *, include_hidden: bool = False) -> str:
    sections: list[str] = []
    queue = [parser]
    while queue:
        current = queue.pop(0)
        sections.append(f"# {current.prog}\n\n{current.format_help().rstrip()}")
        for child, hidden in _children(current):
            if hidden and not include_hidden:
                continue
            queue.append(child)
    return "\n\n".join(sections) + "\n"


class FullHelpAction(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        sys.stdout.write(render_full_help(parser, include_hidden=False))
        parser.exit(0)


def add_full_help_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--full-help",
        action=FullHelpAction,
        help="Print full help for this command tree and exit",
    )


def bind_root_handler(
    root_parser: argparse.ArgumentParser,
    handler: Callable[..., object],
) -> Callable[[argparse.Namespace], object]:
    def bound(args: argparse.Namespace) -> object:
        return handler(args, root_parser=root_parser)

    return bound


def create_parser(
    *,
    prog: str,
    description: str,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.set_defaults(
        _selected_parser=parser,
        _uses_context=False,
        _hidden_command=False,
        _accepts_timeout=False,
        run=None,
        _preview_wrapper=False,
        _batch_mode=False,
    )
    add_full_help_option(parser)
    return parser


def add_command(
    parent_parser: argparse.ArgumentParser,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    *,
    help_text: str,
    description: str | None = None,
    hidden: bool = False,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        name,
        help=argparse.SUPPRESS if hidden else help_text,
        description=description or help_text,
    )
    parser.set_defaults(
        _selected_parser=parser,
        _uses_context=False,
        _hidden_command=hidden,
        _accepts_timeout=False,
        run=None,
        _preview_wrapper=False,
        _batch_mode=False,
    )
    add_full_help_option(parser)
    _append_child(parent_parser, parser, hidden=hidden)
    return parser


def finalize_help_tree(parser: argparse.ArgumentParser) -> None:
    visible_names = [child.prog.split()[-1] for child, hidden in _children(parser) if not hidden]
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        action._choices_actions = [item for item in action._choices_actions if item.help != argparse.SUPPRESS]
        if visible_names:
            action.metavar = "{" + ",".join(visible_names) + "}"
    for child, _hidden in _children(parser):
        finalize_help_tree(child)


def _add_context_arguments(parser: argparse.ArgumentParser, *, timeout_help: str) -> None:
    parser.add_argument(
        "-c",
        "--context",
        metavar="LOCATOR",
        default=argparse.SUPPRESS,
        help=(
            "Execution context: a live GUI selector such as pid:1234 or tiny, "
            "or an idalib database locator such as db:sample.i64"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=argparse.SUPPRESS,
        help=timeout_help,
    )


def add_root_context_options(parser: argparse.ArgumentParser) -> None:
    _add_context_arguments(
        parser,
        timeout_help="Backend request timeout in seconds; forwarded to the selected command",
    )


def set_context_defaults(
    parser: argparse.ArgumentParser,
    *,
    require_timeout: bool = False,
    timeout_requirement_label: str | None = None,
) -> None:
    parser.set_defaults(
        _uses_context=True,
        backend=None,
        target=None,
        database=None,
        _require_timeout=require_timeout,
        _timeout_requirement_label=timeout_requirement_label,
    )


def add_context_options(
    parser: argparse.ArgumentParser,
    *,
    require_timeout: bool = False,
    timeout_requirement_label: str | None = None,
) -> None:
    set_context_defaults(
        parser,
        require_timeout=require_timeout,
        timeout_requirement_label=timeout_requirement_label,
    )
    _add_context_arguments(
        parser,
        timeout_help=(
            "Backend request timeout in seconds; required for this command"
            if require_timeout
            else "Backend request timeout in seconds; omit to wait indefinitely"
        ),
    )


def add_output_options(
    parser: argparse.ArgumentParser,
    *,
    default_format: str = "text",
    require_out: bool = False,
) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json", "jsonl"),
        default=default_format,
        help="Output format to render on stdout or write to --out",
    )
    parser.add_argument(
        "-j",
        "--json",
        dest="format",
        action="store_const",
        const="json",
        help="Shortcut for --format json",
    )
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        required=require_out,
        help="Write command output to a file and keep stdout empty",
    )


def add_pattern_options(parser: argparse.ArgumentParser, *, label: str = "the pattern") -> None:
    parser.add_argument(
        "--regex",
        action="store_true",
        help=f"Interpret {label} as a regular expression",
    )
    parser.add_argument(
        "-i",
        "--ignore-case",
        action="store_true",
        help=f"Match {label} without case sensitivity",
    )


def add_segment_option(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    parser.add_argument(
        "--segment",
        required=required,
        help="Segment scope: full visible segment name, segment prefix before `:`, or exact suffix after `:`",
    )


def add_decl_input(
    parser: argparse.ArgumentParser,
    *,
    help_text: str,
    file_help: str = "Read declaration text from this file",
) -> None:
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--decl", help=help_text)
    mode.add_argument("--decl-file", dest="decl_file", type=Path, help=file_help)


def add_retype_input(parser: argparse.ArgumentParser) -> None:
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--type",
        dest="type_text",
        help="Local type text shorthand, for example `unsigned int`; use --decl or --decl-file for complex declarators",
    )
    mode.add_argument(
        "--decl",
        help="Full local variable declaration text, for example `unsigned int value;`",
    )
    mode.add_argument(
        "--decl-file",
        dest="decl_file",
        type=Path,
        help="Read full local variable declaration text from this file",
    )


def read_decl_text(args: argparse.Namespace, *, attr: str = "decl", file_attr: str = "decl_file") -> str:
    decl = getattr(args, attr, None)
    if decl not in (None, ""):
        return str(decl)
    decl_file = getattr(args, file_attr, None)
    if decl_file is not None:
        return Path(decl_file).read_text(encoding="utf-8")
    raise CliUserError("missing declaration input")


def read_decl_text_if_present(
    args: argparse.Namespace,
    *,
    attr: str = "decl",
    file_attr: str = "decl_file",
) -> str | None:
    decl = getattr(args, attr, None)
    if decl not in (None, ""):
        return str(decl)
    decl_file = getattr(args, file_attr, None)
    if decl_file is not None:
        return Path(decl_file).read_text(encoding="utf-8")
    return None


def read_decl_or_type_text(
    args: argparse.Namespace,
    *,
    attr: str = "decl",
    file_attr: str = "decl_file",
    type_attr: str = "type_text",
    placeholder_name: str = "__idac_local",
) -> str:
    decl = read_decl_text_if_present(args, attr=attr, file_attr=file_attr)
    if decl is not None:
        return decl
    type_text = getattr(args, type_attr, None)
    if type_text not in (None, ""):
        normalized = str(type_text).strip().rstrip(";").rstrip()
        if normalized:
            return f"{normalized} {placeholder_name};"
    raise CliUserError("missing declaration or type input")


def add_install_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mode",
        choices=("copy", "symlink"),
        default="symlink",
        help="Installation mode",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing destination if it already exists",
    )
