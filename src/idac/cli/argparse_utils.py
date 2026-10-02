from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Callable
from pathlib import Path

from .errors import CliUserError


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--timeout must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("--timeout must be a positive finite number")
    return timeout


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return parsed


def _children(parser: argparse.ArgumentParser) -> list[argparse.ArgumentParser]:
    return list(getattr(parser, "_idac_children", []))


def render_full_help(parser: argparse.ArgumentParser) -> str:
    sections: list[str] = []
    queue = [parser]
    while queue:
        current = queue.pop(0)
        sections.append(f"# {current.prog}\n\n{current.format_help().rstrip()}")
        queue.extend(_children(current))
    return "\n\n".join(sections) + "\n"


class FullHelpAction(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        sys.stdout.write(render_full_help(parser))
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
        _accepts_timeout=False,
        run=None,
        allow_batch=False,
        allow_preview=False,
        _input_path_attrs=(),
        _request_validator=None,
        _mutating_command=False,
        _preview_wrapper=False,
        _batch_mode=False,
        _nexus_session=None,
    )
    add_full_help_option(parser)
    return parser


def add_command(
    parent_parser: argparse.ArgumentParser,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    *,
    help_text: str,
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        name,
        help=help_text,
        description=help_text,
    )
    parser.set_defaults(
        _selected_parser=parser,
        _uses_context=False,
        _accepts_timeout=False,
        run=None,
        allow_batch=False,
        allow_preview=False,
        _input_path_attrs=(),
        _request_validator=None,
        _mutating_command=False,
        _preview_wrapper=False,
        _batch_mode=False,
    )
    add_full_help_option(parser)
    children = _children(parent_parser)
    children.append(parser)
    parent_parser._idac_children = children  # ty: ignore[unresolved-attribute]  # dynamic attr on stdlib parser
    return parser


def add_standard_command(
    parent_parser: argparse.ArgumentParser,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    *,
    help_text: str,
    run: Callable[[argparse.Namespace], object],
    default_format: str = "text",
    require_timeout: bool = False,
    timeout_requirement_label: str | None = None,
) -> argparse.ArgumentParser:
    parser = add_command(parent_parser, subparsers, name, help_text=help_text)
    add_context_options(parser, require_timeout=require_timeout, timeout_requirement_label=timeout_requirement_label)
    add_output_options(parser, default_format=default_format)
    parser.set_defaults(
        run=run,
        allow_batch=True,
        allow_preview=True,
    )
    return parser


def finalize_help_tree(parser: argparse.ArgumentParser) -> None:
    child_names = [child.prog.split()[-1] for child in _children(parser)]
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        if child_names:
            action.metavar = "{" + ",".join(child_names) + "}"
    for child in _children(parser):
        finalize_help_tree(child)


def _add_context_arguments(parser: argparse.ArgumentParser, *, timeout_help: str) -> None:
    context_group = parser.add_mutually_exclusive_group()
    context_group.add_argument(
        "-c",
        "--context",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help=(
            "Open or attach to an .i64 database or input binary through ida-nexus; "
            "legacy db:, pid:, module, and .idb locators are not supported"
        ),
    )
    context_group.add_argument(
        "--instance",
        metavar="RECORD_ID",
        default=argparse.SUPPRESS,
        help="Attach to one exact READY ida-nexus discovery record",
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
        timeout_help="Nexus startup, analysis, and operation timeout in seconds; forwarded to the selected command",
    )


def add_context_options(
    parser: argparse.ArgumentParser,
    *,
    require_timeout: bool = False,
    timeout_requirement_label: str | None = None,
) -> None:
    parser.set_defaults(
        _uses_context=True,
        _require_timeout=require_timeout,
        _timeout_requirement_label=timeout_requirement_label,
    )
    _add_context_arguments(
        parser,
        timeout_help=(
            "Nexus operation timeout in seconds; required for this command"
            if require_timeout
            else "Nexus startup, analysis, and operation timeout in seconds; omit to use Nexus defaults"
        ),
    )


def add_output_options(
    parser: argparse.ArgumentParser,
    *,
    default_format: str = "text",
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
        help="Write command output to a file and keep stdout empty",
    )


def add_pattern_options(parser: argparse.ArgumentParser, *, label: str) -> None:
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
    parser.set_defaults(_input_path_attrs=("decl_file",))


def read_decl_text(args: argparse.Namespace) -> str:
    decl = read_decl_text_if_present(args)
    if decl is None:
        raise CliUserError("missing declaration input")
    return decl


def read_decl_text_if_present(args: argparse.Namespace) -> str | None:
    decl = getattr(args, "decl", None)
    if decl not in (None, ""):
        return str(decl)
    decl_file = getattr(args, "decl_file", None)
    if decl_file is not None:
        return Path(decl_file).read_text(encoding="utf-8")
    return None


def read_decl_or_type_text(args: argparse.Namespace) -> str:
    decl = read_decl_text_if_present(args)
    if decl is not None:
        return decl
    type_text = getattr(args, "type_text", None)
    if type_text not in (None, ""):
        normalized = str(type_text).strip().rstrip(";").rstrip()
        if normalized:
            return f"{normalized} __idac_local;"
    raise CliUserError("missing declaration or type input")
