from __future__ import annotations

import argparse

from ..argparse_utils import (
    add_command,
    add_pattern_options,
    add_segment_option,
    add_standard_command,
    positive_int,
)
from ..commands.common import OperationBinding, bind_operation, run_bound_operation
from ..errors import CliUserError


def _bytes_params(args: argparse.Namespace) -> dict[str, object]:
    params: dict[str, object] = {
        "pattern": args.pattern,
        "segment": args.segment,
        "limit": args.limit,
    }
    if args.start:
        params["start"] = args.start
    if args.end:
        params["end"] = args.end
    return params


def _strings_params(args: argparse.Namespace) -> dict[str, object]:
    if not args.scan and (args.start is not None or args.end is not None):
        raise CliUserError("`--start` and `--end` are only valid with `search strings --scan`")
    params: dict[str, object] = {
        "pattern": args.pattern,
        "regex": args.regex,
        "ignore_case": args.ignore_case,
        "segment": args.segment,
    }
    if args.start:
        params["start"] = args.start
    if args.end:
        params["end"] = args.end
    if args.scan:
        params["scan"] = True
    return params


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "search", help_text="Search operations")
    search_subparsers = parser.add_subparsers(dest="search_command")

    child = add_standard_command(
        parser,
        search_subparsers,
        "bytes",
        help_text="Search for a byte pattern",
        run=run_bound_operation,
        require_timeout=True,
        timeout_requirement_label="`idac search bytes`",
    )
    bind_operation(child, OperationBinding("search_bytes", params_builder=_bytes_params))
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = """examples:
  # Search defined bytes with IDA byte-pattern syntax, not regex/text matching
  idac search bytes '48 8B ?? ??' --segment __TEXT --timeout 30 -c sample.i64

  # Restrict the search to an address range inside the segment
  idac search bytes 'DE AD BE EF' --segment __TEXT --start 0x401000 --end 0x402000 --timeout 30
"""
    child.add_argument(
        "pattern",
        metavar="BYTE_PATTERN",
        help="IDA byte pattern to search for, for example '48 8B ??' or 'DE AD BE EF'; this is not a regex",
    )
    add_segment_option(child, required=True)
    child.add_argument("--start", help="Start address for range operations")
    child.add_argument("--end", help="End address for range operations")
    child.add_argument("--limit", type=positive_int, default=100, help="Maximum number of results to return")

    child = add_standard_command(
        parser,
        search_subparsers,
        "strings",
        help_text="List defined strings",
        run=run_bound_operation,
        require_timeout=True,
        timeout_requirement_label="`idac search strings`",
    )
    bind_operation(child, OperationBinding("strings", params_builder=_strings_params))
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = """examples:
  # Filter already-defined strings by text
  idac search strings error --segment __cstring --timeout 30 -c sample.i64

  # Regex-filter defined strings
  idac search strings 'error|warning' --regex --segment __cstring --timeout 30

  # Scan a bounded range for string-like data instead of listing defined strings
  idac search strings --scan --segment __TEXT --start 0x401000 --end 0x402000 --timeout 30
"""
    add_segment_option(child, required=True)
    child.add_argument(
        "pattern",
        nargs="?",
        metavar="TEXT_FILTER",
        help=(
            "Optional string-text substring filter; with --regex, treat as a regex. "
            "Omit it with --scan to scan a bounded range for string-like data."
        ),
    )
    child.add_argument(
        "--scan",
        action="store_true",
        help="Search a bounded address range for string-like data instead of listing defined strings",
    )
    child.add_argument("--start", help="Start address for range operations")
    child.add_argument("--end", help="End address for range operations")
    add_pattern_options(child, label="TEXT_FILTER")
