from __future__ import annotations

import argparse
from dataclasses import dataclass

from ..argparse_utils import (
    add_command,
    add_context_options,
    add_output_options,
    add_pattern_options,
    add_segment_option,
    positive_int,
)
from ..commands.common import send_op
from ..errors import CliUserError
from ..invocation import Invocation
from ..result import CommandResult


@dataclass(frozen=True)
class BytesRequest:
    pattern: str
    segment: str
    limit: int
    start: str | None = None
    end: str | None = None

    def to_params(self) -> dict[str, object]:
        params: dict[str, object] = {
            "pattern": self.pattern,
            "segment": self.segment,
            "limit": self.limit,
        }
        if self.start:
            params["start"] = self.start
        if self.end:
            params["end"] = self.end
        return params


@dataclass(frozen=True)
class StringsRequest:
    pattern: str | None
    regex: bool
    ignore_case: bool
    scan: bool
    segment: str
    start: str | None = None
    end: str | None = None

    def to_params(self) -> dict[str, object]:
        params: dict[str, object] = {
            "pattern": self.pattern,
            "regex": self.regex,
            "ignore_case": self.ignore_case,
            "segment": self.segment,
        }
        if self.start:
            params["start"] = self.start
        if self.end:
            params["end"] = self.end
        if self.scan:
            params["scan"] = True
        return params


def _bytes_request(args: argparse.Namespace) -> BytesRequest:
    return BytesRequest(
        pattern=args.pattern,
        segment=args.segment,
        limit=args.limit,
        start=args.start,
        end=args.end,
    )


def _bytes(invocation: Invocation) -> CommandResult:
    return send_op(
        invocation, op="search_bytes", params=_bytes_request(invocation.args).to_params(), render_op="search_bytes"
    )


def _strings_request(args: argparse.Namespace) -> StringsRequest:
    if not args.scan and (args.start is not None or args.end is not None):
        raise CliUserError("`--start` and `--end` are only valid with `search strings --scan`")
    return StringsRequest(
        pattern=args.pattern,
        regex=args.regex,
        ignore_case=args.ignore_case,
        scan=args.scan,
        segment=args.segment,
        start=args.start,
        end=args.end,
    )


def _strings(invocation: Invocation) -> CommandResult:
    return send_op(
        invocation, op="strings", params=_strings_request(invocation.args).to_params(), render_op="strings"
    )


def register(
    root_parser: argparse.ArgumentParser, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    parser = add_command(root_parser, subparsers, "search", help_text="Search operations")
    search_subparsers = parser.add_subparsers(dest="search_command")

    child = add_command(parser, search_subparsers, "bytes", help_text="Search for a byte pattern")
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = """examples:
  # Search defined bytes with IDA byte-pattern syntax, not regex/text matching
  idac search bytes '48 8B ?? ??' --segment __TEXT --timeout 30 -c db:sample.i64

  # Restrict the search to an address range inside the segment
  idac search bytes 'DE AD BE EF' --segment __TEXT --start 0x401000 --end 0x402000 --timeout 30
"""
    add_context_options(child, require_timeout=True, timeout_requirement_label="`idac search bytes`")
    add_output_options(child, default_format="text")
    child.add_argument(
        "pattern",
        metavar="BYTE_PATTERN",
        help="IDA byte pattern to search for, for example '48 8B ??' or 'DE AD BE EF'; this is not a regex",
    )
    add_segment_option(child, required=True)
    child.add_argument("--start", help="Start address for range operations")
    child.add_argument("--end", help="End address for range operations")
    child.add_argument("--limit", type=positive_int, default=100, help="Maximum number of results to return")
    child.set_defaults(
        run=_bytes, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )

    child = add_command(parser, search_subparsers, "strings", help_text="List defined strings")
    child.formatter_class = argparse.RawDescriptionHelpFormatter
    child.epilog = """examples:
  # Filter already-defined strings by text
  idac search strings error --segment __cstring --timeout 30 -c db:sample.i64

  # Regex-filter defined strings
  idac search strings 'error|warning' --regex --segment __cstring --timeout 30

  # Scan a bounded range for string-like data instead of listing defined strings
  idac search strings --scan --segment __TEXT --start 0x401000 --end 0x402000 --timeout 30
"""
    add_context_options(child, require_timeout=True, timeout_requirement_label="`idac search strings`")
    add_output_options(child, default_format="text")
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
    child.set_defaults(
        run=_strings, context_policy="standard", allow_batch=True, allow_preview=True, _mutating_command=False
    )
