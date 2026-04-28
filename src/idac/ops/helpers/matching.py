from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import Any


def pattern_from_params(params: dict[str, Any]) -> tuple[str, bool, bool, bool]:
    pattern = params.get("pattern")
    if pattern not in (None, ""):
        return str(pattern), bool(params.get("glob")), bool(params.get("regex")), bool(params.get("ignore_case"))
    query = params.get("query")
    if query in (None, ""):
        return "", False, False, False
    return str(query), False, False, True


def text_matches(
    text: str,
    *,
    pattern: str,
    glob: bool = False,
    regex: bool = False,
    ignore_case: bool = False,
) -> bool:
    if not pattern:
        return True
    if glob and regex:
        raise ValueError("glob and regex are mutually exclusive")
    haystack = text
    needle = pattern
    if regex:
        flags = re.IGNORECASE if ignore_case else 0
        try:
            return re.search(needle, haystack, flags=flags) is not None
        except re.error as exc:
            raise ValueError(f"invalid regex pattern: {pattern}") from exc
    if ignore_case:
        haystack = haystack.lower()
        needle = needle.lower()
    if glob:
        return fnmatchcase(haystack, needle)
    return needle in haystack
