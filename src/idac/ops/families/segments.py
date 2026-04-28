from __future__ import annotations

import re
from dataclasses import dataclass

from ..base import OperationContext, OperationSpec
from ..helpers.matching import pattern_from_params, text_matches
from ..runtime import IdaOperationError


@dataclass(frozen=True)
class SegmentListRequest:
    pattern: str
    glob: bool
    regex: bool
    ignore_case: bool


def _parse_segment_list(params: dict[str, object]) -> SegmentListRequest:
    pattern, glob, regex, ignore_case = pattern_from_params(params)
    if regex and pattern:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise IdaOperationError(f"invalid segment regex: {exc}") from exc
    return SegmentListRequest(pattern=pattern, glob=glob, regex=regex, ignore_case=ignore_case)


def _segment_list(
    context: OperationContext,
    request: SegmentListRequest,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for segment in context.runtime.iter_segments():
        if request.pattern and not text_matches(
            segment.name,
            pattern=request.pattern,
            glob=request.glob,
            regex=request.regex,
            ignore_case=request.ignore_case,
        ):
            continue
        rows.append(
            {
                "name": segment.name,
                "start": hex(segment.start_ea),
                "end": hex(segment.end_ea),
                "size": segment.end_ea - segment.start_ea,
            }
        )
    return rows


def segment_operations() -> tuple[OperationSpec[object, object], ...]:
    return (
        OperationSpec(
            name="segment_list",
            parse=_parse_segment_list,
            run=_segment_list,
        ),
    )


__all__ = [
    "SegmentListRequest",
    "segment_operations",
]
