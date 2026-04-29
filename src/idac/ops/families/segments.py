from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..base import Op
from ..helpers.matching import pattern_from_params, text_matches
from ..runtime import IdaOperationError, IdaRuntime


@dataclass(frozen=True)
class SegmentListRequest:
    pattern: str
    glob: bool
    regex: bool
    ignore_case: bool


def _parse_segment_list(params: Mapping[str, Any]) -> SegmentListRequest:
    pattern, glob, regex, ignore_case = pattern_from_params(params)
    if regex and pattern:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise IdaOperationError(f"invalid segment regex: {exc}") from exc
    return SegmentListRequest(pattern=pattern, glob=glob, regex=regex, ignore_case=ignore_case)


def _segment_list(runtime: IdaRuntime, request: SegmentListRequest) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for segment in runtime.iter_segments():
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


def _run_segment_list(runtime: IdaRuntime, params: Mapping[str, Any]) -> list[dict[str, object]]:
    return _segment_list(runtime, _parse_segment_list(params))


SEGMENT_OPS: dict[str, Op] = {
    "segment_list": Op(run=_run_segment_list),
}


__all__ = [
    "SEGMENT_OPS",
    "SegmentListRequest",
]
