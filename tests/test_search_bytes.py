from __future__ import annotations

from types import SimpleNamespace

import pytest

from idac import remote_ops
from tests.remote_ops_harness import dispatch_with_runtime

IdaOperationError = remote_ops.IdaOperationError
IdaRuntime = remote_ops.IdaRuntime
SegmentRange = remote_ops.SegmentRange


def _run_search(runtime: IdaRuntime, params: dict[str, object]):
    return dispatch_with_runtime(runtime, "search_bytes", params)


class _CompiledPattern:
    def __init__(self, pattern: str) -> None:
        self.pattern = pattern

    def __len__(self) -> int:
        return 1


class _CompiledBinpatVecFactory:
    def __init__(self, *, error: str | None = None) -> None:
        self.error = error

    def parse(self, ea: int, text: str, radix: int, strlit_encoding: int) -> _CompiledPattern:
        del ea, radix, strlit_encoding
        if self.error is not None:
            raise RuntimeError(self.error)
        return _CompiledPattern(text)


class _FakeIdaBytes:
    BIN_SEARCH_FORWARD = 0x1
    BIN_SEARCH_NOBREAK = 0x2
    BIN_SEARCH_NOSHOW = 0x4

    def __init__(self, *, matches: list[int] | None = None, parse_error: str | None = None) -> None:
        self.compiled_binpat_vec_t = _CompiledBinpatVecFactory(error=parse_error)
        self._matches = [] if matches is None else list(matches)

    def bin_search(self, start_ea: int, end_ea: int, compiled, flags: int) -> tuple[int, int]:
        del compiled, flags
        for index, match in enumerate(self._matches):
            if start_ea <= match < end_ea:
                self._matches.pop(index)
                return match, 0
        return _FakeIdaApi.BADADDR, 0


class _FakeIdaApi:
    BADADDR = -1


class _FakeRuntime(IdaRuntime):
    def __init__(self, ida_bytes: _FakeIdaBytes) -> None:
        super().__init__()
        self._segment_ranges = (SegmentRange(name="__TEXT:__text", start_ea=0x1000, end_ea=0x2000),)
        self._mods = {
            "ida_bytes": ida_bytes,
            "idaapi": _FakeIdaApi(),
            "ida_ida": SimpleNamespace(
                inf_get_min_ea=lambda: 0x1000,
                inf_get_max_ea=lambda: 0x2000,
            ),
        }
        self.ida_funcs = SimpleNamespace(get_func=lambda ea: None)

    def mod(self, name: str):
        return self._mods[name]

    @staticmethod
    def resolve_address(identifier: str) -> int:
        return int(identifier, 0)

    def resolve_segment_ranges(
        self,
        selector: str,
        *,
        start: str | None = None,
        end: str | None = None,
        require_bounds: bool = False,
        missing_message: str = "range requires both start and end addresses",
    ) -> tuple[SegmentRange, ...]:
        del require_bounds, missing_message
        assert selector == "__TEXT"
        range_start = self._segment_ranges[0].start_ea if start is None else int(start, 0)
        range_end = self._segment_ranges[-1].end_ea if end is None else int(end, 0)
        if range_end <= range_start:
            raise IdaOperationError("range end must be greater than the start")
        return tuple(
            SegmentRange(
                name=item.name,
                start_ea=max(item.start_ea, range_start),
                end_ea=min(item.end_ea, range_end),
            )
            for item in self._segment_ranges
            if min(item.end_ea, range_end) > max(item.start_ea, range_start)
        )


def test_search_bytes_returns_matches_in_address_order() -> None:
    ida_bytes = _FakeIdaBytes(matches=[0x1010, 0x1020])
    runtime = _FakeRuntime(ida_bytes)

    result = _run_search(
        runtime,
        {"pattern": "aa bb", "segment": "__TEXT", "start": "0x1000", "end": "0x1030", "limit": 2},
    )

    assert result["results"] == [{"address": "0x1010"}, {"address": "0x1020"}]


def test_search_bytes_reports_invalid_pattern_as_user_error() -> None:
    ida_bytes = _FakeIdaBytes(parse_error="Could not parse pattern: bad digit")
    runtime = _FakeRuntime(ida_bytes)

    with pytest.raises(IdaOperationError, match="invalid byte pattern: bad digit"):
        _run_search(
            runtime,
            {"pattern": "zz", "segment": "__TEXT", "start": "0x1000", "end": "0x1030", "limit": 5},
        )


def test_search_bytes_returns_empty_results_when_no_matches_found() -> None:
    ida_bytes = _FakeIdaBytes(matches=[])
    runtime = _FakeRuntime(ida_bytes)

    result = _run_search(
        runtime,
        {"pattern": "aa bb", "segment": "__TEXT", "start": "0x1000", "end": "0x1030", "limit": 5},
    )

    assert result["results"] == []
    assert result["truncated"] is False


def test_search_bytes_marks_results_truncated_when_limit_is_hit() -> None:
    ida_bytes = _FakeIdaBytes(matches=[0x1010, 0x1020])
    runtime = _FakeRuntime(ida_bytes)

    result = _run_search(
        runtime,
        {"pattern": "aa bb", "segment": "__TEXT", "start": "0x1000", "end": "0x1030", "limit": 1},
    )

    assert result["results"] == [{"address": "0x1010"}]
    assert result["truncated"] is True


def test_search_bytes_walks_each_matching_segment_range() -> None:
    ida_bytes = _FakeIdaBytes(matches=[0x1010, 0x2018])
    runtime = _FakeRuntime(ida_bytes)
    runtime._segment_ranges = (
        SegmentRange(name="__TEXT:__text", start_ea=0x1000, end_ea=0x1030),
        SegmentRange(name="__TEXT:__stubs", start_ea=0x2000, end_ea=0x2030),
    )

    result = _run_search(runtime, {"pattern": "aa bb", "segment": "__TEXT", "limit": 10})

    assert result["results"] == [
        {"address": "0x1010"},
        {"address": "0x2018"},
    ]
    assert result["ranges"] == [
        {"name": "__TEXT:__text", "start": "0x1000", "end": "0x1030"},
        {"name": "__TEXT:__stubs", "start": "0x2000", "end": "0x2030"},
    ]
