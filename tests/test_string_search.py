from __future__ import annotations

import pytest

from idac.ops.families import search
from idac.ops.families.search import SEARCH_OPS
from idac.ops.runtime import IdaOperationError, IdaRuntime, SegmentRange


def _strings_run(runtime, params):
    return SEARCH_OPS["strings"].run(runtime, params)


class _FakeIdaBytes:
    HEAD = 0x1
    STRLIT = 0x2
    ALOPT_IGNHEADS = 0x1

    def __init__(
        self,
        items: dict[int, tuple[int, int, bytes]],
        *,
        scan_lengths: dict[int, int] | None = None,
    ) -> None:
        self._items = items
        self._heads = sorted(items)
        self._scan_lengths = {} if scan_lengths is None else scan_lengths

    def get_flags(self, ea: int) -> int:
        item = self._items.get(ea)
        if item is None:
            return 0
        _strtype, _length, _text = item
        return self.HEAD | self.STRLIT

    @staticmethod
    def is_head(flags: int) -> bool:
        return bool(flags & _FakeIdaBytes.HEAD)

    @staticmethod
    def is_strlit(flags: int) -> bool:
        return bool(flags & _FakeIdaBytes.STRLIT)

    def next_head(self, ea: int, end: int) -> int:
        for head in self._heads:
            if head > ea and head < end:
                return head
        return -1

    def get_item_end(self, ea: int) -> int:
        _strtype, length, _text = self._items[ea]
        return ea + length

    def get_strlit_contents(self, ea: int, length: int, strtype: int) -> bytes:
        expected_strtype, expected_length, text = self._items[ea]
        assert strtype == expected_strtype
        assert length == expected_length
        return text

    def get_max_strlit_length(self, ea: int, strtype: int, options: int = 0) -> int:
        _ = (strtype, options)
        return self._scan_lengths.get(ea, 0)


class _FakeStrwinsetup:
    def __init__(self) -> None:
        self.strtypes = [0x55]
        self.minlen = 5
        self.display_only_existing_strings = False
        self.only_7bit = True
        self.ignore_heads = True


class _FakeStringInfo:
    def __init__(self) -> None:
        self.ea = 0
        self.length = 0
        self.type = 0


class _FakeIdaStrlist:
    def __init__(self, items: dict[int, tuple[int, int, bytes]]) -> None:
        self._items = items
        self.options = _FakeStrwinsetup()
        self.build_calls = 0

    def get_strlist_options(self) -> _FakeStrwinsetup:
        return self.options

    @staticmethod
    def string_info_t() -> _FakeStringInfo:
        return _FakeStringInfo()

    def build_strlist(self) -> None:
        self.build_calls += 1

    def get_strlist_qty(self) -> int:
        return len(self._items)

    def get_strlist_item(self, info: _FakeStringInfo, index: int) -> bool:
        try:
            ea = sorted(self._items)[index]
        except IndexError:
            return False
        strtype, length, _text = self._items[ea]
        info.ea = ea
        info.length = length
        info.type = strtype
        return True


class _FakeIdaIda:
    @staticmethod
    def inf_get_min_ea() -> int:
        return 0x1000

    @staticmethod
    def inf_get_max_ea() -> int:
        return 0x2000


class _FakeIdaApi:
    BADADDR = -1

    def __init__(self, input_path: str = "/tmp/tiny") -> None:
        self._input_path = input_path

    def get_input_file_path(self) -> str:
        return self._input_path


class _FakeRuntime(IdaRuntime):
    def __init__(
        self,
        *,
        items: dict[int, tuple[int, int, bytes]] | None = None,
        scan_lengths: dict[int, int] | None = None,
        input_path: str = "/tmp/tiny",
    ) -> None:
        super().__init__()
        self._items = {} if items is None else items
        self._segment_ranges = (SegmentRange(name="__TEXT:__cstring", start_ea=0x1000, end_ea=0x2000),)
        self._ida_strlist = _FakeIdaStrlist(self._items)
        self._mods = {
            "ida_bytes": _FakeIdaBytes(self._items, scan_lengths=scan_lengths),
            "ida_ida": _FakeIdaIda(),
            "idaapi": _FakeIdaApi(input_path),
            "ida_strlist": self._ida_strlist,
            "ida_nalt": type(
                "FakeIdaNalt",
                (),
                {
                    "STRTYPE_TERMCHR": 7,
                    "STRTYPE_C": 0,
                },
            )(),
        }

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
        assert selector == "__TEXT"
        if require_bounds and (start is None or end is None):
            raise IdaOperationError(missing_message)
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


def test_op_strings_lists_defined_strings_without_global_string_list() -> None:
    runtime = _FakeRuntime(
        items={
            0x1010: (7, 5, b"alpha"),
            0x1020: (0, 10, b"Tiny token"),
        }
    )

    rows = _strings_run(runtime, {"query": "tiny", "segment": "__TEXT"})

    assert rows == [{"address": "0x1020", "text": "Tiny token"}]
    assert runtime._ida_strlist.build_calls == 2
    assert runtime._ida_strlist.options.strtypes == [0x55]
    assert runtime._ida_strlist.options.minlen == 5
    assert runtime._ida_strlist.options.display_only_existing_strings is False
    assert runtime._ida_strlist.options.only_7bit is True
    assert runtime._ida_strlist.options.ignore_heads is True


def test_op_strings_includes_termchr_string_literals() -> None:
    runtime = _FakeRuntime(
        items={
            0x1010: (7, 9, b"term text"),
        }
    )

    rows = _strings_run(runtime, {"query": "term", "segment": "__TEXT"})

    assert rows == [{"address": "0x1010", "text": "term text"}]


def test_op_strings_returns_empty_list_when_no_matches_are_found() -> None:
    runtime = _FakeRuntime(
        items={
            0x1010: (0, 5, b"alpha"),
        }
    )

    rows = _strings_run(runtime, {"query": "missing", "segment": "__TEXT"})

    assert rows == []


def test_op_strings_scan_walks_addresses_and_finds_strings() -> None:
    runtime = _FakeRuntime(
        items={
            0x1008: (0, 5, b"alpha"),
            0x1020: (0, 10, b"Tiny token"),
        },
        scan_lengths={
            0x1008: 5,
            0x1020: 10,
        },
    )

    rows = _strings_run(
        runtime,
        {
            "scan": True,
            "segment": "__TEXT",
            "start": "0x1008",
            "end": "0x102a",
            "query": "tiny",
        },
    )

    assert rows == [{"address": "0x1020", "text": "Tiny token"}]


def test_op_strings_scan_rejects_invalid_range() -> None:
    runtime = _FakeRuntime()

    with pytest.raises(IdaOperationError, match="range end must be greater than the start"):
        _strings_run(runtime, {"scan": True, "segment": "__TEXT", "start": "0x1020", "end": "0x1020"})


def test_op_strings_rejects_defined_string_listing_on_dsc() -> None:
    runtime = _FakeRuntime(
        input_path="/System/Library/dyld/dyld_shared_cache_arm64e",
        items={0x1010: (0, 5, b"alpha")},
    )

    with pytest.raises(IdaOperationError, match="defined string listing is disabled for dyld shared caches"):
        _strings_run(runtime, {"query": "alpha", "segment": "__TEXT"})

    assert runtime._ida_strlist.build_calls == 0


def test_op_strings_does_not_treat_dsc_substring_as_shared_cache() -> None:
    runtime = _FakeRuntime(
        input_path="/tmp/my_dsc_tool",
        items={0x1010: (0, 5, b"alpha")},
    )

    rows = _strings_run(runtime, {"query": "alpha", "segment": "__TEXT"})

    assert rows == [{"address": "0x1010", "text": "alpha"}]


def test_op_strings_dsc_scan_requires_bounded_range() -> None:
    runtime = _FakeRuntime(input_path="/System/Library/dyld/dyld_shared_cache_arm64e")

    with pytest.raises(IdaOperationError, match="requires both start and end addresses"):
        _strings_run(runtime, {"scan": True, "segment": "__TEXT"})


def test_op_strings_dsc_scan_rejects_large_ranges() -> None:
    runtime = _FakeRuntime(input_path="/System/Library/dyld/dyld_shared_cache_arm64e")
    runtime._segment_ranges = (SegmentRange(name="__TEXT:__cstring", start_ea=0x1000, end_ea=0x1201000),)

    with pytest.raises(IdaOperationError, match="limited to 16 MiB"):
        _strings_run(
            runtime,
            {
                "scan": True,
                "segment": "__TEXT",
                "start": "0x1000",
                "end": "0x1201000",
            },
        )


def test_string_text_returns_empty_string_when_ida_returns_none() -> None:
    runtime = _FakeRuntime(items={0x1010: (0, 5, b"alpha")})
    runtime._mods["ida_bytes"].get_strlit_contents = lambda ea, length, strtype: None

    assert search._string_text(runtime, 0x1010, 5, 0) == ""


def test_op_strings_filters_to_selected_segment_ranges() -> None:
    runtime = _FakeRuntime(
        items={
            0x1010: (0, 5, b"alpha"),
            0x2010: (0, 10, b"Tiny token"),
        }
    )
    runtime._segment_ranges = (SegmentRange(name="__TEXT:__cstring", start_ea=0x2000, end_ea=0x2100),)

    rows = _strings_run(runtime, {"query": "tiny", "segment": "__TEXT"})

    assert rows == [{"address": "0x2010", "text": "Tiny token"}]
