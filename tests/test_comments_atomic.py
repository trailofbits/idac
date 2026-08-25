from __future__ import annotations

import pytest

from idac import remote_ops

IdaOperationError = remote_ops.IdaOperationError
IdaRuntime = remote_ops.IdaRuntime


def _run_op(name: str, runtime: IdaRuntime, params: dict[str, object]):
    spec = remote_ops._OPERATIONS[name]
    assert spec.parse is not None
    return remote_ops.payload_from_model(spec.run(remote_ops.OperationContext(runtime=runtime), spec.parse(params)))


class _FakeIdaLines:
    E_PREV = 1
    E_NEXT = 2

    def __init__(
        self,
        *,
        initial: dict[tuple[int, int], list[str]] | None = None,
        fail_on_update_index: int | None = None,
    ) -> None:
        self._comments = {} if initial is None else {key: list(value) for key, value in initial.items()}
        self._fail_on_update_index = fail_on_update_index

    def get_extra_cmt(self, ea: int, index: int):
        for (comment_ea, anchor), lines in self._comments.items():
            if comment_ea != ea:
                continue
            offset = index - anchor
            if 0 <= offset < len(lines):
                return lines[offset]
        return None

    def delete_extra_cmts(self, ea: int, anchor: int) -> None:
        self._comments.pop((ea, anchor), None)

    def update_extra_cmt(self, ea: int, index: int, line: str) -> bool:
        if self._fail_on_update_index == index:
            self._fail_on_update_index = None
            return False
        for (comment_ea, anchor), lines in self._comments.items():
            if comment_ea == ea and index == anchor + len(lines):
                lines.append(line)
                return True
        self._comments[(ea, index)] = [line]
        return True


class _FakeRuntime(IdaRuntime):
    def __init__(self, ida_lines: _FakeIdaLines) -> None:
        super().__init__()
        self._mods = {"ida_bytes": object(), "ida_lines": ida_lines}

    def mod(self, name: str):
        return self._mods[name]

    @staticmethod
    def resolve_address(identifier: str) -> int:
        return int(identifier, 0)


def test_write_extra_comment_restores_previous_text_on_failure() -> None:
    ida_lines = _FakeIdaLines(initial={(0x1000, 1): ["old one", "old two"]}, fail_on_update_index=2)
    runtime = _FakeRuntime(ida_lines)

    with pytest.raises(IdaOperationError, match="failed to set anterior comment"):
        _run_op(
            "comment_set",
            runtime,
            {"address": "0x1000", "scope": "anterior", "text": "new one\nnew two"},
        )

    assert _run_op("comment_get", runtime, {"address": "0x1000", "scope": "anterior"})["comment"] == (
        "old one\nold two"
    )


def test_write_extra_comment_preserves_terminal_blank_lines() -> None:
    ida_lines = _FakeIdaLines(initial={(0x1000, 1): ["old one", "old two"]})
    runtime = _FakeRuntime(ida_lines)

    result = _run_op(
        "comment_set",
        runtime,
        {"address": "0x1000", "scope": "anterior", "text": "new one\nnew two\n"},
    )

    assert result["comment"] == "new one\nnew two\n"
