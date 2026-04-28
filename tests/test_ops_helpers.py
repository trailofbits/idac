from __future__ import annotations

from typing import get_args

import pytest

from idac.ops import OperationContext
from idac.ops.families import (
    bookmarks,
    classes,
    database,
    functions,
    locals,
    names,
    prototypes,
    search,
    segments,
    type_declare,
)
from idac.ops.families import named_types as types
from idac.ops.families.named_types import op_struct_field_set
from idac.ops.families.type_declare import _split_declarations
from idac.ops.helpers import matching
from idac.ops.manifest import OPERATION_SPEC_MAP, SUPPORTED_OPERATIONS, OperationName
from idac.ops.preview import PreviewSpec, run_preview
from idac.ops.runtime import (
    IdaOperationError,
    IdaRuntime,
    SegmentRange,
    XrefRecord,
    is_recoverable_ida_error,
    suppress_recoverable_ida_errors,
)


class _DummyRuntime:
    def mod(self, _name: str):
        return object()

    def get_struct_or_union(self, _name: str):
        raise AssertionError("negative offset validation should fail before type lookup")


def test_struct_field_set_rejects_negative_offsets() -> None:
    with pytest.raises(IdaOperationError, match="greater than or equal to 0"):
        op_struct_field_set(
            _DummyRuntime(),
            {
                "struct_name": "Player",
                "field_name": "hp",
                "decl": "int",
                "offset": "-1",
            },
        )


def test_parse_member_type_uses_parse_decl_with_field_name() -> None:
    calls: list[tuple[str, int]] = []
    tif = object()

    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert out_tif is tif
            assert til is None
            calls.append((decl, flags))
            return True

    class FakeRuntime(IdaRuntime):
        def mod(self, name: str) -> FakeIdaTypeInf:
            assert name == "ida_typeinf"
            return FakeIdaTypeInf()

    assert types._parse_member_type(FakeRuntime(), "unsigned int", "count") is tif
    assert calls == [("unsigned int count;", 0x4009)]


def test_parse_member_type_accepts_full_field_declaration() -> None:
    calls: list[tuple[str, int]] = []
    tif = object()

    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert out_tif is tif
            assert til is None
            calls.append((decl, flags))
            return decl == "unsigned int count;"

    class FakeRuntime(IdaRuntime):
        def mod(self, name: str) -> FakeIdaTypeInf:
            assert name == "ida_typeinf"
            return FakeIdaTypeInf()

    assert types._parse_member_type(FakeRuntime(), "unsigned int count;", "count") is tif
    assert calls == [("unsigned int count;", 0x4009)]


def test_parse_var_decl_uses_parse_decl_with_silent_var_mode() -> None:
    calls: list[tuple[str, int]] = []
    tif = object()

    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert out_tif is tif
            assert til is None
            calls.append((decl, flags))
            return True

    class FakeRuntime(IdaRuntime):
        def mod(self, name: str) -> FakeIdaTypeInf:
            assert name == "ida_typeinf"
            return FakeIdaTypeInf()

    assert (
        locals._parse_var_decl(
            FakeRuntime(),
            "unsigned int value",
            error_message="boom",
        )
        is tif
    )
    assert calls == [("unsigned int value;", 0x4009)]


def test_op_decompile_passes_no_cache_flag_when_requested() -> None:
    calls: list[tuple[int, int]] = []

    class FakeLine:
        def __init__(self, line: str) -> None:
            self.line = line

    class FakeCfunc:
        def get_pseudocode(self) -> list[FakeLine]:
            return [FakeLine("int main(void)")]

    class FakeHexrays:
        DECOMP_NO_CACHE = 0x2

        @staticmethod
        def decompile(ea: int, hf=None, flags: int = 0) -> FakeCfunc:
            assert hf is None
            calls.append((ea, flags))
            return FakeCfunc()

    class FakeRuntime(IdaRuntime):
        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

        def function_ea(self, identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

        @staticmethod
        def mod(name: str):
            assert name == "ida_lines"

            class FakeIdaLines:
                @staticmethod
                def tag_remove(text: str) -> str:
                    return text

            return FakeIdaLines()

    payload = functions.op_decompile(FakeRuntime(), {"identifier": "main", "no_cache": True})

    assert payload == {"text": "int main(void)"}
    assert calls == [(0x401000, 0x2)]


def test_disasm_uses_direct_ida_lines_api() -> None:
    calls: list[tuple[str, int]] = []

    class FakeIdaLines:
        @staticmethod
        def generate_disasm_line(ea: int, flags: int) -> str:
            calls.append(("generate", ea))
            assert flags == 0
            return f"<tag>insn_{ea:x}</tag>"

        @staticmethod
        def tag_remove(text: str) -> str:
            calls.append(("tag_remove", 0))
            return text.replace("<tag>", "").replace("</tag>", "")

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

        @staticmethod
        def mod(name: str) -> FakeIdaLines:
            assert name == "ida_lines"
            return FakeIdaLines()

        class idautils:
            @staticmethod
            def FuncItems(func_ea: int) -> list[int]:
                assert func_ea == 0x401000
                return [0x401000, 0x401004]

    rendered = functions._disasm(OperationContext(runtime=FakeRuntime()), functions.FunctionIdentifierRequest("main"))

    assert rendered.text == "0x401000: insn_401000\n0x401004: insn_401004"
    assert calls == [("generate", 0x401000), ("tag_remove", 0), ("generate", 0x401004), ("tag_remove", 0)]


def test_text_matches_supports_regex_alternation() -> None:
    assert matching.text_matches(
        "GlobalHEIFInfo",
        pattern="GlobalHEIFInfo|HEIFGroupItem|HEIFGroup|HEIFStereoAggressor|HEIFReadPlugin|HEIFWritePlugin",
        regex=True,
    )
    assert not matching.text_matches("UnrelatedName", pattern="GlobalHEIFInfo|HEIFGroupItem", regex=True)


def test_function_list_honors_limit() -> None:
    class FakeFunc:
        def __init__(self, ea: int) -> None:
            self.start_ea = ea
            self.end_ea = ea + 0x10

    class FakeIdaUtils:
        @staticmethod
        def Functions():
            return [0x1000, 0x2000, 0x3000]

    class FakeIdaFuncs:
        @staticmethod
        def get_func(ea: int) -> FakeFunc:
            return FakeFunc(ea)

    class FakeRuntime(IdaRuntime):
        idautils = FakeIdaUtils()
        ida_funcs = FakeIdaFuncs()

        @staticmethod
        def function_name(ea: int) -> str:
            return {0x1000: "alpha", 0x2000: "beta", 0x3000: "gamma"}[ea]

    rows = functions._function_list(
        OperationContext(runtime=FakeRuntime()),
        functions.FunctionListRequest(
            pattern="",
            glob=False,
            regex=False,
            ignore_case=False,
            segment=None,
            limit=2,
            demangle=False,
        ),
    )

    assert [row.name for row in rows] == ["alpha", "beta"]


def test_database_info_reports_start_ea_separately_from_first_entry() -> None:
    class FakeIdaEntry:
        @staticmethod
        def get_entry_ordinal(index: int) -> int:
            assert index == 0
            return 0

        @staticmethod
        def get_entry(ordinal: int) -> int:
            assert ordinal == 0
            return 0x402000

    class FakeIdaIda:
        @staticmethod
        def inf_get_start_ea() -> int:
            return 0x401000

        @staticmethod
        def inf_is_64bit() -> bool:
            return True

        @staticmethod
        def inf_is_32bit_exactly() -> bool:
            return False

        @staticmethod
        def inf_get_procname() -> str:
            return "metapc"

        @staticmethod
        def inf_get_min_ea() -> int:
            return 0x400000

        @staticmethod
        def inf_get_max_ea() -> int:
            return 0x500000

    class FakeIdaLoader:
        PATH_TYPE_IDB = 1

        @staticmethod
        def get_path(path_type: int) -> str:
            assert path_type == 1
            return "/tmp/sample.i64"

    class FakeIdaApi:
        BADADDR = -1

        @staticmethod
        def get_input_file_path() -> str:
            return "/tmp/sample"

        @staticmethod
        def get_root_filename() -> str:
            return "sample"

        @staticmethod
        def get_imagebase() -> int:
            return 0x400000

    class FakeRuntime(IdaRuntime):
        @staticmethod
        def mod(name: str):
            modules = {
                "ida_entry": FakeIdaEntry(),
                "ida_ida": FakeIdaIda(),
                "ida_loader": FakeIdaLoader(),
                "idaapi": FakeIdaApi(),
            }
            return modules[name]

    result = database._database_info(OperationContext(runtime=FakeRuntime()), database.DatabaseInfoRequest())

    assert result.start_ea == "0x401000"
    assert result.entry_ea == "0x402000"


def test_segment_list_filters_with_regex_pattern() -> None:
    class FakeRuntime(IdaRuntime):
        @staticmethod
        def iter_segments() -> tuple[SegmentRange, ...]:
            return (
                SegmentRange(name="__TEXT:__text", start_ea=0x1000, end_ea=0x2000),
                SegmentRange(name="__TEXT:__cstring", start_ea=0x3000, end_ea=0x3400),
                SegmentRange(name="__DATA:__data", start_ea=0x4000, end_ea=0x4800),
            )

    rows = segments._segment_list(
        OperationContext(runtime=FakeRuntime()),
        segments.SegmentListRequest(pattern="__TEXT|__cstring", glob=False, regex=True, ignore_case=False),
    )

    assert rows == (
        segments.SegmentListEntry(name="__TEXT:__text", start="0x1000", end="0x2000", size=0x1000),
        segments.SegmentListEntry(name="__TEXT:__cstring", start="0x3000", end="0x3400", size=0x400),
    )


def test_xrefs_collect_code_and_data_references_explicitly() -> None:
    seen_flags: list[int] = []

    class FakeRuntime(IdaRuntime):
        class ida_xref:
            XREF_FLOW = 0
            XREF_CODE = 0x4
            XREF_DATA = 0x2

        class ida_funcs:
            @staticmethod
            def get_func(_ea: int):
                return None

        @staticmethod
        def resolve_address(identifier: str) -> int:
            assert identifier == "target"
            return 0x401004

        def xrefs_to(self, ea: int, *, flags: int = 0) -> tuple[XrefRecord, ...]:
            assert ea == 0x401004
            seen_flags.append(flags)
            if flags == self.ida_xref.XREF_FLOW:
                return (
                    XrefRecord(
                        from_ea=0x400FF0,
                        to_ea=0x401004,
                        type="Ordinary_Flow",
                        kind="flow",
                        user=False,
                    ),
                )
            if flags == self.ida_xref.XREF_CODE:
                return (
                    XrefRecord(
                        from_ea=0x401000,
                        to_ea=0x401004,
                        type="Code_Near_Call",
                        kind="call",
                        user=False,
                    ),
                )
            if flags == self.ida_xref.XREF_DATA:
                return (
                    XrefRecord(
                        from_ea=0x402000,
                        to_ea=0x401004,
                        type="Data_Read",
                        kind="read",
                        user=False,
                    ),
                )
            raise AssertionError(f"unexpected flags: {flags}")

    rows = search._xrefs(OperationContext(runtime=FakeRuntime()), search.XrefsRequest(identifier="target"))

    assert seen_flags == [0, 4, 2]
    assert rows == (
        search.XrefRow(
            from_="0x401000",
            to="0x401004",
            type="Code_Near_Call",
            kind="call",
            user=False,
            function=None,
        ),
        search.XrefRow(
            from_="0x400ff0",
            to="0x401004",
            type="Ordinary_Flow",
            kind="flow",
            user=False,
            function=None,
        ),
        search.XrefRow(
            from_="0x402000",
            to="0x401004",
            type="Data_Read",
            kind="read",
            user=False,
            function=None,
        ),
    )


def test_runtime_xrefs_to_requests_flow_by_default() -> None:
    seen: list[tuple[int, int]] = []

    class FakeXref:
        frm = 0x401000
        to = 0x401004
        iscode = True
        type = 99
        user = False

    class FakeXrefBlock:
        def refs_to(self, ea: int, flags: int):
            seen.append((ea, flags))
            return (FakeXref(),)

        def refs_from(self, ea: int, flags: int):
            seen.append((ea, flags))
            return (FakeXref(),)

    class FakeIdaXref:
        XREF_FLOW = 1234

        @staticmethod
        def xrefblk_t() -> FakeXrefBlock:
            return FakeXrefBlock()

    class FakeRuntime(IdaRuntime):
        def mod(self, name: str):
            assert name == "ida_xref"
            return FakeIdaXref()

        @staticmethod
        def _normalize_xref(_xref) -> XrefRecord:
            return XrefRecord(
                from_ea=0x401000,
                to_ea=0x401004,
                type="Ordinary_Flow",
                kind="flow",
                user=False,
            )

    runtime = FakeRuntime()
    assert runtime.xrefs_to(0x401004) == (
        XrefRecord(
            from_ea=0x401000,
            to_ea=0x401004,
            type="Ordinary_Flow",
            kind="flow",
            user=False,
        ),
    )
    assert runtime.xrefs_from(0x401000) == (
        XrefRecord(
            from_ea=0x401000,
            to_ea=0x401004,
            type="Ordinary_Flow",
            kind="flow",
            user=False,
        ),
    )
    assert seen == [(0x401004, 1234), (0x401000, 1234)]


def test_op_function_frame_uses_get_func_frame_not_func_frame_object() -> None:
    calls: list[tuple[str, int]] = []

    class FakeMemberType:
        @staticmethod
        def dstr() -> str:
            return "int"

    class FakeFrameMember:
        name = "var_4"
        type = FakeMemberType()

        @staticmethod
        def begin() -> int:
            return 32

        @staticmethod
        def end() -> int:
            return 64

    class FakeFrameTif:
        def __init__(self) -> None:
            self._members = [FakeFrameMember()]

        @staticmethod
        def get_size() -> int:
            return 24

        def get_func_frame(self, func: object) -> bool:
            calls.append(("get_func_frame", int(func.start_ea)))
            return True

        def iter_struct(self):
            return iter(self._members)

        @staticmethod
        def get_udm_tid(index: int) -> int:
            assert index == 0
            return 0

    class FakeIdaTypeInf:
        @staticmethod
        def tinfo_t() -> FakeFrameTif:
            return FakeFrameTif()

    class FakeIdaFrame:
        @staticmethod
        def is_special_frame_member(_tid: int) -> bool:
            return False

        @staticmethod
        def is_funcarg_off(_func: object, _offset: int) -> bool:
            return False

        @staticmethod
        def soff_to_fpoff(_func: object, offset: int) -> int:
            return offset

    class FakeIdaFuncs:
        @staticmethod
        def get_func_name(ea: int) -> str:
            assert ea == 0x401000
            return "main"

    class FakeIdaXref:
        dr_R = 1
        dr_W = 2

    class FakeFunc:
        start_ea = 0x401000
        end_ea = 0x401020
        frsize = 16
        frregs = 0
        argsize = 0

        @property
        def frame_object(self) -> object:
            raise AssertionError("reads.op_function_frame should not use func.frame_object")

    class FakeRuntime(IdaRuntime):
        def resolve_function(self, identifier: str) -> FakeFunc:
            assert identifier == "main"
            return FakeFunc()

        def mod(self, name: str):
            if name == "ida_frame":
                return FakeIdaFrame()
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_funcs":
                return FakeIdaFuncs()
            if name == "ida_xref":
                return FakeIdaXref()
            raise AssertionError(name)

        @staticmethod
        def tinfo_decl(_tif, *, multi: bool = True) -> str:
            assert multi is False
            return "int"

    payload = functions.op_function_frame(FakeRuntime(), {"identifier": "main"})

    assert payload["frame_size"] == 24
    assert payload["members"] == [
        {
            "index": 0,
            "name": "var_4",
            "offset": 4,
            "end_offset": 8,
            "size": 4,
            "type": "int",
            "kind": "local",
            "is_special": False,
            "is_arg": False,
            "fp_offset": 4,
            "xrefs": [],
            "xref_count": None,
        }
    ]
    assert calls == [("get_func_frame", 0x401000), ("get_func_frame", 0x401000)]


def test_local_rename_uses_direct_hexrays_rename_for_name_selector(monkeypatch) -> None:
    class FakeHexrays:
        def rename_lvar(self, func_ea: int, old_name: str, new_name: str) -> bool:
            assert func_ea == 0x401000
            assert old_name == "v4"
            assert new_name == "sum_value"
            return True

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

    monkeypatch.setattr(
        locals,
        "_select_local",
        lambda runtime, func_ea, selector: locals.SelectedLocal("v4", "loc"),
    )
    monkeypatch.setattr(
        locals,
        "_local_list_result",
        lambda runtime, func_ea: locals.LocalListResult(
            function="main",
            address="0x401000",
            locals=(),
        ),
    )

    payload = locals.op_local_rename(
        FakeRuntime(),
        {"identifier": "main", "old_name": "v4", "new_name": "sum_value"},
    )

    assert payload["changed"] is True


def test_operation_literal_matches_spec_keys() -> None:
    assert set(get_args(OperationName)) == set(SUPPORTED_OPERATIONS)


def test_only_list_targets_lacks_a_direct_operation_handler() -> None:
    assert set(SUPPORTED_OPERATIONS) - set(OPERATION_SPEC_MAP) == {"list_targets"}


def test_python_exec_is_marked_mutating() -> None:
    spec = OPERATION_SPEC_MAP["python_exec"]

    assert spec.mutating is True


def test_python_exec_scope_exposes_explicit_ida_runtime_modules() -> None:
    imported: list[str] = []
    require_hexrays_calls = 0

    class FakeRuntime(IdaRuntime):
        def mod(self, name: str):
            imported.append(name)
            if name == "ida_broken":
                raise ImportError(name)
            return {"module": name}

        def require_hexrays(self):
            nonlocal require_hexrays_calls
            require_hexrays_calls += 1
            return {"module": "ida_hexrays"}

    scope = FakeRuntime().python_exec_scope(persist=False)

    assert scope["idaapi"] == {"module": "idaapi"}
    assert scope["ida_bytes"] == {"module": "ida_bytes"}
    assert scope["ida_hexrays"] == {"module": "ida_hexrays"}
    assert "ida_broken" not in scope
    assert scope["idc"] == {"module": "idc"}
    assert scope["idautils"] == {"module": "idautils"}
    assert scope["result"] is None
    assert require_hexrays_calls == 1
    assert imported == [
        "idaapi",
        "ida_auto",
        "ida_bytes",
        "ida_entry",
        "ida_frame",
        "ida_funcs",
        "ida_ida",
        "ida_idc",
        "ida_idp",
        "ida_kernwin",
        "ida_lines",
        "ida_loader",
        "ida_moves",
        "ida_name",
        "ida_nalt",
        "ida_range",
        "ida_segment",
        "ida_strlist",
        "ida_srclang",
        "ida_typeinf",
        "ida_ua",
        "ida_undo",
        "ida_xref",
        "idc",
        "idautils",
    ]


def test_python_exec_scope_omits_ida_hexrays_when_unavailable() -> None:
    class FakeRuntime(IdaRuntime):
        def mod(self, name: str):
            return {"module": name}

        def require_hexrays(self):
            raise IdaOperationError("Hex-Rays decompiler is unavailable")

    scope = FakeRuntime().python_exec_scope(persist=False)

    assert "ida_hexrays" not in scope


def test_name_set_preview_resolves_identifier_before_capture() -> None:
    spec = OPERATION_SPEC_MAP["name_set"].preview
    assert spec is not None
    assert spec.prepare is not None

    class FakeRuntime(IdaRuntime):
        @staticmethod
        def mod(name: str):
            assert name == "ida_name"

            class FakeIdaName:
                @staticmethod
                def get_name(ea: int) -> str:
                    assert ea == 0x401000
                    return ""

            return FakeIdaName()

        @staticmethod
        def resolve_address(identifier: str) -> int:
            assert identifier in {"main", "0x401000"}
            return 0x401000

    context = OperationContext(runtime=FakeRuntime())
    request = names._parse_name_set({"identifier": "main", "new_name": "renamed"})
    prepared = spec.prepare_request(context, request)

    assert prepared == names.NameSetRequest(identifier="0x401000", new_name="renamed")
    assert spec.capture_before(context, prepared) == names.NameState(address="0x401000", name="")


def test_name_set_preview_prepare_preserves_mutation_params() -> None:
    spec = OPERATION_SPEC_MAP["name_set"].preview
    assert spec is not None
    assert spec.prepare is not None

    class FakeRuntime(IdaRuntime):
        @staticmethod
        def resolve_address(identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

    context = OperationContext(runtime=FakeRuntime())
    request = names._parse_name_set({"identifier": "main", "new_name": "add_numbers"})
    prepared = spec.prepare_request(context, request)

    assert prepared == names.NameSetRequest(identifier="0x401000", new_name="add_numbers")


def test_local_rename_preview_registers_cleanup() -> None:
    spec = OPERATION_SPEC_MAP["local_rename"].preview

    assert spec is not None
    assert spec.cleanup is not None


def test_strings_manifest_marks_operation_read_only() -> None:
    spec = OPERATION_SPEC_MAP["strings"]

    assert spec.mutating is False
    assert spec.preview is None


def test_preview_cleanup_runs_after_failed_mutation() -> None:
    events: list[str] = []

    class FakeUndo:
        def create_undo_point(self, **_kwargs) -> bool:
            events.append("create")
            return True

        def perform_undo(self) -> bool:
            events.append("undo")
            return True

    class FakeRuntime(IdaRuntime):
        def mod(self, name: str) -> FakeUndo:
            assert name == "ida_undo"
            return FakeUndo()

    def capture(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        events.append("capture")
        return {"captured": True}

    def cleanup(_context: OperationContext, _request: dict[str, object]) -> None:
        events.append("cleanup")

    def handler(_context: OperationContext, _request: dict[str, object]) -> object:
        events.append("mutate")
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        run_preview(
            OperationContext(runtime=FakeRuntime(), preview=True),
            "test_preview",
            {},
            handler,
            PreviewSpec(capture_before=capture, capture_after=capture, cleanup=cleanup, use_undo=True),
        )

    assert events == ["create", "capture", "mutate", "undo", "cleanup"]


def test_preview_cleanup_does_not_mask_mutation_failure() -> None:
    class FakeUndo:
        def create_undo_point(self, **_kwargs) -> bool:
            return True

        def perform_undo(self) -> bool:
            return True

    class FakeRuntime(IdaRuntime):
        def mod(self, name: str) -> FakeUndo:
            assert name == "ida_undo"
            return FakeUndo()

    def capture(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        return {"captured": True}

    def cleanup(_context: OperationContext, _request: dict[str, object]) -> None:
        raise RuntimeError("cleanup failed")

    def handler(_context: OperationContext, _request: dict[str, object]) -> object:
        raise ValueError("mutation failed")

    with pytest.raises(ValueError, match="mutation failed"):
        run_preview(
            OperationContext(runtime=FakeRuntime(), preview=True),
            "test_preview",
            {},
            handler,
            PreviewSpec(capture_before=capture, capture_after=capture, cleanup=cleanup, use_undo=True),
        )


def test_manual_preview_rolls_back_when_after_capture_fails() -> None:
    events: list[str] = []

    def capture_before(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        events.append("before")
        return {"before": True}

    def capture_after(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        events.append("after")
        raise RuntimeError("after failed")

    def rollback(
        _context: OperationContext,
        _request: dict[str, object],
        _before: dict[str, bool],
        _result: dict[str, bool],
    ) -> None:
        events.append("rollback")

    def handler(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        events.append("mutate")
        return {"changed": True}

    with pytest.raises(RuntimeError, match="after failed"):
        run_preview(
            OperationContext(runtime=IdaRuntime(), preview=True),
            "test_preview",
            {},
            handler,
            PreviewSpec(capture_before=capture_before, capture_after=capture_after, rollback=rollback),
        )

    assert events == ["before", "mutate", "after", "rollback"]


def test_manual_preview_reports_rollback_failure_after_capture_failure() -> None:
    def capture_before(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        return {"before": True}

    def capture_after(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        raise RuntimeError("after failed")

    def rollback(
        _context: OperationContext,
        _request: dict[str, object],
        _before: dict[str, bool],
        _result: dict[str, bool],
    ) -> None:
        raise RuntimeError("rollback failed")

    def handler(_context: OperationContext, _request: dict[str, object]) -> dict[str, bool]:
        return {"changed": True}

    with pytest.raises(RuntimeError, match="rollback failed") as excinfo:
        run_preview(
            OperationContext(runtime=IdaRuntime(), preview=True),
            "test_preview",
            {},
            handler,
            PreviewSpec(capture_before=capture_before, capture_after=capture_after, rollback=rollback),
        )

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "after failed"


def test_recoverable_ida_errors_do_not_treat_typeerror_as_recoverable() -> None:
    assert is_recoverable_ida_error(TypeError("boom")) is False

    with pytest.raises(TypeError, match="boom"), suppress_recoverable_ida_errors():
        raise TypeError("boom")


def test_split_declarations_tracks_next_chunk_line_after_newline() -> None:
    chunks = _split_declarations("typedef int a;\n\n typedef int b;")

    assert chunks[0]["start_line"] == 1
    assert chunks[1]["start_line"] == 3


def test_type_declare_diagnostics_ignore_braces_inside_comments_and_strings() -> None:
    diagnostics = type_declare._type_declare_diagnostics(
        'const char *s = "{"; /* } */',
        errors=1,
        aliases_applied=[],
    )

    assert not any(item["kind"] == "unbalanced_braces" for item in diagnostics)
    assert any(item["kind"] == "unterminated_declaration" for item in diagnostics)


def test_type_declare_diagnostics_report_cppobj_and_forward_decl_hints() -> None:
    diagnostics = type_declare._type_declare_diagnostics(
        "struct helper; class __cppobj Broken : helper { int value; };",
        errors=1,
        aliases_applied=[],
    )

    kinds = {item["kind"] for item in diagnostics}
    assert "cppobj_hint" in kinds
    assert "forward_declaration_hint" in kinds


def test_type_declare_detects_forward_declared_opaque_by_value_member() -> None:
    chunks = type_declare._split_declarations(
        "struct Missing; typedef struct wrapper_bad { struct Missing value; } wrapper_bad;"
    )

    blocking = type_declare._opaque_by_value_members(chunks[1], earlier_chunks=chunks[:1])

    assert blocking == [{"type_name": "Missing", "member_name": "value"}]


def test_type_declare_bisect_isolates_first_failing_declaration() -> None:
    chunks = type_declare._split_declarations(
        "typedef struct good_one { int value; } good_one;"
        "struct Missing;"
        "typedef struct wrapper_bad { struct Missing value; } wrapper_bad;"
    )

    class FakeUndo:
        def create_undo_point(self, **_kwargs) -> bool:
            return True

        def perform_undo(self) -> bool:
            return True

    class FakeIdaTypeInf:
        PT_REPLACE = 1

        @staticmethod
        def idc_parse_types(decl: str, _flags: int) -> int:
            return 1 if "wrapper_bad" in decl else 0

    class FakeRuntime:
        def mod(self, name: str):
            if name == "ida_undo":
                return FakeUndo()
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            raise AssertionError(name)

    payload = type_declare._bisect_type_declarations(FakeRuntime(), chunks, replace=False, clang=False)

    assert payload["supported"] is True
    assert payload["failing_declaration"]["index"] == 3
    assert payload["blocking_members"] == [{"type_name": "Missing", "member_name": "value"}]


def test_type_declare_clang_uses_srclang_parser_ext() -> None:
    calls: list[tuple[str, object, str, int]] = []

    class FakeIdaTypeInf:
        HTI_DCL = 0x400
        HTI_SEMICOLON = 0x200000
        HTI_RELAXED = 0x80000

    class FakeIdaSrclang:
        @staticmethod
        def parse_decls_with_parser_ext(parser_name: str, til: object, decl: str, flags: int) -> int:
            calls.append((parser_name, til, decl, flags))
            return 0

    class FakeRuntime:
        def mod(self, name: str):
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_srclang":
                return FakeIdaSrclang()
            raise AssertionError(name)

    errors = type_declare._parse_type_declarations(
        FakeRuntime(),
        "struct ns::Widget { int value; };",
        replace=False,
        clang=True,
    )

    assert errors == 0
    assert calls == [("clang", None, "struct ns::Widget { int value; };", 0x280400)]


def test_type_declare_clang_reports_unavailable_parser() -> None:
    class FakeIdaTypeInf:
        HTI_DCL = 0x400
        HTI_SEMICOLON = 0x200000

    class FakeIdaSrclang:
        @staticmethod
        def parse_decls_with_parser_ext(parser_name: str, til: object, decl: str, flags: int) -> int:
            assert parser_name == "clang"
            assert til is None
            assert decl == "struct Widget { int value; };"
            assert flags == 0x200400
            return -1

    class FakeRuntime:
        def mod(self, name: str):
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_srclang":
                return FakeIdaSrclang()
            raise AssertionError(name)

    with pytest.raises(IdaOperationError, match="clang parser is unavailable"):
        type_declare._parse_type_declarations(
            FakeRuntime(),
            "struct Widget { int value; };",
            replace=False,
            clang=True,
        )


def test_type_declare_clang_replace_deletes_existing_types_before_parse() -> None:
    calls: list[tuple[object, ...]] = []

    class FakeIdaUndo:
        @staticmethod
        def create_undo_point(**kwargs) -> bool:
            calls.append(("undo_create", kwargs["action_name"], kwargs["label"]))
            return True

        @staticmethod
        def perform_undo() -> bool:
            calls.append(("undo",))
            return True

    class FakeIdaTypeInf:
        HTI_DCL = 0x400
        HTI_SEMICOLON = 0x200000
        NTF_TYPE = 0x1

        @staticmethod
        def del_named_type(_til: object, name: str, flags: int) -> bool:
            calls.append(("delete", name, flags))
            return True

    class FakeIdaSrclang:
        @staticmethod
        def parse_decls_with_parser_ext(parser_name: str, til: object, decl: str, flags: int) -> int:
            calls.append(("parse", parser_name, til, decl, flags))
            return 0

    class FakeRuntime:
        def mod(self, name: str):
            if name == "ida_undo":
                return FakeIdaUndo()
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_srclang":
                return FakeIdaSrclang()
            raise AssertionError(name)

        @staticmethod
        def find_named_type(name: str):
            return object() if name == "Widget" else None

    errors = type_declare._parse_type_declarations(
        FakeRuntime(),
        "typedef struct Widget { int value; } Widget;",
        replace=True,
        clang=True,
    )

    assert errors == 0
    assert calls == [
        ("undo_create", "idac_type_declare_clang_replace", "idac type declare clang replace"),
        ("delete", "Widget", 0x1),
        ("parse", "clang", None, "typedef struct Widget { int value; } Widget;", 0x200400),
    ]


def test_type_declare_clang_replace_restores_deleted_types_on_parse_error() -> None:
    calls: list[tuple[object, ...]] = []

    class FakeIdaUndo:
        @staticmethod
        def create_undo_point(**_kwargs) -> bool:
            calls.append(("undo_create",))
            return True

        @staticmethod
        def perform_undo() -> bool:
            calls.append(("undo",))
            return True

    class FakeIdaTypeInf:
        HTI_DCL = 0x400
        HTI_SEMICOLON = 0x200000
        NTF_TYPE = 0x1

        @staticmethod
        def del_named_type(_til: object, name: str, flags: int) -> bool:
            calls.append(("delete", name, flags))
            return True

    class FakeIdaSrclang:
        @staticmethod
        def parse_decls_with_parser_ext(parser_name: str, til: object, decl: str, flags: int) -> int:
            calls.append(("parse", parser_name, til, decl, flags))
            return 2

    class FakeRuntime:
        def mod(self, name: str):
            if name == "ida_undo":
                return FakeIdaUndo()
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_srclang":
                return FakeIdaSrclang()
            raise AssertionError(name)

        @staticmethod
        def find_named_type(name: str):
            return object() if name == "Widget" else None

    errors = type_declare._parse_type_declarations(
        FakeRuntime(),
        "typedef struct Widget { int value; } Widget;",
        replace=True,
        clang=True,
    )

    assert errors == 2
    assert calls == [
        ("undo_create",),
        ("delete", "Widget", 0x1),
        ("parse", "clang", None, "typedef struct Widget { int value; } Widget;", 0x200400),
        ("undo",),
    ]


def test_type_declare_clang_bisect_returns_structured_unavailable_result() -> None:
    class FakeIdaTypeInf:
        HTI_DCL = 0x400
        HTI_SEMICOLON = 0x200000

    class FakeIdaSrclang:
        @staticmethod
        def parse_decls_with_parser_ext(parser_name: str, til: object, decl: str, flags: int) -> int:
            assert parser_name == "clang"
            assert til is None
            assert decl == "struct Widget { int value; };"
            assert flags == 0x200400
            return -1

    class FakeUndo:
        def create_undo_point(self, **_kwargs) -> bool:
            return True

        def perform_undo(self) -> bool:
            return True

    class FakeRuntime:
        def mod(self, name: str):
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_srclang":
                return FakeIdaSrclang()
            if name == "ida_undo":
                return FakeUndo()
            raise AssertionError(name)

        @staticmethod
        def list_named_types() -> list[dict[str, object]]:
            return [{"name": "Existing", "decl": "struct Existing;"}]

    chunks = type_declare._coerce_chunks(type_declare._split_declarations("struct Widget { int value; };"))
    errors, before, after, bisect = type_declare._apply_type_declarations_with_optional_bisect(
        FakeRuntime(),
        "struct Widget { int value; };",
        replace=False,
        clang=True,
        chunks=chunks,
        bisect_requested=True,
    )

    assert errors == 1
    assert before == {"Existing": "struct Existing;"}
    assert after == before
    assert bisect == {
        "requested": True,
        "supported": False,
        "mode": "ordered_prefix",
        "declaration_count": 1,
        "message": "clang parser is unavailable for type declare",
        "diagnostics": [{"kind": "bisect_unavailable", "message": "clang parser is unavailable for type declare"}],
    }


def test_local_rename_reports_success_when_readback_fails(monkeypatch) -> None:
    class FakeHexrays:
        MLI_NAME = 1

        class lvar_saved_info_t:
            def __init__(self) -> None:
                self.ll = None
                self.name = ""

        def modify_user_lvar_info(self, func_ea: int, kind: int, info: object) -> bool:
            assert func_ea == 0x401000
            assert kind == self.MLI_NAME
            assert info.name == "sum_value"
            return True

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

    monkeypatch.setattr(locals, "_select_local", lambda runtime, func_ea, selector: locals.SelectedLocal("v4", "loc"))
    monkeypatch.setattr(
        locals,
        "_local_list_result",
        lambda runtime, func_ea: (_ for _ in ()).throw(RuntimeError("decompiler refresh failed")),
    )

    with pytest.raises(
        IdaOperationError,
        match="failed to read back locals: decompiler refresh failed",
    ):
        locals.op_local_rename(
            FakeRuntime(),
            {"identifier": "main", "old_name": "v4", "new_name": "sum_value"},
        )


def test_local_name_from_selector_rejects_multiple_stable_selector_kinds(monkeypatch) -> None:
    with pytest.raises(
        IdaOperationError,
        match="--local-id and --index are mutually exclusive",
    ):
        locals._resolve_lvar_selection(
            object(),
            0x401000,
            {"index": 0, "local_id": "stack(16)@0x401000"},
            name_key="old_name",
        )


def test_resolve_lvar_selection_uses_stable_locator_for_index_selector() -> None:
    class FakeLocation:
        pass

    class FakeLvar:
        def __init__(self) -> None:
            self.name = "v4"
            self.defea = 0x401000
            self.location = FakeLocation()

        def is_stk_var(self) -> bool:
            return False

    class FakeCfunc:
        def get_lvars(self) -> list[FakeLvar]:
            return [FakeLvar()]

    class FakeHexrays:
        class lvar_locator_t:
            def __init__(self) -> None:
                self.defea = 0
                self.location = None

        def decompile(self, func_ea: int) -> FakeCfunc:
            assert func_ea == 0x401000
            return FakeCfunc()

    class FakeRuntime:
        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

    name, locator = locals._resolve_lvar_selection(
        FakeRuntime(),
        0x401000,
        {"index": 0},
        name_key="old_name",
    )

    assert name == "v4"
    assert locator.defea == 0x401000
    assert isinstance(locator.location, FakeLocation)


def test_resolve_lvar_selection_allows_name_hint_with_stable_selector() -> None:
    class FakeLocation:
        pass

    class FakeLvar:
        def __init__(self) -> None:
            self.name = "v4"
            self.defea = 0x401000
            self.location = FakeLocation()

        def is_stk_var(self) -> bool:
            return False

    class FakeCfunc:
        def get_lvars(self) -> list[FakeLvar]:
            return [FakeLvar()]

    class FakeHexrays:
        class lvar_locator_t:
            def __init__(self) -> None:
                self.defea = 0
                self.location = None

        def decompile(self, func_ea: int) -> FakeCfunc:
            assert func_ea == 0x401000
            return FakeCfunc()

    class FakeRuntime:
        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

    name, locator = locals._resolve_lvar_selection(
        FakeRuntime(),
        0x401000,
        {"old_name": "v6", "index": 0},
        name_key="old_name",
    )

    assert name == "v4"
    assert locator.defea == 0x401000


def test_resolve_lvar_selection_accepts_local_id_text() -> None:
    class FakeLocation:
        def is_stkoff(self) -> bool:
            return True

        def stkoff(self) -> int:
            return -16

    class FakeLvar:
        def __init__(self) -> None:
            self.name = "v4"
            self.defea = 0x401000
            self.location = FakeLocation()

        def is_stk_var(self) -> bool:
            return True

    class FakeCfunc:
        def get_lvars(self) -> list[FakeLvar]:
            return [FakeLvar()]

    class FakeHexrays:
        class lvar_locator_t:
            def __init__(self) -> None:
                self.defea = 0
                self.location = None

        def decompile(self, func_ea: int) -> FakeCfunc:
            assert func_ea == 0x401000
            return FakeCfunc()

    class FakeRuntime:
        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

    name, locator = locals._resolve_lvar_selection(
        FakeRuntime(),
        0x401000,
        {"local_id": "stack(-16)@0X401000"},
        name_key="old_name",
    )

    assert name == "v4"
    assert locator.defea == 0x401000


def test_local_update_allows_unnamed_local_selected_by_stable_selector(monkeypatch) -> None:
    class FakeLocation:
        pass

    class FakeLvar:
        def __init__(self) -> None:
            self.name = ""
            self.defea = 0x401000
            self.location = FakeLocation()

    class FakeCfunc:
        def get_lvars(self) -> list[FakeLvar]:
            return [FakeLvar()]

    class FakeHexrays:
        MLI_NAME = 1

        class lvar_locator_t:
            def __init__(self) -> None:
                self.defea = 0
                self.location = None

        class lvar_saved_info_t:
            def __init__(self) -> None:
                self.ll = None
                self.name = ""
                self.type = None

        def decompile(self, func_ea: int) -> FakeCfunc:
            assert func_ea == 0x401000
            return FakeCfunc()

        def modify_user_lvar_info(self, func_ea: int, kind: int, info: object) -> bool:
            assert func_ea == 0x401000
            assert kind == self.MLI_NAME
            assert info.name == "recovered_name"
            return True

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

    monkeypatch.setattr(
        locals,
        "_local_list_result",
        lambda runtime, func_ea: locals.LocalListResult(function="main", address="0x401000", locals=()),
    )

    payload = locals.op_local_update(
        FakeRuntime(),
        {"identifier": "main", "index": 0, "new_name": "recovered_name"},
    )

    assert payload["changed"] is True


def test_proto_set_parses_silently_and_applies_tinfo() -> None:
    calls: list[tuple[object, ...]] = []
    tif = object()

    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000
        TINFO_DEFINITE = 0x1
        PRTYPE_1LINE = 1

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert out_tif is tif
            assert til is None
            calls.append(("parse", decl, flags))
            return True

        @staticmethod
        def apply_tinfo(ea: int, parsed_tif: object, flags: int) -> bool:
            calls.append(("apply", ea, parsed_tif, flags))
            return True

        @staticmethod
        def print_type(ea: int, flags: int) -> str:
            assert ea == 0x401000
            assert flags == 1
            return "void __fastcall target(void)"

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "target"
            return 0x401000

        def mod(self, name: str) -> object:
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_name":

                class FakeIdaName:
                    @staticmethod
                    def get_name(_ea: int) -> str:
                        return "target"

                return FakeIdaName()
            raise AssertionError(name)

        def find_named_type(self, name: str):
            return object()

    payload = prototypes.op_proto_set(
        FakeRuntime(),
        {"identifier": "target", "decl": "void __fastcall target(void)", "propagate_callers": False},
    )

    assert payload == {
        "address": "0x401000",
        "prototype": "void __fastcall target(void)",
        "changed": True,
        "callers_considered": 0,
        "callers_updated": 0,
        "callers_failed": 0,
    }
    assert calls == [
        ("parse", "void __fastcall target(void);", 0x4009),
        ("apply", 0x401000, tif, 0x1),
    ]


def test_proto_set_retries_with_relaxed_namespace_parse() -> None:
    calls: list[tuple[str, int]] = []
    tif = object()

    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_RELAXED = 0x1000
        PT_SEMICOLON = 0x4000
        TINFO_DEFINITE = 0x1
        PRTYPE_1LINE = 1

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert til is None
            assert out_tif is tif
            calls.append((decl, flags))
            return flags == 0x5009

        @staticmethod
        def apply_tinfo(ea: int, parsed_tif: object, flags: int) -> bool:
            assert ea == 0x401000
            assert parsed_tif is tif
            assert flags == 0x1
            return True

        @staticmethod
        def print_type(_ea: int, _flags: int) -> str:
            return "ns::Type *__fastcall target(ns::Type *value)"

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "target"
            return 0x401000

        def mod(self, name: str) -> object:
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_name":

                class FakeIdaName:
                    @staticmethod
                    def get_name(_ea: int) -> str:
                        return "target"

                return FakeIdaName()
            raise AssertionError(name)

        def find_named_type(self, name: str):
            return object()

    payload = prototypes.op_proto_set(
        FakeRuntime(),
        {
            "identifier": "target",
            "decl": "ns::Type *__fastcall target(ns::Type *value)",
            "propagate_callers": False,
        },
    )

    assert payload["changed"] is True
    assert calls == [
        ("ns::Type *__fastcall target(ns::Type *value);", 0x4009),
        ("ns::Type *__fastcall target(ns::Type *value);", 0x5009),
    ]


def test_proto_set_optionally_propagates_to_callers() -> None:
    tif = object()

    class FakeInsn:
        pass

    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000
        TINFO_DEFINITE = 0x1
        PRTYPE_1LINE = 1

        def __init__(self) -> None:
            self.applied: list[int] = []

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert out_tif is tif
            assert til is None
            assert decl == "void __fastcall target(int value);"
            assert flags == 0x4009
            return True

        @staticmethod
        def apply_tinfo(ea: int, parsed_tif: object, flags: int) -> bool:
            assert ea == 0x401000
            assert parsed_tif is tif
            assert flags == 0x1
            return True

        def apply_callee_tinfo(self, call_ea: int, parsed_tif: object) -> bool:
            assert parsed_tif is tif
            self.applied.append(call_ea)
            return call_ea != 0x402008

        @staticmethod
        def print_type(ea: int, flags: int) -> str:
            assert ea == 0x401000
            assert flags == 1
            return "void __fastcall target(int value)"

    ida_typeinf = FakeIdaTypeInf()

    class FakeIdaUa:
        @staticmethod
        def insn_t() -> FakeInsn:
            return FakeInsn()

        @staticmethod
        def decode_insn(_insn: FakeInsn, _ea: int) -> bool:
            return True

    class FakeIdaIdp:
        @staticmethod
        def is_call_insn(insn: FakeInsn) -> bool:
            return getattr(insn, "ea", None) != 0x402010

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "target"
            return 0x401000

        def mod(self, name: str) -> object:
            if name == "ida_typeinf":
                return ida_typeinf
            if name == "ida_name":

                class FakeIdaName:
                    @staticmethod
                    def get_name(_ea: int) -> str:
                        return "target"

                return FakeIdaName()
            raise AssertionError(name)

        class idautils:
            @staticmethod
            def CodeRefsTo(ea: int, flow: int) -> list[int]:
                assert ea == 0x401000
                assert flow == 0
                return [0x402000, 0x402008, 0x402010]

        class ida_ua(FakeIdaUa):
            @staticmethod
            def decode_insn(insn: FakeInsn, ea: int) -> bool:
                insn.ea = ea
                return True

        class ida_idp(FakeIdaIdp):
            pass

        def find_named_type(self, name: str):
            return object()

    payload = prototypes.op_proto_set(
        FakeRuntime(),
        {
            "identifier": "target",
            "decl": "void __fastcall target(int value)",
            "propagate_callers": True,
        },
    )

    assert payload["changed"] is True
    assert payload["callers_considered"] == 2
    assert payload["callers_updated"] == 1
    assert payload["callers_failed"] == 1
    assert ida_typeinf.applied == [0x402000, 0x402008]


def test_proto_set_reports_unknown_type_name() -> None:
    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000
        PRTYPE_1LINE = 1

        @staticmethod
        def tinfo_t() -> object:
            return object()

        @staticmethod
        def parse_decl(_out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert til is None
            assert decl == "void __fastcall target(eValueType value_type);"
            assert flags == 0x4009
            return False

        def print_type(self, ea: int, flags: int) -> str:
            raise AssertionError("print_type should not be reached on failure")

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "target"
            return 0x401000

        def mod(self, name: str) -> object:
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_name":

                class FakeIdaName:
                    @staticmethod
                    def get_name(_ea: int) -> str:
                        return "target"

                return FakeIdaName()
            raise AssertionError(name)

        def find_named_type(self, name: str):
            return None if name == "eValueType" else object()

    with pytest.raises(IdaOperationError, match="unknown type\\(s\\): eValueType"):
        prototypes.op_proto_set(
            FakeRuntime(),
            {"identifier": "target", "decl": "void __fastcall target(eValueType value_type)"},
        )


def test_proto_set_reports_generic_parse_failure() -> None:
    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000
        PRTYPE_1LINE = 1

        @staticmethod
        def tinfo_t() -> object:
            return object()

        @staticmethod
        def parse_decl(_out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert til is None
            assert decl == "void __fastcall target(ValueType value);"
            assert flags == 0x4009
            return False

        @staticmethod
        def print_type(ea: int, flags: int) -> str:
            assert ea == 0x401000
            assert flags == 1
            return "int __fastcall target(int value)"

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "target"
            return 0x401000

        def mod(self, name: str) -> object:
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_name":

                class FakeIdaName:
                    @staticmethod
                    def get_name(_ea: int) -> str:
                        return "target"

                return FakeIdaName()
            raise AssertionError(name)

        def find_named_type(self, name: str):
            return object()

    with pytest.raises(IdaOperationError, match="parser limitations"):
        prototypes.op_proto_set(
            FakeRuntime(),
            {"identifier": "target", "decl": "void __fastcall target(ValueType value)"},
        )


def test_proto_set_reports_apply_failure_after_successful_parse() -> None:
    tif = object()

    class FakeIdaTypeInf:
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000
        TINFO_DEFINITE = 0x1
        PRTYPE_1LINE = 1

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(out_tif: object, til: object, decl: str, flags: int) -> bool:
            assert out_tif is tif
            assert til is None
            assert decl == "void __fastcall target(int value);"
            assert flags == 0x4009
            return True

        @staticmethod
        def apply_tinfo(ea: int, parsed_tif: object, flags: int) -> bool:
            assert ea == 0x401000
            assert parsed_tif is tif
            assert flags == 0x1
            return False

        @staticmethod
        def print_type(ea: int, flags: int) -> str:
            assert ea == 0x401000
            assert flags == 1
            return "int __fastcall target(int value)"

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "target"
            return 0x401000

        def mod(self, name: str) -> object:
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_name":

                class FakeIdaName:
                    @staticmethod
                    def get_name(_ea: int) -> str:
                        return "target"

                return FakeIdaName()
            raise AssertionError(name)

        def find_named_type(self, name: str):
            return object()

    with pytest.raises(IdaOperationError, match="apply_tinfo failed"):
        prototypes.op_proto_set(
            FakeRuntime(),
            {"identifier": "target", "decl": "void __fastcall target(int value)"},
        )


def test_require_class_tinfo_explains_non_class_materialized_type() -> None:
    class FakeRuntime:
        def find_named_type(self, name: str):
            assert name == "CMessaging"
            return object()

        def is_class_tinfo(self, tif: object) -> bool:
            return False

        def classify_tinfo(self, tif: object) -> str:
            return "struct"

        def find_symbols(self, *, query: str | None = None):
            assert query == "CMessaging"
            return [
                {"name": "__ZTV10CMessaging", "is_function": False},
                {"name": "__ZN10CMessaging17SendInlineMessageEv", "is_function": True},
            ]

    with pytest.raises(IdaOperationError) as excinfo:
        classes._require_class_tinfo(FakeRuntime(), "CMessaging")
    message = str(excinfo.value)
    assert "exists as a struct, but is not class-materialized" in message
    assert "type class candidates --query CMessaging" in message
    assert "symbol evidence:" in message


def test_class_hierarchy_explains_non_class_materialized_type() -> None:
    class FakeRuntime:
        def list_named_classes(self):
            return []

        def find_named_type(self, name: str):
            assert name == "CMessaging"
            return object()

        def is_class_tinfo(self, tif: object) -> bool:
            return False

        def classify_tinfo(self, tif: object) -> str:
            return "struct"

        def find_symbols(self, *, query: str | None = None):
            assert query == "CMessaging"
            return [
                {"name": "__ZTV10CMessaging", "is_function": False},
                {"name": "__ZN10CMessaging17SendInlineMessageEv", "is_function": True},
            ]

    with pytest.raises(IdaOperationError) as excinfo:
        classes.op_class_hierarchy(FakeRuntime(), {"name": "CMessaging"})
    message = str(excinfo.value)
    assert "exists as a struct, but is not class-materialized" in message
    assert "type class candidates --query CMessaging" in message


def test_symbol_evidence_swallows_recoverable_lookup_errors() -> None:
    class FakeRuntime:
        def find_symbols(self, *, query: str | None = None):
            assert query == "CMessaging"
            raise RuntimeError("temporary IDA lookup failure")

    assert classes._symbol_evidence(FakeRuntime(), "CMessaging") == []


def test_symbol_evidence_reraises_nonrecoverable_lookup_errors() -> None:
    class FakeRuntime:
        def find_symbols(self, *, query: str | None = None):
            assert query == "CMessaging"
            raise TypeError("bad lookup")

    with pytest.raises(TypeError, match="bad lookup"):
        classes._symbol_evidence(FakeRuntime(), "CMessaging")


def test_class_summary_uses_requested_alias_for_name_and_decl() -> None:
    runtime = IdaRuntime()
    calls: list[tuple[str | None, bool]] = []

    class FakeTif:
        @staticmethod
        def get_type_name() -> str:
            return ""

        @staticmethod
        def get_size() -> int:
            return 24

    runtime.class_base_names = lambda tif: ["Base"]
    runtime.class_vtable_type_name = lambda tif: "Alias_vtbl"

    def fake_tinfo_decl(tif, *, name=None, multi=True) -> str:
        calls.append((name, multi))
        return f"struct {name}" if name else "struct <anonymous>"

    runtime.tinfo_decl = fake_tinfo_decl

    payload = runtime.class_summary(FakeTif(), name="Alias", decl_multi=True)

    assert payload["name"] == "Alias"
    assert payload["decl"] == "struct Alias"
    assert calls == [("Alias", True)]


def test_class_vtable_runtime_fallback_uses_requested_alias_when_type_name_missing(
    monkeypatch,
) -> None:
    class AnonymousClassTif:
        @staticmethod
        def get_type_name() -> str:
            return ""

    looked_up_names: list[str] = []
    runtime = type(
        "FakeRuntime",
        (),
        {
            "find_named_type": staticmethod(lambda name: AnonymousClassTif() if name == "Alias" else None),
            "is_class_tinfo": staticmethod(lambda tif: True),
            "get_named_type": staticmethod(lambda name: object()),
            "class_vtable_type_name": staticmethod(lambda tif: "Alias_vtbl"),
            "class_runtime_vtable_identifier": staticmethod(
                lambda tif, name=None: looked_up_names.append(name) or "0x402000"
            ),
            "tinfo_decl": staticmethod(lambda tif, **kwargs: "struct Alias_vtbl"),
            "vtable_slot": staticmethod(lambda offset_bits: offset_bits // 64),
            "udt_members": staticmethod(lambda tif: []),
        },
    )()
    monkeypatch.setattr(
        classes,
        "_raw_vtable_dump",
        lambda runtime, identifier, slot_limit=64: {
            "identifier": identifier,
            "slot_limit": slot_limit,
        },
    )

    payload = classes.op_class_vtable(runtime, {"name": "Alias", "runtime": True})

    assert looked_up_names == ["Alias"]
    assert payload["runtime_vtable"] == {"identifier": "0x402000", "slot_limit": 64}


def test_class_show_preserves_case_sensitive_name_lookup(monkeypatch) -> None:
    tif = object()

    class FakeRuntime:
        def find_named_type(self, name: str):
            assert name == "MiXeDClass"
            return tif

        def is_class_tinfo(self, resolved_tif: object) -> bool:
            assert resolved_tif is tif
            return True

        def class_summary(self, resolved_tif: object, *, name: str, decl_multi: bool) -> dict[str, object]:
            assert resolved_tif is tif
            assert name == "MiXeDClass"
            assert decl_multi is True
            return {"name": name, "decl": "struct MiXeDClass;"}

    monkeypatch.setattr(classes, "_flatten_class_fields", lambda runtime, resolved_tif, derived_only: [])

    payload = classes.op_class_show(FakeRuntime(), {"name": "MiXeDClass"})

    assert payload["name"] == "MiXeDClass"
    assert payload["decl"] == "struct MiXeDClass;"
    assert payload["members"] == []


def test_type_show_normalizes_unknown_size_to_none() -> None:
    class FakeType:
        @staticmethod
        def get_size() -> int:
            return 0xFFFFFFFFFFFFFFFF

    class FakeRuntime:
        def get_named_type(self, name: str):
            assert name == "OpaqueThing"
            return FakeType()

        def classify_tinfo(self, tif: object) -> str:
            return "struct"

        def tinfo_decl(self, tif: object, *, name: str, multi: bool) -> str:
            assert name == "OpaqueThing"
            assert multi is True
            return "struct OpaqueThing;"

        def tinfo_members(self, tif: object) -> list[dict[str, object]]:
            return []

    payload = types.op_type_show(FakeRuntime(), {"name": "OpaqueThing"})

    assert payload["size"] is None
    assert payload["size_known"] is False


def test_enum_member_rename_reports_success_when_readback_fails(monkeypatch) -> None:
    class FakeEnumTif:
        def __init__(self) -> None:
            self.persisted_name: str | None = None

        def get_edm(self, name: str) -> tuple[int, object]:
            assert name == "RED"
            return 0, object()

        def rename_edm(self, idx: int, new_name: str) -> int:
            assert idx == 0
            assert new_name == "CRIMSON"
            return 0

        def set_named_type(self, _til, name: str, _flags: int) -> int:
            self.persisted_name = name
            return 0

    class FakeIdaTypeInf:
        TERR_OK = 0
        NTF_REPLACE = 1

        @staticmethod
        def tinfo_errstr(code: int) -> str:
            return f"terr={code}"

    tif = FakeEnumTif()

    class FakeRuntime:
        def mod(self, name: str) -> FakeIdaTypeInf:
            assert name == "ida_typeinf"
            return FakeIdaTypeInf()

    monkeypatch.setattr(types, "_enum_type", lambda runtime, name: tif)
    monkeypatch.setattr(
        types,
        "_enum_view",
        lambda context, request: (_ for _ in ()).throw(RuntimeError("enum refresh failed")),
    )

    with pytest.raises(
        IdaOperationError,
        match="persisted named type `Color` but failed to read it back: enum refresh failed",
    ):
        types.op_enum_member_rename(
            FakeRuntime(),
            {"enum_name": "Color", "member_name": "RED", "new_name": "CRIMSON"},
        )

    assert tif.persisted_name == "Color"


def test_first_free_bookmark_slot_reports_full_range() -> None:
    class FakeIdaMoves:
        MAX_MARK_SLOT = 2

    class FakeRuntime:
        def mod(self, name: str):
            assert name == "ida_moves"
            return FakeIdaMoves()

    occupied = {0, 1, 2}
    original = bookmarks._bookmark_state
    try:
        bookmarks._bookmark_state = lambda runtime, slot: bookmarks.BookmarkState(  # type: ignore[assignment]
            slot=slot,
            present=slot in occupied,
            address=None,
            comment=None,
        )
        with pytest.raises(IdaOperationError, match=r"no free bookmark slots remain \(0\.\.2\)"):
            bookmarks._first_free_bookmark_slot(FakeRuntime())
    finally:
        bookmarks._bookmark_state = original  # type: ignore[assignment]
