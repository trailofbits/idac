from __future__ import annotations

import pytest

from idac import remote_ops
from tests.remote_ops_harness import dispatch_with_runtime

IdaOperationError = remote_ops.IdaOperationError
IdaRuntime = remote_ops.IdaRuntime
XrefRecord = remote_ops.XrefRecord


def _run_op(name: str, runtime, params: dict[str, object], *, preview: bool = False):
    return dispatch_with_runtime(runtime, name, params, preview=preview)


class _SuccessfulUndo:
    @staticmethod
    def create_undo_point(**_kwargs) -> bool:
        return True

    @staticmethod
    def perform_undo() -> bool:
        return True


class _DummyRuntime:
    def mod(self, _name: str):
        return object()

    def get_struct_or_union(self, _name: str):
        raise AssertionError("negative offset validation should fail before type lookup")


def test_struct_field_set_rejects_negative_offsets() -> None:
    with pytest.raises(IdaOperationError, match="greater than or equal to 0"):
        _run_op(
            "struct_field_set",
            _DummyRuntime(),
            {
                "struct_name": "Player",
                "field_name": "hp",
                "decl": "int",
                "offset": "-1",
            },
        )


def test_op_decompile_passes_no_cache_flag_when_requested() -> None:
    flags_used: list[int] = []

    class FakeLine:
        def __init__(self, line: str) -> None:
            self.line = line

    class FakeCfunc:
        def get_pseudocode(self) -> list[FakeLine]:
            return [FakeLine("int main(void)")]

    class FakeHexrays:
        DECOMP_NO_CACHE = 0x2

        @staticmethod
        def decompile(_ea: int, hf=None, flags: int = 0) -> FakeCfunc:
            del hf
            flags_used.append(flags)
            return FakeCfunc()

    class FakeRuntime(IdaRuntime):
        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

        def function_ea(self, _identifier: str) -> int:
            return 0x401000

        @staticmethod
        def mod(_name: str):
            class FakeIdaLines:
                @staticmethod
                def tag_remove(text: str) -> str:
                    return text

            return FakeIdaLines()

    payload = _run_op("decompile", FakeRuntime(), {"identifier": "main", "no_cache": True})

    assert payload == {"text": "int main(void)"}
    assert flags_used == [FakeHexrays.DECOMP_NO_CACHE]


def test_function_list_honors_limit() -> None:
    class FakeFunc:
        def __init__(self, ea: int, flags: int = 0) -> None:
            self.start_ea = ea
            self.end_ea = ea + 0x10
            self.flags = flags

    class FakeIdaUtils:
        @staticmethod
        def Functions():
            return [0x1000, 0x2000, 0x3000]

    class FakeIdaFuncs:
        FUNC_THUNK = 0x8000

        @staticmethod
        def get_func(ea: int) -> FakeFunc:
            flags = FakeIdaFuncs.FUNC_THUNK if ea == 0x2000 else 0
            return FakeFunc(ea, flags=flags)

    class FakeIdaSegment:
        @staticmethod
        def get_segment_name(_ea: int, _flags: int) -> str:
            return ""

    class FakeIdaName:
        GN_VISIBLE = 1

    class FakeRuntime(IdaRuntime):
        idautils = FakeIdaUtils()
        ida_funcs = FakeIdaFuncs()
        ida_segment = FakeIdaSegment()
        ida_name = FakeIdaName()

        @staticmethod
        def function_name(ea: int) -> str:
            return {0x1000: "alpha", 0x2000: "beta", 0x3000: "gamma"}[ea]

        @staticmethod
        def display_function_name(ea: int, *, demangle: bool = False) -> str:
            return FakeRuntime.function_name(ea)

    rows = _run_op("function_list", FakeRuntime(), {"limit": 2})

    assert [row["name"] for row in rows] == ["alpha", "beta"]


def test_function_list_reports_section_name() -> None:
    class FakeFunc:
        start_ea = 0x401000
        end_ea = 0x401010
        flags = 0

    class FakeIdaUtils:
        @staticmethod
        def Functions():
            return [0x401000]

    class FakeIdaFuncs:
        FUNC_THUNK = 0x8000

        @staticmethod
        def get_func(_ea: int) -> FakeFunc:
            return FakeFunc()

    class FakeIdaSegment:
        @staticmethod
        def get_segment_name(_ea: int, _flags: int) -> str:
            return ".text"

    class FakeIdaName:
        GN_VISIBLE = 1

    class FakeRuntime(IdaRuntime):
        idautils = FakeIdaUtils()
        ida_funcs = FakeIdaFuncs()
        ida_segment = FakeIdaSegment()
        ida_name = FakeIdaName()

        @staticmethod
        def function_name(_ea: int) -> str:
            return "main"

        @staticmethod
        def display_function_name(ea: int, *, demangle: bool = False) -> str:
            return FakeRuntime.function_name(ea)

    rows = _run_op("function_list", FakeRuntime(), {})

    assert [(row["name"], row["section"]) for row in rows] == [("main", ".text")]


def test_function_list_demangle_controls_matching_and_rendering() -> None:
    class FakeFunc:
        start_ea = 0x401000
        end_ea = 0x401010

    class FakeIdaUtils:
        @staticmethod
        def Functions():
            return [0x401000]

    class FakeIdaFuncs:
        @staticmethod
        def get_func(_ea: int) -> FakeFunc:
            return FakeFunc()

    class FakeIdaSegment:
        @staticmethod
        def get_segment_name(_ea: int, _flags: int) -> str:
            return ""

    class FakeIdaName:
        GN_VISIBLE = 1

    class FakeRuntime(IdaRuntime):
        idautils = FakeIdaUtils()
        ida_funcs = FakeIdaFuncs()
        ida_segment = FakeIdaSegment()
        ida_name = FakeIdaName()

        @staticmethod
        def function_name(_ea: int) -> str:
            return "__ZN3Foo3barEv"

        @staticmethod
        def display_function_name(_ea: int, *, demangle: bool = False) -> str:
            return "Foo::bar()"

    raw_matches = _run_op("function_list", FakeRuntime(), {"pattern": "Foo::bar"})
    demangled_matches = _run_op("function_list", FakeRuntime(), {"pattern": "Foo::bar", "demangle": True})

    assert raw_matches == []
    assert [(row["name"], row["render_name"]) for row in demangled_matches] == [("__ZN3Foo3barEv", "Foo::bar()")]


def test_database_info_reports_start_ea_separately_from_first_entry() -> None:
    class FakeIdaEntry:
        @staticmethod
        def get_entry_ordinal(_index: int) -> int:
            return 0

        @staticmethod
        def get_entry(_ordinal: int) -> int:
            return 0x402000

    class FakeIdaIda:
        @staticmethod
        def inf_get_start_ea() -> int:
            return 0x401000

        @staticmethod
        def inf_get_main() -> int:
            return 0x403000

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
        def get_path(_path_type: int) -> str:
            return "/tmp/sample.i64"

    class FakeIdaApi:
        BADADDR = -1

    class FakeIdaNalt:
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
                "ida_nalt": FakeIdaNalt(),
                "idaapi": FakeIdaApi(),
            }
            return modules[name]

    result = _run_op("database_info", FakeRuntime(), {})

    assert result["start_ea"] == "0x401000"
    assert result["entry_ea"] == "0x402000"
    assert result["main_ea"] == "0x403000"


def test_xrefs_collect_unique_code_and_data_references() -> None:
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
            del flags
            return (
                XrefRecord(
                    from_ea=0x400FF0,
                    to_ea=0x401004,
                    type="Ordinary_Flow",
                    kind="flow",
                    user=False,
                ),
                XrefRecord(
                    from_ea=0x401000,
                    to_ea=0x401004,
                    type="Code_Near_Call",
                    kind="call",
                    user=False,
                ),
                XrefRecord(
                    from_ea=0x402000,
                    to_ea=0x401004,
                    type="Data_Read",
                    kind="read",
                    user=False,
                ),
            )

    rows = _run_op("xrefs", FakeRuntime(), {"identifier": "target"})

    assert [(row["from"], row["kind"]) for row in rows] == [
        ("0x401000", "call"),
        ("0x400ff0", "flow"),
        ("0x402000", "read"),
    ]


def test_comment_preview_rollback_does_not_repeat_failed_readback() -> None:
    state = {0x401000: "before"}
    reads = 0

    class FakeIdaBytes:
        @staticmethod
        def get_cmt(ea: int, repeatable: bool) -> str:
            nonlocal reads
            assert repeatable is False
            reads += 1
            if reads > 2:
                raise RuntimeError("comment readback failed")
            return state[ea]

        @staticmethod
        def set_cmt(ea: int, text: str, repeatable: bool) -> bool:
            assert repeatable is False
            state[ea] = text
            return True

    class FakeRuntime(IdaRuntime):
        @staticmethod
        def resolve_address(identifier: str) -> int:
            assert identifier in {"main", "0x401000"}
            return 0x401000

        @staticmethod
        def mod(name: str) -> FakeIdaBytes:
            assert name == "ida_bytes"
            return FakeIdaBytes()

    with pytest.raises(RuntimeError, match="comment readback failed"):
        _run_op("comment_set", FakeRuntime(), {"address": "main", "text": "after"}, preview=True)

    assert state == {0x401000: "before"}


def test_type_show_does_not_suppress_type_errors_from_ida() -> None:
    class BrokenType:
        @staticmethod
        def get_type_name() -> str:
            return "Widget"

        @staticmethod
        def get_size() -> int:
            return 4

        @staticmethod
        def _print(_name: str, _flags: int) -> str:
            raise TypeError("broken type printer")

    class FakeIdaTypeInf:
        PRTYPE_TYPE = 0x1
        PRTYPE_DEF = 0x2
        PRTYPE_MULTI = 0x4

    class FakeRuntime(IdaRuntime):
        def __init__(self) -> None:
            super().__init__()

        @staticmethod
        def get_named_type(name: str) -> BrokenType:
            assert name == "Widget"
            return BrokenType()

        @staticmethod
        def classify_tinfo(_tif: object) -> str:
            return "struct"

        @staticmethod
        def mod(name: str) -> FakeIdaTypeInf:
            assert name == "ida_typeinf"
            return FakeIdaTypeInf()

    with pytest.raises(TypeError, match="broken type printer"):
        _run_op("type_show", FakeRuntime(), {"name": "Widget"})


def test_type_declare_diagnostics_ignore_braces_inside_comments_and_strings() -> None:
    class FakeIdaTypeInf:
        HTI_DCL = 0x1
        HTI_SEMICOLON = 0x2
        HTI_TST = 0x4

        @staticmethod
        def parse_decls(_til, _decl: str, _printer, _flags: int) -> int:
            return 1

    class FakeRuntime:
        @staticmethod
        def mod(name: str) -> FakeIdaTypeInf:
            assert name == "ida_typeinf"
            return FakeIdaTypeInf()

    result = _run_op(
        "type_declare_check",
        FakeRuntime(),
        {"decl": 'struct Widget { const char *value; }; const char *text = "{" /* } */'},
    )
    diagnostics = result["diagnostics"]

    assert not any(item["kind"] == "unbalanced_braces" for item in diagnostics)
    assert any(item["kind"] == "unterminated_declaration" for item in diagnostics)


def test_type_declare_clang_reports_unavailable_parser() -> None:
    class FakeIdaTypeInf:
        HTI_DCL = 0x400
        HTI_SEMICOLON = 0x200000

    class FakeIdaSrclang:
        @staticmethod
        def parse_decls_with_parser_ext(_parser_name: str, _til: object, _decl: str, _flags: int) -> int:
            return -1

    class FakeRuntime:
        def mod(self, name: str):
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_srclang":
                return FakeIdaSrclang()
            if name == "ida_undo":
                return _SuccessfulUndo()
            raise AssertionError(name)

        @staticmethod
        def list_named_types() -> list[dict[str, object]]:
            return []

    with pytest.raises(IdaOperationError, match="clang parser is unavailable"):
        _run_op(
            "type_declare",
            FakeRuntime(),
            {"decl": "struct Widget { int value; };", "clang": True},
        )


def test_local_rename_rolls_back_after_readback_failure() -> None:
    mutated = False

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

        @staticmethod
        def locate_lvar(locator: object, func_ea: int, name: str) -> bool:
            assert func_ea == 0x401000
            assert name == "v4"
            locator.defea = func_ea
            locator.location = object()
            return True

        def modify_user_lvar_info(self, func_ea: int, kind: int, info: object) -> bool:
            nonlocal mutated
            assert func_ea == 0x401000
            assert kind == self.MLI_NAME
            assert info.name == "sum_value"
            mutated = True
            return True

        @staticmethod
        def mark_cfunc_dirty(_func_ea: int, _close_views: bool) -> None:
            return None

        @staticmethod
        def clear_cached_cfuncs() -> None:
            return None

        @staticmethod
        def decompile(_func_ea: int):
            if mutated:
                raise RuntimeError("decompiler refresh failed")
            raise AssertionError("name-based selection should not decompile before mutation")

    class FakeRuntime(IdaRuntime):
        class FakeUndo(_SuccessfulUndo):
            @staticmethod
            def perform_undo() -> bool:
                nonlocal mutated
                mutated = False
                return True

        def function_ea(self, identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

        def require_hexrays(self) -> FakeHexrays:
            return FakeHexrays()

        @staticmethod
        def function_name(func_ea: int) -> str:
            assert func_ea == 0x401000
            return "main"

        def mod(self, name: str):
            assert name == "ida_undo"
            return self.FakeUndo()

    with pytest.raises(
        IdaOperationError,
        match="failed to read back locals: decompiler refresh failed",
    ):
        _run_op(
            "local_rename",
            FakeRuntime(),
            {"identifier": "main", "old_name": "v4", "new_name": "sum_value"},
        )

    assert mutated is False


def test_local_rename_rejects_multiple_stable_selector_kinds() -> None:
    with pytest.raises(
        IdaOperationError,
        match="--local-id and --index are mutually exclusive",
    ):
        _run_op(
            "local_rename",
            object(),
            {
                "identifier": "main",
                "new_name": "count",
                "index": 0,
                "local_id": "stack(16)@0x401000",
            },
        )


def test_local_update_allows_unnamed_local_selected_by_stable_selector() -> None:
    class FakeLocation:
        @staticmethod
        def is_stkoff() -> bool:
            return False

        @staticmethod
        def is_reg1() -> bool:
            return True

        @staticmethod
        def is_reg2() -> bool:
            return False

        @staticmethod
        def reg1() -> int:
            return 4

    class FakeLvar:
        def __init__(self) -> None:
            self.name = ""
            self.defea = 0x401000
            self.location = FakeLocation()
            self.tif = object()
            self.is_arg_var = False
            self.width = 4

        @staticmethod
        def is_stk_var() -> bool:
            return False

    class FakeCfunc:
        def get_lvars(self) -> list[FakeLvar]:
            return [FakeLvar()]

    class FakeHexrays:
        MLI_NAME = 1

        def __init__(self, lvar: FakeLvar) -> None:
            self.lvar = lvar

        class lvar_locator_t:
            def __init__(self) -> None:
                self.defea = 0
                self.location = None

        class lvar_saved_info_t:
            def __init__(self) -> None:
                self.ll = None
                self.name = ""
                self.type = None

        class lvar_uservec_t:
            def __init__(self) -> None:
                self.lvvec: list[object] = []

        def decompile(self, func_ea: int) -> FakeCfunc:
            assert func_ea == 0x401000
            cfunc = FakeCfunc()
            cfunc.get_lvars = lambda: [self.lvar]
            return cfunc

        @staticmethod
        def restore_user_lvar_settings(_user_info: object, _func_ea: int) -> bool:
            return False

        def modify_user_lvar_info(self, func_ea: int, kind: int, info: object) -> bool:
            assert func_ea == 0x401000
            assert kind == self.MLI_NAME
            assert info.name == "recovered_name"
            self.lvar.name = info.name
            return True

        @staticmethod
        def mark_cfunc_dirty(_func_ea: int, _close_views: bool) -> None:
            return None

        @staticmethod
        def clear_cached_cfuncs() -> None:
            return None

    class FakeRuntime(IdaRuntime):
        def __init__(self) -> None:
            self.hexrays = FakeHexrays(FakeLvar())

        def function_ea(self, identifier: str) -> int:
            assert identifier == "main"
            return 0x401000

        def require_hexrays(self) -> FakeHexrays:
            return self.hexrays

        @staticmethod
        def function_name(func_ea: int) -> str:
            assert func_ea == 0x401000
            return "main"

        @staticmethod
        def tinfo_decl(_tif: object, *, multi: bool) -> str:
            assert multi is False
            return "int"

        @staticmethod
        def mod(name: str):
            assert name == "ida_undo"
            return _SuccessfulUndo()

    payload = _run_op(
        "local_update",
        FakeRuntime(),
        {"identifier": "main", "index": 0, "new_name": "recovered_name"},
    )

    assert payload["changed"] is True
    assert payload["locals"][0]["name"] == "recovered_name"


def test_local_apply_plan_rejects_unknown_wire_fields() -> None:
    with pytest.raises(IdaOperationError, match="unsupported field"):
        _run_op(
            "local_apply_plan",
            object(),
            {"identifier": "main", "items": [{"index": 3, "type_text": "uint64_t"}]},
        )


def test_proto_check_allows_successful_parse_with_heuristic_unknowns() -> None:
    class FakeTif:
        @staticmethod
        def is_func() -> bool:
            return True

        @staticmethod
        def get_func_details(_details: object, _flags: int) -> bool:
            return True

    tif = FakeTif()
    func_details = object()

    class FakeIdaTypeInf:
        GTD_CALC_ARGLOCS = 0
        PT_SIL = 0x1
        PT_VAR = 0x8
        PT_SEMICOLON = 0x4000

        @staticmethod
        def func_type_data_t() -> object:
            return func_details

        @staticmethod
        def tinfo_t() -> object:
            return tif

        @staticmethod
        def parse_decl(_out_tif: object, _til: object, _decl: str, _flags: int) -> bool:
            return True

    class FakeRuntime(IdaRuntime):
        def function_ea(self, identifier: str) -> int:
            assert identifier == "target"
            return 0x401000

        def mod(self, name: str) -> object:
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            raise AssertionError(name)

        def find_named_type(self, name: str):
            del name
            return None

    result = _run_op(
        "proto_check",
        FakeRuntime(),
        {"identifier": "target", "decl": "void __fastcall target(void (*cb)(int))"},
    )

    assert result["success"] is True
    assert result["parsed"] is True
    assert result["is_function"] is True
    assert result["arglocs_calculated"] is True
    assert result["unknown_types"] == ["cb"]
    assert result["diagnostics"] == []


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
        def parse_decl(_out_tif: object, _til: object, _decl: str, _flags: int) -> bool:
            return True

        @staticmethod
        def apply_tinfo(_ea: int, _parsed_tif: object, _flags: int) -> bool:
            return False

        @staticmethod
        def print_type(_ea: int, _flags: int) -> str:
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
            if name == "ida_undo":
                return _SuccessfulUndo()
            raise AssertionError(name)

        def find_named_type(self, name: str):
            return object()

    with pytest.raises(IdaOperationError, match="apply_tinfo failed"):
        _run_op(
            "proto_set",
            FakeRuntime(),
            {"identifier": "target", "decl": "void __fastcall target(int value)"},
        )


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

        def find_symbols(self, *, pattern: str | None = None, ignore_case: bool = False):
            assert (pattern, ignore_case) == ("CMessaging", True)
            return [
                {"name": "__ZTV10CMessaging", "is_function": False},
                {"name": "__ZN10CMessaging17SendInlineMessageEv", "is_function": True},
            ]

    with pytest.raises(IdaOperationError) as excinfo:
        _run_op("class_hierarchy", FakeRuntime(), {"name": "CMessaging"})
    message = str(excinfo.value)
    assert "exists as a struct, but is not class-materialized" in message
    assert "type class candidates CMessaging" in message


def test_class_vtable_runtime_lookup_uses_requested_alias_when_type_name_missing() -> None:
    class AnonymousClassTif:
        @staticmethod
        def get_type_name() -> str:
            return ""

    class FakeRuntime:
        @staticmethod
        def find_named_type(name: str):
            return AnonymousClassTif() if name == "Alias" else None

        @staticmethod
        def is_class_tinfo(_tif: object) -> bool:
            return True

        @staticmethod
        def get_named_type(_name: str) -> object:
            return object()

        @staticmethod
        def class_vtable_type_name(_tif: object) -> str:
            return "Alias_vtbl"

        @staticmethod
        def class_runtime_vtable_identifier(_tif: object, *, name: str | None = None) -> str | None:
            return "0x402000" if name == "Alias" else None

        @staticmethod
        def tinfo_decl(_tif: object, **_kwargs) -> str:
            return "struct Alias_vtbl"

        @staticmethod
        def vtable_slot(offset_bits: int) -> int:
            return offset_bits // 64

        @staticmethod
        def udt_members(_tif: object) -> list[object]:
            return []

        @staticmethod
        def resolve_address(identifier: str) -> int:
            return int(identifier, 0)

        @staticmethod
        def pointer_size() -> int:
            return 8

        @staticmethod
        def read_pointer(_ea: int) -> int:
            return 0

        @staticmethod
        def demangle_name(_name: str) -> None:
            return None

        @staticmethod
        def mod(name: str):
            class FakeIdaName:
                @staticmethod
                def get_name(_ea: int) -> str:
                    return ""

            class FakeIdaBytes:
                @staticmethod
                def get_flags(_ea: int) -> int:
                    return 0

                @staticmethod
                def is_code(_flags: int) -> bool:
                    return False

            class FakeIdaFuncs:
                @staticmethod
                def get_func(_ea: int) -> None:
                    return None

            return {
                "ida_bytes": FakeIdaBytes(),
                "ida_funcs": FakeIdaFuncs(),
                "ida_name": FakeIdaName(),
            }[name]

    runtime = FakeRuntime()

    payload = _run_op("class_vtable", runtime, {"name": "Alias", "runtime": True})

    assert payload["runtime_vtable"]["identifier"] == "0x402000"
    assert payload["runtime_vtable"]["table_address"] == "0x402000"


def test_class_show_preserves_case_sensitive_name_lookup() -> None:
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

        @staticmethod
        def udt_members(_tif: object) -> tuple[object, ...]:
            return ()

    payload = _run_op("class_show", FakeRuntime(), {"name": "MiXeDClass"})

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

    payload = _run_op("type_show", FakeRuntime(), {"name": "OpaqueThing"})

    assert payload["size"] is None
    assert payload["size_known"] is False


def test_type_deps_uses_local_ordinal_and_dependency_export() -> None:
    class FakeType:
        @staticmethod
        def get_ordinal() -> int:
            return 17

    class FakeTextSink:
        pass

    class FakeIdaTypeInf:
        PDF_INCL_DEPS = 0x1
        PDF_DEF_FWD = 0x2
        text_sink_t = FakeTextSink

        @staticmethod
        def print_decls(sink: object, til: object, ordinals: list[int], flags: int) -> int:
            del til, ordinals, flags
            sink._print("struct Dependency;\nstruct Widget { Dependency *value; };\n")
            return 2

    class FakeRuntime:
        @staticmethod
        def get_named_type(name: str) -> FakeType:
            assert name == "Widget"
            return FakeType()

        @staticmethod
        def classify_tinfo(_tif: object) -> str:
            return "struct"

        @staticmethod
        def mod(name: str) -> FakeIdaTypeInf:
            assert name == "ida_typeinf"
            return FakeIdaTypeInf()

    payload = _run_op("type_deps", FakeRuntime(), {"name": "Widget"})

    assert payload == {
        "name": "Widget",
        "kind": "struct",
        "decl": "struct Dependency;\nstruct Widget { Dependency *value; };",
        "dependencies_included": True,
    }


def test_type_deps_rejects_named_type_without_local_ordinal() -> None:
    class FakeType:
        @staticmethod
        def get_ordinal() -> int:
            return 0

    class FakeRuntime:
        @staticmethod
        def get_named_type(_name: str) -> FakeType:
            return FakeType()

        @staticmethod
        def classify_tinfo(_tif: object) -> str:
            return "struct"

        @staticmethod
        def mod(name: str) -> object:
            assert name == "ida_typeinf"
            return object()

    with pytest.raises(IdaOperationError, match="named type has no local ordinal: Widget"):
        _run_op("type_deps", FakeRuntime(), {"name": "Widget"})


def test_enum_member_rename_rolls_back_after_readback_failure() -> None:
    class FakeEnumTif:
        def __init__(self) -> None:
            self.persisted_name: str | None = None
            self.persisted_names: list[str] = []

        def get_edm(self, name: str) -> tuple[int, object]:
            assert name == "RED"
            return 0, object()

        def rename_edm(self, idx: int, new_name: str) -> int:
            assert idx == 0
            assert new_name == "CRIMSON"
            return 0

        def set_named_type(self, _til, name: str, _flags: int) -> int:
            self.persisted_name = name
            self.persisted_names.append(name)
            return 0

    class FakeIdaTypeInf:
        TERR_OK = 0
        NTF_REPLACE = 1

        @staticmethod
        def tinfo_errstr(code: int) -> str:
            return f"terr={code}"

    tif = FakeEnumTif()

    class FakeRuntime:
        class FakeUndo(_SuccessfulUndo):
            @staticmethod
            def perform_undo() -> bool:
                tif.persisted_name = None
                return True

        def mod(self, name: str):
            if name == "ida_typeinf":
                return FakeIdaTypeInf()
            if name == "ida_undo":
                return self.FakeUndo()
            raise AssertionError(name)

        def get_named_type(self, name: str, *, kind: str):
            assert (name, kind) == ("Color", "enum")
            if tif.persisted_name is not None:
                raise RuntimeError("enum refresh failed")
            return tif

    with pytest.raises(
        IdaOperationError,
        match="persisted named type `Color` but failed to read it back: enum refresh failed",
    ):
        _run_op(
            "enum_member_rename",
            FakeRuntime(),
            {"enum_name": "Color", "member_name": "RED", "new_name": "CRIMSON"},
        )

    assert tif.persisted_names == ["Color"]
    assert tif.persisted_name is None


class _FakeBookmarkPlace:
    def __init__(self, ea: int = 0) -> None:
        self.ea = ea


class _FakeBookmarkLocation:
    def __init__(self) -> None:
        self._place = _FakeBookmarkPlace()

    def set_place(self, place: _FakeBookmarkPlace) -> None:
        self._place = place

    def place(self) -> _FakeBookmarkPlace:
        return self._place


class _FakeBookmarkRuntime:
    def __init__(
        self,
        *,
        max_slot: int,
        bookmarks: dict[int, tuple[int, str]] | None = None,
        fail_read_after_write: bool = False,
    ) -> None:
        self.bookmarks = {} if bookmarks is None else dict(bookmarks)
        self._newly_written: set[int] = set()
        self._fail_read_after_write = fail_read_after_write
        runtime = self

        class FakeBookmarks:
            @staticmethod
            def get(loc: _FakeBookmarkLocation, slot: int, _ud):
                if runtime._fail_read_after_write and slot in runtime._newly_written:
                    raise RuntimeError("bookmark decode failed")
                current = runtime.bookmarks.get(slot)
                if current is None:
                    return None, None
                ea, comment = current
                loc.set_place(_FakeBookmarkPlace(ea))
                return comment, slot

            @staticmethod
            def erase(_loc: _FakeBookmarkLocation, slot: int, _ud) -> bool:
                existed = slot in runtime.bookmarks
                runtime.bookmarks.pop(slot, None)
                runtime._newly_written.discard(slot)
                return existed

        class FakeIdaMoves:
            MAX_MARK_SLOT = max_slot
            bookmarks_t = FakeBookmarks()
            lochist_entry_t = _FakeBookmarkLocation

        class FakePlaceT:
            @staticmethod
            def as_idaplace_t(place: _FakeBookmarkPlace) -> _FakeBookmarkPlace:
                return place

        class FakeIdaKernwin:
            place_t = FakePlaceT

            @staticmethod
            def get_place_class_id(name: str) -> int:
                assert name == "idaplace_t"
                return 1

            @staticmethod
            def get_place_class_template(place_id: int) -> _FakeBookmarkPlace:
                assert place_id == 1
                return _FakeBookmarkPlace()

        class FakeIdaIdc:
            @staticmethod
            def mark_position(ea: int, _lnnum: int, _x: int, _y: int, slot: int, comment: str) -> None:
                runtime.bookmarks[slot] = (ea, comment)
                runtime._newly_written.add(slot)

        self._mods = {
            "ida_idc": FakeIdaIdc(),
            "ida_kernwin": FakeIdaKernwin(),
            "ida_moves": FakeIdaMoves(),
        }

    def mod(self, name: str):
        return self._mods[name]

    @staticmethod
    def resolve_address(identifier: str) -> int:
        return int(identifier, 0)


def test_bookmark_add_reports_full_slot_range() -> None:
    runtime = _FakeBookmarkRuntime(
        max_slot=2,
        bookmarks={
            0: (0x401000, "first"),
            1: (0x401010, "second"),
            2: (0x401020, "third"),
        },
    )

    with pytest.raises(IdaOperationError, match=r"no free bookmark slots remain \(0\.\.2\)"):
        _run_op("bookmark_add", runtime, {"address": "0x401000"})


def test_bookmark_add_preview_rollback_removes_slot_after_runner_readback_failure() -> None:
    runtime = _FakeBookmarkRuntime(max_slot=2, fail_read_after_write=True)

    with pytest.raises(RuntimeError, match="bookmark decode failed"):
        _run_op("bookmark_add", runtime, {"address": "0x401010", "comment": "new"}, preview=True)

    assert runtime.bookmarks == {}
