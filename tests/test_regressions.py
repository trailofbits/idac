from __future__ import annotations

import builtins
import importlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from idac import doctor
from idac.cli import build_parser
from idac.metadata import WIRE_PROTOCOL_VERSION, bridge_registry_payload
from idac.ops.families import classes
from idac.ops.families.classes import op_class_vtable
from idac.ops.families.type_declare import _apply_type_aliases, _normalize_aliases, _split_declarations
from idac.ops.runtime import IdaOperationError, IdaRuntime
from idac.ops.runtime_classes import find_vtable_symbol
from idac.transport import idalib, idalib_common, idalib_server
from idac.transport.idalib import IdaLibBackend, IdaLibInstance
from idac.transport.schema import RequestEnvelope
from idac.version import VERSION


def _runtime_with_modules(modules: dict[str, object]) -> IdaRuntime:
    runtime = IdaRuntime()
    runtime.mod = lambda name: modules[name]  # type: ignore[method-assign]
    return runtime


def test_runtime_mod_caches_imports(monkeypatch) -> None:
    calls: list[str] = []

    def fake_import_module(name: str) -> object:
        calls.append(name)
        return object()

    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    runtime = IdaRuntime()

    first = runtime.mod("ida_name")
    second = runtime.mod("ida_name")

    assert first is second
    assert calls == ["ida_name"]


def test_runtime_module_attrs_cache_via_mod_override() -> None:
    calls: list[str] = []
    ida_name = object()
    runtime = IdaRuntime()
    runtime.mod = lambda name: (calls.append(name), ida_name)[1]  # type: ignore[method-assign]

    assert runtime.ida_name is ida_name
    assert runtime.ida_name is ida_name
    assert calls == ["ida_name"]


def test_idalib_backend_reports_malformed_json(monkeypatch) -> None:
    instance = IdaLibInstance(
        pid=1234,
        socket_path=Path("/tmp/idac-idalib-1234.sock"),
        registry_path=Path("/tmp/idac-idalib-1234.json"),
        database_path="/tmp/fixture.i64",
        started_at=None,
        meta={},
    )

    monkeypatch.setattr(
        "idac.transport.idalib._ensure_instance_for_database",
        lambda database_path, *, timeout, run_auto_analysis, start_if_missing: (instance, True),
    )
    monkeypatch.setattr(
        "idac.transport.idalib._socket_request",
        lambda socket_path, payload, *, timeout: (_ for _ in ()).throw(
            RuntimeError("idalib daemon returned a non-object JSON payload")
        ),
    )

    with pytest.raises(RuntimeError, match="idalib daemon returned a non-object JSON payload"):
        IdaLibBackend().send(RequestEnvelope(op="database_info", backend="idalib", database="fixture.i64"))


def test_idalib_startup_failure_includes_startup_hint_without_detail() -> None:
    message = idalib._format_startup_failure("/tmp/sample.i64")

    assert "idalib daemon failed to start for `/tmp/sample.i64`" in message
    assert "license validation" in message
    assert "Run `idac doctor`" in message


def test_idalib_startup_failure_preserves_child_detail() -> None:
    message = idalib._format_startup_failure("/tmp/sample.i64", "Cannot continue without a valid license")

    assert message.endswith("Cannot continue without a valid license")


def test_idalib_server_rejects_empty_operation() -> None:
    with pytest.raises(Exception, match="idalib backend requires an operation name"):
        idalib_server._parse_request({"version": WIRE_PROTOCOL_VERSION, "op": "   ", "params": {}})


def test_idalib_server_returns_json_for_expected_operation_failures() -> None:
    service = object.__new__(idalib_server.IdaLibService)
    service.database_path = "/tmp/fixture.i64"
    service.exit_requested = False
    service.list_targets = lambda: []
    service._build_registry = lambda: {"database_info": lambda params: (_ for _ in ()).throw(IdaOperationError("boom"))}

    response = service._dispatch({"version": WIRE_PROTOCOL_VERSION, "op": "database_info", "params": {}})
    assert response["ok"] is False
    assert response["error"] == "boom"


def test_idalib_server_returns_json_for_unexpected_operation_failures() -> None:
    service = object.__new__(idalib_server.IdaLibService)
    service.database_path = "/tmp/fixture.i64"
    service.exit_requested = False
    service.list_targets = lambda: []
    service._build_registry = lambda: {
        "database_info": lambda params: (_ for _ in ()).throw(ModuleNotFoundError("hexrays"))
    }

    response = service._dispatch({"version": WIRE_PROTOCOL_VERSION, "op": "database_info", "params": {}})
    assert response["ok"] is False
    assert "unexpected idalib server failure" in response["error"]
    assert "hexrays" in response["error"]


def test_resolve_address_uses_ida_parser_for_numeric_hex_and_symbols() -> None:
    seen: list[tuple[str, int, int]] = []
    runtime = _runtime_with_modules(
        {
            "idaapi": SimpleNamespace(BADADDR=0xFFFFFFFFFFFFFFFF),
            "ida_kernwin": SimpleNamespace(
                S2EAOPT_NOCALC=0x1,
                str2ea_ex=lambda text, screen_ea, flags: (
                    seen.append((text, screen_ea, flags))
                    or {
                        "100000460": 0x100000460,
                        "main": 0x100000460,
                    }.get(text, 0xFFFFFFFFFFFFFFFF)
                ),
            ),
        }
    )

    assert runtime.resolve_address("100000460") == 0x100000460
    assert runtime.resolve_address("main") == 0x100000460
    assert seen == [
        ("100000460", 0xFFFFFFFFFFFFFFFF, 0x1),
        ("main", 0xFFFFFFFFFFFFFFFF, 0x1),
    ]


def test_resolve_address_raises_for_unknown_identifier() -> None:
    runtime = _runtime_with_modules(
        {
            "idaapi": SimpleNamespace(BADADDR=0xFFFFFFFFFFFFFFFF),
            "ida_kernwin": SimpleNamespace(
                S2EAOPT_NOCALC=0x1,
                str2ea_ex=lambda text, screen_ea, flags: 0xFFFFFFFFFFFFFFFF,
            ),
        }
    )

    with pytest.raises(IdaOperationError, match="symbol not found: missing_symbol"):
        runtime.resolve_address("missing_symbol")


def test_resolve_address_handles_none_from_ida_parser() -> None:
    runtime = _runtime_with_modules(
        {
            "idaapi": SimpleNamespace(BADADDR=0xFFFFFFFFFFFFFFFF),
            "ida_kernwin": SimpleNamespace(
                S2EAOPT_NOCALC=0x1,
                str2ea_ex=lambda text, screen_ea, flags: None,
            ),
        }
    )

    with pytest.raises(IdaOperationError, match="symbol not found: missing_symbol"):
        runtime.resolve_address("missing_symbol")


def test_resolve_segment_ranges_matches_visible_name_prefix_and_suffix() -> None:
    segments = [
        SimpleNamespace(start_ea=0x1000, end_ea=0x1100, visible_name="__TEXT:__text"),
        SimpleNamespace(start_ea=0x2000, end_ea=0x2100, visible_name="__TEXT:__cstring"),
        SimpleNamespace(start_ea=0x3000, end_ea=0x3100, visible_name="__DATA_CONST:__got"),
    ]
    runtime = _runtime_with_modules(
        {
            "ida_segment": SimpleNamespace(
                get_first_seg=lambda: segments[0],
                get_next_seg=lambda ea: next((item for item in segments if item.start_ea > ea), None),
                get_visible_segm_name=lambda seg: seg.visible_name,
            ),
            "ida_ida": SimpleNamespace(
                inf_get_min_ea=lambda: 0x1000,
                inf_get_max_ea=lambda: 0x4000,
            ),
        }
    )
    runtime.resolve_address = lambda text: int(text, 0)  # type: ignore[method-assign]

    prefix_ranges = runtime.resolve_segment_ranges("__TEXT")
    suffix_ranges = runtime.resolve_segment_ranges("__cstring")

    assert [(item.name, item.start_ea, item.end_ea) for item in prefix_ranges] == [
        ("__TEXT:__text", 0x1000, 0x1100),
        ("__TEXT:__cstring", 0x2000, 0x2100),
    ]
    assert [(item.name, item.start_ea, item.end_ea) for item in suffix_ranges] == [
        ("__TEXT:__cstring", 0x2000, 0x2100),
    ]


def test_resolve_segment_ranges_rejects_out_of_database_bounds() -> None:
    segment = SimpleNamespace(start_ea=0x1000, end_ea=0x2000, visible_name="__TEXT:__text")
    runtime = _runtime_with_modules(
        {
            "ida_segment": SimpleNamespace(
                get_first_seg=lambda: segment,
                get_next_seg=lambda ea: None,
                get_visible_segm_name=lambda seg: seg.visible_name,
            ),
            "ida_ida": SimpleNamespace(
                inf_get_min_ea=lambda: 0x1000,
                inf_get_max_ea=lambda: 0x2000,
            ),
        }
    )
    runtime.resolve_address = lambda text: int(text, 0)  # type: ignore[method-assign]

    with pytest.raises(IdaOperationError, match="range start 0xfff is outside database bounds 0x1000-0x2000"):
        runtime.resolve_segment_ranges("__TEXT", start="0xfff")
    with pytest.raises(IdaOperationError, match="range end 0x2001 is outside database bounds 0x1000-0x2000"):
        runtime.resolve_segment_ranges("__TEXT", end="0x2001")


def test_resolve_range_rejects_out_of_database_bounds() -> None:
    runtime = _runtime_with_modules(
        {
            "ida_ida": SimpleNamespace(
                inf_get_min_ea=lambda: 0x1000,
                inf_get_max_ea=lambda: 0x2000,
            ),
        }
    )
    runtime.resolve_address = lambda text: int(text, 0)  # type: ignore[method-assign]

    with pytest.raises(IdaOperationError, match="range start 0xfff is outside database bounds 0x1000-0x2000"):
        runtime.resolve_range(start="0xfff")
    with pytest.raises(IdaOperationError, match="range end 0x2001 is outside database bounds 0x1000-0x2000"):
        runtime.resolve_range(end="0x2001")


def test_resolve_function_falls_back_to_short_demangled_name() -> None:
    runtime = _runtime_with_modules(
        {
            "idaapi": SimpleNamespace(BADADDR=0xFFFFFFFFFFFFFFFF),
            "ida_kernwin": SimpleNamespace(
                S2EAOPT_NOCALC=0x1,
                str2ea_ex=lambda text, screen_ea, flags: 0xFFFFFFFFFFFFFFFF,
            ),
            "idautils": SimpleNamespace(Functions=lambda: [0x100000460]),
            "ida_name": SimpleNamespace(
                GN_DEMANGLED=0x1,
                GN_SHORT=0x2,
                GN_LONG=0x4,
                GN_VISIBLE=0x8,
                get_ea_name=lambda ea, flags=0: (
                    "IIOReadPlugin::optInForBandedDecoding(uchar const*,ulong,char const*,uint)"
                    if flags & 0x2
                    else (
                        "bool IIOReadPlugin::optInForBandedDecoding("
                        "unsigned char const*, unsigned long, char const*, unsigned int)"
                    )
                ),
                demangle_name=lambda text, disable_mask: (
                    "IIOReadPlugin::optInForBandedDecoding(unsigned char const*,unsigned long,char const*,unsigned int)"
                ),
                get_name=lambda ea: "__ZN13IIOReadPlugin23optInForBandedDecodingEv",
            ),
            "ida_funcs": SimpleNamespace(
                get_func=lambda ea: SimpleNamespace(start_ea=ea) if ea == 0x100000460 else None
            ),
        }
    )

    assert int(runtime.resolve_function("IIOReadPlugin::optInForBandedDecoding").start_ea) == 0x100000460


def test_resolve_function_rejects_ambiguous_short_demangled_name() -> None:
    runtime = _runtime_with_modules(
        {
            "idaapi": SimpleNamespace(BADADDR=0xFFFFFFFFFFFFFFFF),
            "ida_kernwin": SimpleNamespace(
                S2EAOPT_NOCALC=0x1,
                str2ea_ex=lambda text, screen_ea, flags: 0xFFFFFFFFFFFFFFFF,
            ),
            "idautils": SimpleNamespace(Functions=lambda: [0x1000, 0x2000]),
            "ida_name": SimpleNamespace(
                GN_DEMANGLED=0x1,
                GN_SHORT=0x2,
                GN_LONG=0x4,
                GN_VISIBLE=0x8,
                get_ea_name=lambda ea, flags=0: (
                    "Foo::bar"
                    if flags & 0x2
                    else {
                        0x1000: "int Foo::bar(int)",
                        0x2000: "double Foo::bar(double)",
                    }[ea]
                ),
                demangle_name=lambda text, disable_mask: text,
                get_name=lambda ea: {
                    0x1000: "__ZN3Foo3barEi",
                    0x2000: "__ZN3Foo3barEd",
                }[ea],
            ),
            "ida_funcs": SimpleNamespace(
                get_func=lambda ea: SimpleNamespace(start_ea=ea) if ea in {0x1000, 0x2000} else None
            ),
        }
    )

    with pytest.raises(IdaOperationError, match="multiple functions matched demangled name"):
        runtime.resolve_function("Foo::bar")


def test_vtable_ea_prefers_ida_metadata() -> None:
    runtime = _runtime_with_modules(
        {
            "idaapi": SimpleNamespace(BADADDR=0xFFFFFFFFFFFFFFFF),
            "ida_typeinf": SimpleNamespace(
                get_vftable_ea=lambda ordinal: {
                    10: 0,
                    11: 0x1234,
                }.get(ordinal, 0),
            ),
        }
    )
    tif = SimpleNamespace(get_ordinal=lambda: 10, get_final_ordinal=lambda: 11)

    assert runtime.vtable_ea(tif) == 0x1234


def test_class_vtable_runtime_prefers_ida_metadata_before_symbol_scan(monkeypatch) -> None:
    class_tif = SimpleNamespace(name="Handler_Stream")
    runtime = SimpleNamespace(
        find_named_type=lambda name: class_tif if name == "Handler_Stream" else None,
        is_class_tinfo=lambda tif: True,
        get_named_type=lambda name: SimpleNamespace(name=name),
        class_vtable_type_name=lambda tif: "Handler_Stream_vtbl",
        class_runtime_vtable_identifier=lambda tif, name=None: "0x401000",
        tinfo_decl=lambda tif, **kwargs: "struct Handler_Stream_vtbl",
        vtable_slot=lambda offset_bits: offset_bits // 64,
        udt_members=lambda tif: [],
    )
    monkeypatch.setattr(
        "idac.ops.families.classes._raw_vtable_dump",
        lambda runtime, identifier, slot_limit=64: {
            "identifier": identifier,
            "slot_limit": slot_limit,
        },
    )

    payload = op_class_vtable(runtime, {"name": "Handler_Stream", "runtime": True})

    assert payload["runtime_vtable"] == {"identifier": "0x401000", "slot_limit": 64}


def test_idalib_server_updates_database_path_after_save() -> None:
    service = object.__new__(idalib_server.IdaLibService)
    service.database_path = "/tmp/old.i64"
    service.exit_requested = False
    service.list_targets = lambda: []
    writes: list[str] = []
    service._write_registry = lambda: writes.append(service.database_path)
    service._validate_db_save = lambda params: "/tmp/new.i64"
    service._build_registry = lambda: {"db_save": lambda params: {"saved": True, "path": "/tmp/new.i64"}}

    response = service._dispatch(
        {"version": WIRE_PROTOCOL_VERSION, "op": "db_save", "params": {"path": "/tmp/new.i64"}}
    )

    assert response["ok"] is True
    normalized = str(Path("/tmp/new.i64").resolve(strict=False))
    assert service.database_path == normalized
    assert writes == [normalized]


def test_idalib_backend_db_close_returns_already_closed_when_database_is_missing() -> None:
    response = IdaLibBackend().send(RequestEnvelope(op="db_close", backend="idalib", database="/tmp/missing.i64"))

    assert response["ok"] is True
    assert response["result"] == {
        "closed": False,
        "database": str(Path("/tmp/missing.i64").resolve(strict=False)),
        "already_closed": True,
    }


def test_cli_and_backend_share_alias_validation_contract() -> None:
    parser = build_parser()
    args = parser.parse_args(["type", "declare", "--decl", "typedef int value_t;", "--alias", "bad"])

    with pytest.raises(ValueError, match="invalid alias `bad`; expected OLD=NEW"):
        _normalize_aliases(args.alias)

    with pytest.raises(ValueError, match="invalid alias `bad`; expected OLD=NEW"):
        _normalize_aliases(["bad"])


def test_apply_type_aliases_preserves_namespace_qualified_names() -> None:
    rewritten, aliases = _apply_type_aliases(
        "struct ns::Foo { Foo inner; };",
        [{"from": "Foo", "to": "Bar"}],
    )

    assert rewritten == "struct ns::Foo { Bar inner; };"
    assert aliases == [{"from": "Foo", "to": "Bar", "count": 1}]


def test_apply_type_aliases_rewrites_globally_qualified_names() -> None:
    rewritten, aliases = _apply_type_aliases(
        "struct Use { ::Foo *global_ptr; Foo value; ns::Foo scoped; };",
        [{"from": "Foo", "to": "Bar"}],
    )

    assert rewritten == "struct Use { ::Bar *global_ptr; Bar value; ns::Foo scoped; };"
    assert aliases == [{"from": "Foo", "to": "Bar", "count": 2}]


def test_parse_vtable_dump_defaults_slot_limit_to_64() -> None:
    request = classes._parse_vtable_dump({"identifier": "0x401000"})

    assert request.identifier == "0x401000"
    assert request.slot_limit == 64


def test_find_vtable_symbol_requires_exact_class_name_match() -> None:
    class FakeRuntime:
        @staticmethod
        def iter_names():
            return iter(
                [
                    (0x1000, "__ZTV6FooBar", "vtable for FooBar"),
                    (0x2000, "__ZTV3Foo", "vtable for Foo"),
                ]
            )

    result = find_vtable_symbol(FakeRuntime(), "Foo")

    assert result == {
        "address": "0x2000",
        "name": "__ZTV3Foo",
        "demangled": "vtable for Foo",
    }


def test_find_vtable_symbol_accepts_msvc_vftable_demangling() -> None:
    class FakeRuntime:
        @staticmethod
        def iter_names():
            return iter(
                [
                    (0x1000, "??_7Foo@@6B@", "FooBar::`vftable'"),
                    (0x2000, "??_7Bar@@6B@", "Foo::`vftable'"),
                ]
            )

    result = find_vtable_symbol(FakeRuntime(), "Foo")

    assert result == {
        "address": "0x2000",
        "name": "??_7Bar@@6B@",
        "demangled": "Foo::`vftable'",
    }


def test_flatten_class_fields_propagates_inherited_base_offsets() -> None:
    base = _NamedTif(
        "Base",
        [
            SimpleNamespace(
                name="base_value",
                offset=32,
                size=32,
                type=_NamedTif("int"),
            )
        ],
    )
    derived = _NamedTif(
        "Derived",
        [
            SimpleNamespace(
                name="Base",
                offset=64,
                size=0,
                type=_NamedTif("Base"),
                is_baseclass=True,
            ),
            SimpleNamespace(
                name="derived_value",
                offset=128,
                size=32,
                type=_NamedTif("int"),
            ),
        ],
    )

    class FakeRuntime:
        @staticmethod
        def udt_members(tif):
            udt: list[object] = []
            tif.get_udt_details(udt)
            return udt

        @staticmethod
        def member_has(member, attr: str) -> bool:
            value = getattr(member, attr, False)
            return bool(value() if callable(value) else value)

        @staticmethod
        def find_named_type(name: str, kind=None):
            del kind
            return {"Base": base}.get(name)

        @staticmethod
        def tinfo_decl(tif, *, name=None, multi=False) -> str:
            del name, multi
            return tif.dstr()

    fields = classes._flatten_class_fields(FakeRuntime(), derived, derived_only=False)

    assert [(field["name"], field["offset"]) for field in fields] == [
        ("base_value", 12),
        ("derived_value", 16),
    ]


def test_bridge_registry_payload_emits_fixed_contract_fields() -> None:
    payload = bridge_registry_payload(pid=7, socket_path="/tmp/idac.sock", started_at="now")

    assert payload == {
        "pid": 7,
        "socket_path": "/tmp/idac.sock",
        "plugin_name": "idac_bridge",
        "plugin_version": VERSION,
        "started_at": "now",
        "backend": "gui",
    }


def test_doctor_reports_broken_plugin_symlink(monkeypatch, tmp_path: Path) -> None:
    source_dir = tmp_path / "plugin-src"
    source_dir.mkdir()
    bootstrap_source = tmp_path / "idac_bridge_plugin.py"
    bootstrap_source.write_text("# bootstrap\n", encoding="utf-8")

    install_dir = tmp_path / "plugins" / "idac_bridge"
    install_dir.parent.mkdir(parents=True)
    install_dir.symlink_to(tmp_path / "missing-plugin", target_is_directory=True)

    install_bootstrap = tmp_path / "plugins" / "idac_bridge_plugin.py"
    install_bootstrap.symlink_to(bootstrap_source)

    monkeypatch.setattr(doctor, "plugin_source_dir", lambda: source_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_source_path", lambda: bootstrap_source)
    monkeypatch.setattr(doctor, "plugin_install_dir", lambda: install_dir)
    monkeypatch.setattr(doctor, "plugin_bootstrap_install_path", lambda: install_bootstrap)
    monkeypatch.setattr(doctor, "user_runtime_dir", lambda: tmp_path / "runtime")
    monkeypatch.setattr(doctor, "bridge_registry_paths", lambda: [])
    monkeypatch.setattr(doctor.gui, "list_instances", lambda: [])
    monkeypatch.setattr(doctor.gui, "list_targets", lambda timeout=None, warnings=None: [])

    result = doctor.run_doctor(scope="gui", timeout=1.0)

    plugin_package = next(item for item in result["checks"] if item["name"] == "plugin_package")
    assert plugin_package["status"] == "error"
    assert "missing install path" in plugin_package["summary"]


def test_split_declarations_exits_block_comment_mode() -> None:
    chunks = _split_declarations("struct A { int x; }; /* comment */ struct B { int y; };")

    assert [chunk["text"] for chunk in chunks] == [
        "struct A { int x; };",
        "/* comment */ struct B { int y; };",
    ]


class _FakeIdaTypeinf:
    PRTYPE_TYPE = 1
    PRTYPE_DEF = 2
    PRTYPE_MULTI = 4
    PRTYPE_1LINE = 8

    @staticmethod
    def udt_type_data_t() -> list[object]:
        return []


class _BrokenAnonymousTif:
    def get_type_name(self) -> str:
        return ""

    def _print(self, *_args, **_kwargs) -> str:
        raise RuntimeError("print failed")

    def dstr(self) -> str:
        raise RuntimeError("dstr failed")


class _NamedTif:
    def __init__(self, name: str, members: list[object] | None = None) -> None:
        self._name = name
        self._members = list(members or [])

    def get_type_name(self) -> str:
        return self._name

    def _print(self, *_args, **_kwargs) -> str:
        return self._name

    def dstr(self) -> str:
        return self._name

    def get_udt_details(self, udt: list[object]) -> bool:
        udt.extend(self._members)
        return True


class _PointerType:
    def __init__(self, pointed) -> None:
        self._pointed = pointed

    def get_pointed_object(self):
        return self._pointed


def test_tinfo_members_falls_back_to_unknown_for_unrenderable_anonymous_types() -> None:
    runtime = IdaRuntime()
    runtime.mod = lambda name: _FakeIdaTypeinf() if name == "ida_typeinf" else None  # type: ignore[method-assign]

    container = _NamedTif(
        "Container",
        [
            SimpleNamespace(
                name="field",
                offset=0,
                size=0,
                type=_BrokenAnonymousTif(),
                cmt="",
            )
        ],
    )

    members = runtime.tinfo_members(container)

    assert members[0]["type"] == "<unknown>"


def test_class_vtable_type_name_skips_unknown_pointed_type_and_uses_base_fallback(
    monkeypatch,
) -> None:
    runtime = IdaRuntime()
    runtime.mod = lambda name: _FakeIdaTypeinf() if name == "ida_typeinf" else None  # type: ignore[method-assign]

    derived = _NamedTif(
        "Derived",
        [
            SimpleNamespace(
                name="__vftable",
                type=_PointerType(_BrokenAnonymousTif()),
                is_vftable=lambda: True,
            ),
            SimpleNamespace(
                name="Base",
                type=_NamedTif("Base"),
                is_baseclass=lambda: True,
            ),
        ],
    )
    base = _NamedTif("Base")
    known_types = {
        "Base": base,
        "Base_vtbl": SimpleNamespace(),
    }
    monkeypatch.setattr(runtime, "find_named_type", lambda name, kind=None: known_types.get(name))

    assert runtime.class_vtable_type_name(derived) == "Base_vtbl"


@pytest.mark.parametrize("exc_type", [RuntimeError, ValueError])
def test_bootstrap_idapro_retries_candidate_installs_on_runtime_import_errors(
    monkeypatch, tmp_path: Path, exc_type: type[Exception]
) -> None:
    bad_root = tmp_path / "bad"
    good_root = tmp_path / "good"
    bad_python = bad_root / "idalib" / "python"
    good_python = good_root / "idalib" / "python"
    bad_python.mkdir(parents=True)
    good_python.mkdir(parents=True)

    imported_module = SimpleNamespace(name="idapro")
    attempts: list[str] = []
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name != "idapro":
            return real_import(name, globals, locals, fromlist, level)
        attempts.append(sys.path[0] if sys.path else "")
        if sys.path and sys.path[0] == str(good_python):
            return imported_module
        raise exc_type("broken idapro")

    fake_environ = dict(os.environ)
    fake_environ.pop("IDADIR", None)
    monkeypatch.setattr(idalib_common, "candidate_ida_dirs", lambda: [bad_root, good_root])
    monkeypatch.setattr(idalib_common.os, "environ", fake_environ)
    monkeypatch.delitem(sys.modules, "idapro", raising=False)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = idalib_common.bootstrap_idapro()

    assert result is imported_module
    assert str(bad_python) in attempts
    assert str(good_python) in attempts


def test_candidate_ida_dirs_reads_ida_config_after_explicit_env(monkeypatch, tmp_path: Path) -> None:
    explicit_root = tmp_path / "explicit"
    configured_root = tmp_path / "configured"
    fallback_root = tmp_path / "fallback"
    idausr = tmp_path / ".idapro"
    idausr.mkdir()
    (idausr / "ida-config.json").write_text(
        json.dumps({"Paths": {"ida-install-dir": str(configured_root)}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("IDAUSR", str(idausr))
    monkeypatch.setenv("IDAC_IDA_INSTALL_DIR", str(explicit_root))
    monkeypatch.delenv("IDADIR", raising=False)
    monkeypatch.setattr(idalib_common, "default_ida_install_dirs", lambda: [configured_root, fallback_root])

    assert idalib_common.candidate_ida_dirs() == [explicit_root, configured_root, fallback_root]
