from __future__ import annotations

from idac.cli.renderers import (
    render_class_vtable,
    render_database_info,
    render_function_list,
    render_function_show,
    render_type_declare,
    render_xrefs,
)


def test_render_database_info_includes_main_start_and_entry_addresses() -> None:
    rendered = render_database_info(
        {
            "path": "/tmp/sample",
            "database_path": "/tmp/sample.i64",
            "module": "sample",
            "processor": "arm",
            "bits": 64,
            "base": "0x100000000",
            "min_ea": "0x100000000",
            "max_ea": "0x100001000",
            "main_ea": "0x100000100",
            "start_ea": "0x100000120",
            "entry_ea": "0x100000200",
        }
    )

    assert "0x100000100" in rendered
    assert "0x100000120" in rendered
    assert "0x100000200" in rendered


def test_render_function_list_uses_render_name_when_present() -> None:
    rendered = render_function_list(
        [
            {
                "address": "0x401000",
                "name": "__ZN3Foo3barEv",
                "display_name": "Foo::bar()",
                "render_name": "Foo::bar()",
                "section": ".text",
            }
        ]
    )

    assert "Foo::bar()" in rendered
    assert "__ZN3Foo3barEv" not in rendered


def test_render_function_show_includes_display_name() -> None:
    rendered = render_function_show(
        {
            "name": "__ZN3Foo3barEv",
            "display_name": "Foo::bar()",
            "address": "0x401000",
            "prototype": "void __fastcall Foo::bar(Foo *this)",
            "size": 32,
            "flags": "0x0",
        }
    )

    assert "__ZN3Foo3barEv" in rendered
    assert "Foo::bar()" in rendered


def test_render_xrefs_includes_normalized_kind_and_raw_type() -> None:
    rendered = render_xrefs(
        [
            {
                "from": "0x401020",
                "to": "0x401000",
                "kind": "call",
                "type": "Code_Near_Call",
                "user": False,
                "function": "main",
            }
        ]
    )

    assert "call" in rendered
    assert "Code_Near_Call" in rendered


def test_render_type_declare_includes_bisect_diagnostics() -> None:
    rendered = render_type_declare(
        {
            "success": False,
            "errors": 1,
            "replace": True,
            "aliases_applied": [{"from": "old", "to": "new", "count": 2}],
            "imported_types": ["alpha"],
            "replaced_types": [],
            "bisect": {
                "supported": True,
                "failing_declaration": {"index": 3, "line": 4, "end_line": 5},
                "blocking_members": [{"type_name": "Missing", "member_name": "value"}],
            },
            "diagnostics": [
                {"kind": "parser_error", "message": "bad token", "line": 4},
                {"kind": "bisect_culprit", "message": "first failing declaration"},
            ],
        }
    )

    assert "Missing" in rendered
    assert "value" in rendered
    assert "bad token" in rendered
    assert "first failing declaration" in rendered


def test_render_class_vtable_includes_runtime_section() -> None:
    class_rendered = render_class_vtable(
        {
            "name": "Foo",
            "vtable_type": "Foo_vtbl",
            "decl": "struct Foo_vtbl;",
            "members": [{"slot": 0, "name": "f0", "type": "void (*)()"}],
            "runtime_vtable": {
                "symbol": "__ZTV3Foo",
                "table_address": "0x1000",
                "members": [{"slot": 0, "name": "sub_100"}],
            },
        }
    )
    assert "Foo_vtbl" in class_rendered
    assert "__ZTV3Foo" in class_rendered
    assert "0x1000" in class_rendered
    assert "sub_100" in class_rendered
