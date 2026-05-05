from __future__ import annotations

from idac.cli2.renderers import (
    render_bookmarks,
    render_class_vtable,
    render_database_info,
    render_function_frame,
    render_function_list,
    render_function_show,
    render_segment_list,
    render_target_list,
    render_type_declare,
    render_vtable_dump,
    render_workspace_init,
    render_xrefs,
    renderer_registry_drift,
)


def test_render_target_list_formats_active_targets() -> None:
    rendered = render_target_list(
        [
            {
                "selector": "target:active",
                "module": "tiny",
                "instance_pid": 1234,
                "active": True,
            }
        ]
    )

    assert rendered == "target:active [active] (tiny, pid=1234)"


def test_render_function_frame_formats_member_suffixes() -> None:
    rendered = render_function_frame(
        {
            "function": "main",
            "address": "0x401000",
            "frame_size": 32,
            "members": [
                {
                    "offset": -8,
                    "kind": "local",
                    "name": "sum",
                    "type": "int",
                    "fp_offset": -16,
                    "is_special": True,
                }
            ],
        }
    )

    assert rendered.splitlines() == [
        "main @ 0x401000",
        "frame_size: 32",
        "members:",
        "      -8  local    sum  int  [fp=-16, special]",
    ]


def test_render_bookmarks_formats_single_value_as_row() -> None:
    rendered = render_bookmarks(
        {
            "slot": 2,
            "present": True,
            "address": "0x401000",
            "comment": "entry",
        }
    )

    assert rendered == "2  0x401000  entry"


def test_render_database_info_includes_start_and_entry_addresses() -> None:
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
            "start_ea": "0x100000120",
            "entry_ea": "0x100000200",
        }
    )

    assert rendered.splitlines() == [
        "path: /tmp/sample",
        "database_path: /tmp/sample.i64",
        "module: sample",
        "processor: arm",
        "bits: 64",
        "base: 0x100000000",
        "min_ea: 0x100000000",
        "max_ea: 0x100001000",
        "start_ea: 0x100000120",
        "entry_ea: 0x100000200",
    ]


def test_render_segment_list_formats_ranges() -> None:
    rendered = render_segment_list(
        [
            {
                "name": "__TEXT:__text",
                "start": "0x1000",
                "end": "0x2000",
                "size": 4096,
            }
        ]
    )

    assert rendered == "__TEXT:__text  0x1000-0x2000 size=4096"


def test_render_function_list_uses_render_name_when_present() -> None:
    rendered = render_function_list(
        [
            {
                "address": "0x401000",
                "name": "__ZN3Foo3barEv",
                "display_name": "Foo::bar()",
                "render_name": "Foo::bar()",
                "type": "thunk",
            }
        ]
    )

    assert rendered == "0x401000  thunk   Foo::bar()"


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

    assert rendered.splitlines() == [
        "__ZN3Foo3barEv @ 0x401000",
        "display_name: Foo::bar()",
        "prototype: void __fastcall Foo::bar(Foo *this)",
        "size: 32",
        "flags: 0x0",
    ]


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

    assert rendered == "0x401020 | 0x401000 | call | Code_Near_Call | main"


def test_render_type_declare_formats_bisect_and_diagnostics() -> None:
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

    assert rendered.splitlines() == [
        "success: False",
        "errors: 1",
        "replace: True",
        "aliases: old->new x2",
        "imported: alpha",
        "replaced: none",
        "bisect: declaration #3 at lines 4-5",
        "blocking members: Missing value",
        "diagnostics:",
        "- line 4: bad token",
        "- first failing declaration",
    ]


def test_render_class_vtable_and_vtable_dump_include_sections() -> None:
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
    dump_rendered = render_vtable_dump(
        {
            "symbol": "__ZTV3Foo",
            "abi": "itanium",
            "table_address": "0x1000",
            "slot_address": "0x1010",
            "header": [{"index": 0, "name": "offset_to_top", "value": "0x0"}],
            "members": [{"slot": 0, "target": "0x2000", "name": "sub_2000"}],
            "stop_reason": "null_target",
        }
    )

    assert class_rendered.splitlines() == [
        "Foo  vtable=Foo_vtbl",
        "struct Foo_vtbl;",
        "members:",
        "       0  f0  void (*)()",
        "runtime:",
        "  symbol: __ZTV3Foo @ 0x1000",
        "       0  sub_100",
    ]
    assert dump_rendered.splitlines() == [
        "__ZTV3Foo  abi=itanium",
        "table: 0x1000",
        "slots: 0x1010",
        "header:",
        "  0: offset_to_top = 0x0",
        "members:",
        "       0  0x2000  sub_2000",
        "stop_reason: null_target",
    ]


def test_render_workspace_init_lists_created_directories_and_files() -> None:
    rendered = render_workspace_init(
        {
            "display_destination": "workspace",
            "created": [
                ".claude/",
                ".claude/settings.json",
                "reference/",
                "reference/cli.md",
                ".idac/",
                ".idac/tmp/",
            ],
            "git": {"initialized": True},
            "next_steps": [],
        }
    )

    assert rendered.splitlines() == [
        "Created workspace/",
        "  .claude/",
        "  .claude/settings.json",
        "  reference/",
        "  reference/cli.md",
        "  .idac/",
        "  .idac/tmp/",
        "Initialized git repository.",
    ]


def test_renderer_registry_stays_in_sync_with_supported_operations() -> None:
    missing, extra = renderer_registry_drift()

    assert missing == []
    assert extra == []
