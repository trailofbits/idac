from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest

from idac.cli2.commands import (
    bookmark,
    comment,
    common,
    database,
    function,
    python_exec,
    search,
    segment,
    top_level,
    type_commands,
)


def test_local_update_params_prefers_stable_selector_without_positional_selector() -> None:
    args = argparse.Namespace(
        function="main",
        selector=None,
        local_id="stack(-16)@0x401000",
        index=None,
        rename="sum_value",
        decl="unsigned int sum_value;",
        decl_file=None,
    )

    assert common.local_update_params(args) == {
        "identifier": "main",
        "local_id": "stack(-16)@0x401000",
        "new_name": "sum_value",
        "decl": "unsigned int sum_value;",
    }


def test_local_rename_params_accepts_index_without_positional_selector() -> None:
    args = argparse.Namespace(
        function="main",
        selector=None,
        local_id=None,
        index="4",
        new_name="msgBufferPtr",
    )

    assert common.local_rename_params(args) == {
        "identifier": "main",
        "index": 4,
        "new_name": "msgBufferPtr",
    }


def test_local_rename_params_accepts_positional_selector_and_name() -> None:
    args = argparse.Namespace(
        function="main",
        selector="v4",
        local_id=None,
        index=None,
        new_name="msgBufferPtr",
    )

    assert common.local_rename_params(args) == {
        "identifier": "main",
        "old_name": "v4",
        "new_name": "msgBufferPtr",
    }


def test_local_retype_params_accepts_local_id_without_positional_selector() -> None:
    args = argparse.Namespace(
        function="main",
        selector=None,
        local_id="stack(-16)@0x401000",
        index=None,
        decl="unsigned int msgBufferPtr;",
        decl_file=None,
        type_text=None,
    )

    assert common.local_retype_params(args) == {
        "identifier": "main",
        "local_id": "stack(-16)@0x401000",
        "decl": "unsigned int msgBufferPtr;",
    }


def test_local_retype_params_accepts_type_shorthand() -> None:
    args = argparse.Namespace(
        function="main",
        selector="v4",
        local_id=None,
        index=None,
        decl=None,
        decl_file=None,
        type_text="unsigned int",
    )

    assert common.local_retype_params(args) == {
        "identifier": "main",
        "local_name": "v4",
        "decl": "unsigned int __idac_local;",
    }


def test_local_rename_params_rejects_missing_selector() -> None:
    args = argparse.Namespace(
        function="main",
        selector=None,
        local_id=None,
        index=None,
        new_name="msgBufferPtr",
    )

    with pytest.raises(common.CliUserError, match="local selector is required via selector, --local-id, or --index"):
        common.local_rename_params(args)


def test_local_rename_params_rejects_positional_selector_with_stable_selector() -> None:
    args = argparse.Namespace(
        function="main",
        selector="v4",
        local_id=None,
        index="4",
        new_name="msgBufferPtr",
    )

    with pytest.raises(common.CliUserError, match="do not combine a positional selector with --local-id or --index"):
        common.local_rename_params(args)


def test_local_retype_params_rejects_multiple_stable_selectors() -> None:
    args = argparse.Namespace(
        function="main",
        selector=None,
        local_id="stack(-16)@0x401000",
        index="4",
        decl="unsigned int msgBufferPtr;",
        decl_file=None,
        type_text=None,
    )

    with pytest.raises(common.CliUserError, match="--local-id and --index are mutually exclusive"):
        common.local_retype_params(args)


def test_local_retype_params_rejects_positional_selector_with_stable_selector() -> None:
    args = argparse.Namespace(
        function="main",
        selector="v4",
        local_id=None,
        index="4",
        decl="unsigned int msgBufferPtr;",
        decl_file=None,
        type_text=None,
    )

    with pytest.raises(common.CliUserError, match="do not combine a positional selector with --local-id or --index"):
        common.local_retype_params(args)


def test_local_update_params_rejects_multiple_stable_selectors() -> None:
    args = argparse.Namespace(
        function="main",
        selector=None,
        local_id="stack(-16)@0x401000",
        index="4",
        rename="sum_value",
        decl="unsigned int sum_value;",
        decl_file=None,
    )

    with pytest.raises(common.CliUserError, match="--local-id and --index are mutually exclusive"):
        common.local_update_params(args)


def test_local_update_params_rejects_positional_selector_with_stable_selector() -> None:
    args = argparse.Namespace(
        function="main",
        selector="v4",
        local_id=None,
        index="4",
        rename="sum_value",
        decl="unsigned int sum_value;",
        decl_file=None,
    )

    with pytest.raises(common.CliUserError, match="do not combine a positional selector with --local-id or --index"):
        common.local_update_params(args)


def test_decompilemany_request_captures_modes(tmp_path: Path) -> None:
    args = argparse.Namespace(
        patterns=["demo"],
        file=None,
        out_file=None,
        out_dir=tmp_path / "out",
        regex=True,
        ignore_case=False,
        no_cache=True,
    )

    request = top_level._decompilemany_request(args)

    assert request.pattern == "demo"
    assert request.out_dir == tmp_path / "out"
    assert request.regex is True
    assert request.no_cache is True


def test_decompilemany_request_captures_extra_positionals(tmp_path: Path) -> None:
    args = argparse.Namespace(
        patterns=["main", "add", "sub_1000"],
        file=None,
        out_file=None,
        out_dir=tmp_path / "out",
        regex=False,
        ignore_case=False,
        no_cache=False,
    )

    request = top_level._decompilemany_request(args)

    assert request.pattern == "main"
    assert request.extra_patterns == ("add", "sub_1000")


def test_python_exec_request_reads_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    args = argparse.Namespace(code=None, stdin=True, script=None, persist=True)
    monkeypatch.setattr("sys.stdin", io.StringIO("print('hi')\n"))

    request = python_exec._python_exec_request(args)

    assert request.script == "print('hi')\n"
    assert request.to_params() == {"script": "print('hi')\n", "persist": True}


def test_strings_request_switches_between_scan_and_pattern_modes() -> None:
    pattern_args = argparse.Namespace(
        pattern="hello",
        segment="__TEXT",
        start=None,
        end=None,
        regex=False,
        ignore_case=True,
        scan=False,
    )
    scan_args = argparse.Namespace(
        pattern="needle",
        segment="__TEXT",
        start="0x1000",
        end="0x2000",
        regex=False,
        ignore_case=False,
        scan=True,
    )

    pattern_request = search._strings_request(pattern_args)
    scan_request = search._strings_request(scan_args)

    assert pattern_request.to_params() == {
        "pattern": "hello",
        "regex": False,
        "ignore_case": True,
        "segment": "__TEXT",
    }
    assert scan_request.to_params() == {
        "pattern": "needle",
        "regex": False,
        "ignore_case": False,
        "segment": "__TEXT",
        "scan": True,
        "start": "0x1000",
        "end": "0x2000",
    }


def test_strings_request_rejects_scan_bounds_without_scan_flag() -> None:
    args = argparse.Namespace(
        pattern="needle",
        segment="__TEXT",
        start="0x1000",
        end="0x2000",
        regex=False,
        ignore_case=False,
        scan=False,
    )

    with pytest.raises(common.CliUserError, match="`--start` and `--end` are only valid with `search strings --scan`"):
        search._strings_request(args)


def test_search_bytes_request_includes_segment_scope() -> None:
    args = argparse.Namespace(
        pattern="74 69 6e 79",
        segment="__TEXT",
        limit=25,
        start="0x1000",
        end="0x2000",
    )

    assert search._bytes_request(args).to_params() == {
        "pattern": "74 69 6e 79",
        "segment": "__TEXT",
        "limit": 25,
        "start": "0x1000",
        "end": "0x2000",
    }


def test_function_list_params_include_regex_flag_and_optional_segment() -> None:
    args = argparse.Namespace(
        pattern="GlobalHEIFInfo|HEIFGroupItem",
        query=None,
        regex=True,
        ignore_case=False,
        segment="__TEXT",
        limit=25,
        demangle=True,
    )

    assert function._list_params(args) == {
        "pattern": "GlobalHEIFInfo|HEIFGroupItem",
        "regex": True,
        "ignore_case": False,
        "demangle": True,
        "segment": "__TEXT",
        "limit": 25,
    }


def test_function_list_params_accept_query_alias() -> None:
    args = argparse.Namespace(
        pattern=None,
        query="PNG",
        regex=False,
        ignore_case=True,
        segment=None,
        limit=None,
        demangle=False,
    )

    assert function._list_params(args) == {
        "pattern": "PNG",
        "regex": False,
        "ignore_case": True,
        "demangle": False,
    }


def test_segment_list_request_includes_pattern_flags() -> None:
    args = argparse.Namespace(pattern="__TEXT|__cstring", regex=True, ignore_case=True)

    assert segment._list_request(args).to_params() == {
        "pattern": "__TEXT|__cstring",
        "regex": True,
        "ignore_case": True,
    }


def test_type_declare_request_builds_aliases_and_flags() -> None:
    args = argparse.Namespace(
        decl="typedef int OLD;",
        decl_file=None,
        replace=True,
        alias=["OLD=NEW"],
        bisect=True,
        clang=True,
    )

    request = type_commands._type_declare_request(args)

    assert request.to_params() == {
        "decl": "typedef int OLD;",
        "replace": True,
        "aliases": [{"from": "OLD", "to": "NEW"}],
        "bisect": True,
        "clang": True,
    }


def test_prototype_set_params_omit_default_caller_propagation() -> None:
    args = argparse.Namespace(
        function="add",
        decl="void __fastcall add(int value);",
        decl_file=None,
        propagate_callers=False,
        _preview_wrapper=False,
    )

    assert function._prototype_set_params(args) == {"identifier": "add", "decl": "void __fastcall add(int value);"}


def test_prototype_set_params_include_opt_in_for_caller_propagation() -> None:
    args = argparse.Namespace(
        function="add",
        decl="void __fastcall add(int value);",
        decl_file=None,
        propagate_callers=True,
        _preview_wrapper=False,
    )

    assert function._prototype_set_params(args) == {
        "identifier": "add",
        "decl": "void __fastcall add(int value);",
        "propagate_callers": True,
    }


def test_bookmark_and_database_request_builders_omit_optional_fields() -> None:
    bookmark_args = argparse.Namespace(slot="3", identifier="main", comment=None)
    save_args = argparse.Namespace(path=None)

    assert bookmark._bookmark_set_request(bookmark_args).to_params() == {"slot": 3, "address": "main"}
    assert database._database_save_request(save_args).to_params() == {}


def test_comment_request_builders_capture_scope_and_repeatable() -> None:
    lookup_args = argparse.Namespace(identifier="main", repeatable=True, scope="function")
    anterior_args = argparse.Namespace(identifier="main", repeatable=False, scope="anterior")
    change_args = argparse.Namespace(identifier="main", text="entry", repeatable=False, scope="posterior")

    assert comment._comment_lookup_request(lookup_args).to_params() == {
        "address": "main",
        "scope": "function",
        "repeatable": True,
    }
    assert comment._comment_lookup_request(anterior_args).to_params() == {
        "address": "main",
        "scope": "anterior",
    }
    assert comment._comment_change_request(change_args).to_params() == {
        "address": "main",
        "text": "entry",
        "scope": "posterior",
    }


def test_comment_request_builders_reject_repeatable_extra_comments() -> None:
    args = argparse.Namespace(identifier="main", repeatable=True, scope="anterior")

    with pytest.raises(common.CliUserError, match="--repeatable is only valid for line or function comments"):
        comment._comment_lookup_request(args)
