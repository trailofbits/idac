from __future__ import annotations

from pathlib import Path

from tests.helpers import run_idalib_json


def _declare_handler_types(idac_cmd: list[str], idac_env: dict[str, str], database: Path, decl_file: Path) -> None:
    payload = run_idalib_json(
        idac_cmd, idac_env, database, ["type", "declare", "--replace", "--decl-file", str(decl_file)]
    )
    assert isinstance(payload, dict)
    assert payload.get("success") is True


def test_idalib_class_list_and_show_from_fixture(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    handler_hierarchy_stripped_database: Path,
    handler_hierarchy_types: Path,
) -> None:
    database = copy_database(handler_hierarchy_stripped_database)
    _declare_handler_types(idac_cmd, idac_env, database, handler_hierarchy_types)

    list_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "class", "list", "Handler"])
    assert isinstance(list_payload, list)
    names = {item.get("name") for item in list_payload if isinstance(item, dict)}
    assert {"Handler", "Handler_Text", "Handler_Stream", "LegacyGroup__Handler_Pack"} <= names

    show_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "class", "show", "Handler_Stream"])
    assert isinstance(show_payload, dict)
    assert show_payload.get("name") == "Handler_Stream"
    assert show_payload.get("kind") == "class"
    assert show_payload.get("bases") == ["Handler"]
    member_names = {member.get("name") for member in show_payload.get("members") or []}
    assert {"primary_hits", "bytes_remaining", "has_result"} <= member_names


def test_idalib_class_hierarchy_fields_and_vtable_from_fixture(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    handler_hierarchy_stripped_database: Path,
    handler_hierarchy_types: Path,
) -> None:
    database = copy_database(handler_hierarchy_stripped_database)
    _declare_handler_types(idac_cmd, idac_env, database, handler_hierarchy_types)

    hierarchy_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "class", "hierarchy", "Handler"])
    assert isinstance(hierarchy_payload, dict)
    derived = set(hierarchy_payload.get("derived") or [])
    assert {"Handler_Text", "Handler_Stream", "LegacyGroup__Handler_Pack"} <= derived

    derived_fields = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "class", "fields", "Handler_Stream", "--derived-only"],
    )
    assert isinstance(derived_fields, dict)
    derived_names = {field.get("name") for field in derived_fields.get("fields") or []}
    assert {
        "primary_hits",
        "secondary_hits",
        "retry_hits",
        "bytes_remaining",
    } <= derived_names
    assert "category_names" not in derived_names

    vtable_payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "class", "vtable", "Handler_Stream"])
    assert isinstance(vtable_payload, dict)
    assert vtable_payload.get("vtable_type") == "Handler_Stream_vtbl"
    member_names = {member.get("name") for member in vtable_payload.get("members") or []}
    assert {
        "acceptBuffer",
        "computeCount",
        "refreshState",
        "createWorker1",
        "createWorker2",
    } <= member_names


def test_idalib_type_declare_replace_with_fixture_class_header(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    handler_hierarchy_stripped_database: Path,
    handler_hierarchy_types: Path,
) -> None:
    database = copy_database(handler_hierarchy_stripped_database)
    _declare_handler_types(idac_cmd, idac_env, database, handler_hierarchy_types)
    replace_decl = handler_hierarchy_types.read_text(encoding="utf-8").replace(
        "bool has_result;",
        "bool has_result;\n  unsigned debug_cookie;",
    )

    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "declare", "--replace", "--decl", replace_decl],
    )
    assert isinstance(payload, dict)
    assert payload.get("success") is True
    replaced = set(payload.get("replaced_types") or [])
    assert "Handler_Stream" in replaced

    fields_payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "class", "fields", "Handler_Stream", "--derived-only"],
    )
    assert isinstance(fields_payload, dict)
    field_names = {field.get("name") for field in fields_payload.get("fields") or []}
    assert "debug_cookie" in field_names


def test_idalib_class_candidates_finds_symbols_in_unstripped_fixture(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    handler_hierarchy_database: Path,
) -> None:
    database = copy_database(handler_hierarchy_database)
    payload = run_idalib_json(idac_cmd, idac_env, database, ["type", "class", "candidates", "Handler_Stream"])
    assert isinstance(payload, list)
    kinds_and_names = {(item.get("kind"), item.get("name")) for item in payload if isinstance(item, dict)}
    assert ("vtable_symbol", "__ZTV14Handler_Stream") in kinds_and_names
    assert ("function_symbol", "__ZN14Handler_Stream12acceptBufferEPKhmPKcj") in kinds_and_names


def test_idalib_class_candidates_kind_filter_limits_results(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    handler_hierarchy_database: Path,
) -> None:
    database = copy_database(handler_hierarchy_database)
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        [
            "type",
            "class",
            "candidates",
            "Handler_Stream",
            "--kind",
            "function_symbol",
        ],
    )
    assert isinstance(payload, list)
    assert payload
    assert all(item.get("kind") == "function_symbol" for item in payload if isinstance(item, dict))
    names = {item.get("name") for item in payload if isinstance(item, dict)}
    assert "__ZN14Handler_Stream12acceptBufferEPKhmPKcj" in names
    assert "__ZTV14Handler_Stream" not in names


def test_idalib_class_vtable_runtime_includes_raw_targets(
    idac_cmd: list[str],
    idac_env: dict[str, str],
    copy_database,
    handler_hierarchy_database: Path,
    handler_hierarchy_types: Path,
) -> None:
    database = copy_database(handler_hierarchy_database)
    _declare_handler_types(idac_cmd, idac_env, database, handler_hierarchy_types)
    payload = run_idalib_json(
        idac_cmd,
        idac_env,
        database,
        ["type", "class", "vtable", "Handler_Stream", "--runtime"],
    )
    assert isinstance(payload, dict)
    runtime_vtable = payload.get("runtime_vtable")
    assert isinstance(runtime_vtable, dict)
    assert runtime_vtable.get("symbol") == "__ZTV14Handler_Stream"
    member_names = {member.get("name") for member in runtime_vtable.get("members") or []}
    assert "__ZN14Handler_Stream12refreshStateEiP12HandlerStateiiiPi" in member_names
