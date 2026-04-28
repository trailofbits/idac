from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ...ops.manifest import SUPPORTED_OPERATIONS

Renderer = Callable[[Any], str]

_RENDERER_NAMES = {
    "doctor": "render_doctor",
    "docs": "render_lines",
    "targets_cleanup": "render_targets_cleanup",
    "list_targets": "render_target_list",
    "database_info": "render_database_info",
    "db_save": "_fallback",
    "segment_list": "render_segment_list",
    "function_list": "render_function_list",
    "function_show": "render_function_show",
    "function_frame": "render_function_frame",
    "function_stackvars": "render_function_stackvars",
    "function_callers": "render_function_relations",
    "function_callees": "render_function_relations",
    "disasm": "render_lines",
    "decompile": "render_lines",
    "ctree": "render_lines",
    "search_bytes": "render_search_results",
    "xrefs": "render_xrefs",
    "strings": "render_strings",
    "imports": "render_imports",
    "bookmark_get": "render_bookmarks",
    "bookmark_add": "_fallback",
    "bookmark_set": "_fallback",
    "bookmark_delete": "_fallback",
    "comment_get": "render_comment",
    "comment_set": "_fallback",
    "comment_delete": "_fallback",
    "name_set": "_fallback",
    "local_list": "render_locals",
    "local_rename": "render_locals",
    "local_retype": "render_locals",
    "local_update": "render_locals",
    "proto_get": "render_type_show",
    "proto_set": "_fallback",
    "type_list": "render_types",
    "type_show": "render_type_show",
    "type_declare": "render_type_declare",
    "class_list": "render_class_list",
    "class_candidates": "render_class_candidates",
    "class_show": "render_type_show",
    "class_hierarchy": "render_class_hierarchy",
    "class_fields": "render_class_fields",
    "class_vtable": "render_class_vtable",
    "vtable_dump": "render_vtable_dump",
    "struct_list": "render_types",
    "struct_show": "render_type_show",
    "struct_field_set": "render_type_show",
    "struct_field_rename": "render_type_show",
    "struct_field_delete": "render_type_show",
    "enum_list": "render_types",
    "enum_show": "render_type_show",
    "enum_member_set": "render_type_show",
    "enum_member_rename": "render_type_show",
    "enum_member_delete": "render_type_show",
    "reanalyze": "_fallback",
    "python_exec": "render_python_exec",
    "decompile_bulk": "render_decompile_bulk",
    "workspace_init": "render_workspace_init",
}

_CLI_ONLY_RENDERERS = {"doctor", "docs", "targets_cleanup", "decompile_bulk", "workspace_init"}


def build_text_renderers(namespace: Mapping[str, object]) -> dict[str, Renderer]:
    renderers: dict[str, Renderer] = {}
    for operation, function_name in _RENDERER_NAMES.items():
        renderer = namespace[function_name]
        if not callable(renderer):
            raise TypeError(f"renderer is not callable: {function_name}")
        renderers[operation] = renderer
    return renderers


def renderer_registry_drift(text_renderers: Mapping[str, Renderer]) -> tuple[list[str], list[str]]:
    missing = sorted(set(SUPPORTED_OPERATIONS) - set(text_renderers))
    extra = sorted(set(text_renderers) - set(SUPPORTED_OPERATIONS) - _CLI_ONLY_RENDERERS)
    return missing, extra


__all__ = ["build_text_renderers", "renderer_registry_drift"]
