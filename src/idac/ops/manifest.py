from __future__ import annotations

from typing import Literal

from .base import OperationSpec
from .families import (
    bookmark_operations,
    class_operations,
    comment_operations,
    database_operations,
    function_operations,
    local_operations,
    misc_operations,
    name_operations,
    named_type_operations,
    prototype_operations,
    search_operations,
    segment_operations,
    type_declare_operations,
)

OperationName = Literal[
    "list_targets",
    "database_info",
    "db_save",
    "segment_list",
    "function_list",
    "function_show",
    "function_frame",
    "function_stackvars",
    "function_callers",
    "function_callees",
    "disasm",
    "decompile",
    "ctree",
    "search_bytes",
    "xrefs",
    "strings",
    "imports",
    "bookmark_get",
    "bookmark_add",
    "bookmark_set",
    "bookmark_delete",
    "comment_get",
    "comment_set",
    "comment_delete",
    "name_set",
    "local_list",
    "local_rename",
    "local_retype",
    "local_update",
    "proto_get",
    "proto_set",
    "type_list",
    "type_show",
    "type_declare",
    "class_list",
    "class_candidates",
    "class_show",
    "class_hierarchy",
    "class_fields",
    "class_vtable",
    "vtable_dump",
    "struct_list",
    "struct_show",
    "struct_field_set",
    "struct_field_rename",
    "struct_field_delete",
    "enum_list",
    "enum_show",
    "enum_member_set",
    "enum_member_rename",
    "enum_member_delete",
    "reanalyze",
    "python_exec",
]

_OPERATION_SPECS: tuple[OperationSpec[object, object], ...] = (
    *database_operations(),
    *segment_operations(),
    *function_operations(),
    *search_operations(),
    *bookmark_operations(),
    *comment_operations(),
    *name_operations(),
    *local_operations(),
    *prototype_operations(),
    *named_type_operations(),
    *type_declare_operations(),
    *class_operations(),
    *misc_operations(),
)

OPERATION_SPEC_MAP: dict[str, OperationSpec[object, object]] = {spec.name: spec for spec in _OPERATION_SPECS}

SUPPORTED_OPERATIONS: tuple[OperationName, ...] = ("list_targets", *tuple(OPERATION_SPEC_MAP))

MUTATING_OPERATIONS: tuple[OperationName, ...] = tuple(
    name for name, spec in OPERATION_SPEC_MAP.items() if spec.mutating
)

PREVIEW_UNSUPPORTED_OPERATIONS: tuple[OperationName, ...] = tuple(
    name for name, spec in OPERATION_SPEC_MAP.items() if spec.mutating and spec.preview is None
)


def operation_specs() -> tuple[OperationSpec[object, object], ...]:
    return _OPERATION_SPECS


__all__ = [
    "MUTATING_OPERATIONS",
    "OPERATION_SPEC_MAP",
    "PREVIEW_UNSUPPORTED_OPERATIONS",
    "SUPPORTED_OPERATIONS",
    "OperationName",
    "operation_specs",
]
