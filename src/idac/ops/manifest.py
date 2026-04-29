from __future__ import annotations

from .base import Op
from .families import (
    BOOKMARK_OPS,
    CLASS_OPS,
    COMMENT_OPS,
    DATABASE_OPS,
    FUNCTION_OPS,
    LOCAL_OPS,
    MISC_OPS,
    NAME_OPS,
    NAMED_TYPE_OPS,
    PROTOTYPE_OPS,
    SEARCH_OPS,
    SEGMENT_OPS,
    TYPE_DECLARE_OPS,
)

OPERATIONS: dict[str, Op] = {
    **DATABASE_OPS,
    **SEGMENT_OPS,
    **FUNCTION_OPS,
    **SEARCH_OPS,
    **BOOKMARK_OPS,
    **COMMENT_OPS,
    **NAME_OPS,
    **LOCAL_OPS,
    **PROTOTYPE_OPS,
    **NAMED_TYPE_OPS,
    **TYPE_DECLARE_OPS,
    **CLASS_OPS,
    **MISC_OPS,
}

SUPPORTED_OPERATIONS: tuple[str, ...] = ("list_targets", *OPERATIONS)

MUTATING_OPERATIONS: tuple[str, ...] = tuple(name for name, op in OPERATIONS.items() if op.mutating)

PREVIEW_UNSUPPORTED_OPERATIONS: tuple[str, ...] = tuple(
    name for name, op in OPERATIONS.items() if op.mutating and op.preview is None
)


__all__ = [
    "MUTATING_OPERATIONS",
    "OPERATIONS",
    "PREVIEW_UNSUPPORTED_OPERATIONS",
    "SUPPORTED_OPERATIONS",
]
