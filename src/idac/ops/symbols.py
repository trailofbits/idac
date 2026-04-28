from __future__ import annotations

VTABLE_SYMBOL_PREFIXES = ("__ZTV", "_ZTV", "??_7")
RTTI_TYPEINFO_PREFIXES = ("__ZTI", "_ZTI")
RTTI_NAME_PREFIXES = ("__ZTS", "_ZTS")
RTTI_SYMBOL_PREFIXES = RTTI_TYPEINFO_PREFIXES + RTTI_NAME_PREFIXES


def is_vtable_symbol_name(name: str) -> bool:
    return (name or "").startswith(VTABLE_SYMBOL_PREFIXES)


def is_rtti_symbol_name(name: str) -> bool:
    return (name or "").startswith(RTTI_SYMBOL_PREFIXES)


def classify_symbol_kind(name: str, *, is_function: bool) -> str:
    if is_vtable_symbol_name(name):
        return "vtable_symbol"
    if (name or "").startswith(RTTI_TYPEINFO_PREFIXES):
        return "typeinfo_symbol"
    if (name or "").startswith(RTTI_NAME_PREFIXES):
        return "typeinfo_name_symbol"
    if is_function:
        return "function_symbol"
    return "symbol"


__all__ = [
    "RTTI_NAME_PREFIXES",
    "RTTI_SYMBOL_PREFIXES",
    "RTTI_TYPEINFO_PREFIXES",
    "VTABLE_SYMBOL_PREFIXES",
    "classify_symbol_kind",
    "is_rtti_symbol_name",
    "is_vtable_symbol_name",
]
