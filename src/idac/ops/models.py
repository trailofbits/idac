from __future__ import annotations

from dataclasses import fields, is_dataclass
from typing import Any, Union

JsonScalar = Union[None, bool, int, float, str]
JsonValue = Union[JsonScalar, list["JsonValue"], dict[str, "JsonValue"]]


def payload_from_model(value: Any) -> JsonValue:
    if is_dataclass(value) and not isinstance(value, type):
        return {
            (field.name[:-1] if field.name.endswith("_") else field.name): payload_from_model(
                getattr(value, field.name)
            )
            for field in fields(value)
        }
    if isinstance(value, tuple):
        return [payload_from_model(item) for item in value]
    if isinstance(value, list):
        return [payload_from_model(item) for item in value]
    if isinstance(value, dict):
        return {str(key): payload_from_model(item) for key, item in value.items()}
    return value


__all__ = ["JsonScalar", "JsonValue", "payload_from_model"]
