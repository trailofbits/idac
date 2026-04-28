from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .base import OperationContext, OperationSpec
from .preview import run_preview


class OperationLookupError(KeyError):
    """Raised when a named operation has not been registered."""


class OperationRegistry:
    def __init__(self, operations: Iterable[OperationSpec[Any, Any]] = ()) -> None:
        self._operations: dict[str, OperationSpec[Any, Any]] = {}
        for operation in operations:
            self.register(operation)

    def register(self, operation: OperationSpec[Any, Any]) -> None:
        if operation.name in self._operations:
            raise ValueError(f"duplicate operation registered: {operation.name}")
        self._operations[operation.name] = operation

    def get(self, name: str) -> OperationSpec[Any, Any]:
        try:
            return self._operations[name]
        except KeyError as exc:
            raise OperationLookupError(name) from exc

    def names(self) -> tuple[str, ...]:
        return tuple(self._operations)

    def execute(
        self,
        name: str,
        *,
        params: Mapping[str, Any],
        context: OperationContext,
    ) -> Any:
        operation = self.get(name)
        request = operation.parse_params(params)
        if context.preview:
            return run_preview(context, name, request, operation.run, operation.preview)
        return operation.run(context, request)


__all__ = ["OperationLookupError", "OperationRegistry"]
