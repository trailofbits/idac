from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from .preview import PreviewSpec
    from .runtime import IdaRuntime

RequestT = TypeVar("RequestT")
ResultT = TypeVar("ResultT")
Params = Mapping[str, Any]

ParseParams = Callable[[Params], RequestT]
RunOperation = Callable[["OperationContext", RequestT], ResultT]


@dataclass(frozen=True)
class OperationContext:
    runtime: IdaRuntime
    preview: bool = False


@dataclass(frozen=True)
class OperationSpec(Generic[RequestT, ResultT]):
    name: str
    parse: ParseParams[RequestT]
    run: RunOperation[RequestT, ResultT]
    mutating: bool = False
    preview: PreviewSpec[RequestT, ResultT] | None = None

    def parse_params(self, params: Params) -> RequestT:
        return self.parse(params)


__all__ = [
    "OperationContext",
    "OperationSpec",
    "Params",
    "ParseParams",
    "RequestT",
    "ResultT",
    "RunOperation",
]
