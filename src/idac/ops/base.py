from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .preview import PreviewSpec
    from .runtime import IdaRuntime

Params = Mapping[str, Any]
Runner = Callable[["IdaRuntime", Params], Any]


@dataclass(frozen=True)
class Op:
    run: Runner
    mutating: bool = False
    preview: PreviewSpec | None = None


__all__ = ["Op", "Params", "Runner"]
