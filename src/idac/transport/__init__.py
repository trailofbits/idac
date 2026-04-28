from __future__ import annotations

from typing import Any

from .gui import GuiBackend
from .idalib import IdaLibBackend
from .schema import RequestEnvelope


class BackendError(RuntimeError):
    """User-facing transport failure raised after backend normalization."""

    pass


_BACKENDS = {
    "gui": GuiBackend,
    "idalib": IdaLibBackend,
}


def get_backend(name: str) -> GuiBackend | IdaLibBackend:
    """Instantiate the backend selected on the CLI request envelope."""

    backend_cls = _BACKENDS.get(name)
    if backend_cls is None:
        raise BackendError(f"Unsupported backend: {name}")
    return backend_cls()


def send_request(request: RequestEnvelope) -> dict[str, Any]:
    """Dispatch a request and normalize backend runtime errors."""

    backend = get_backend(request.backend)
    try:
        return backend.send(request)
    except RuntimeError as exc:
        raise BackendError(str(exc)) from exc
