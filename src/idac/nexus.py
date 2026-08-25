from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from .compatibility import (
    IDA_DOMAIN_VERSION,
    IDA_NEXUS_VERSION,
    REMOTE_ENVIRONMENT_CODE,
    compatibility_mismatches,
)
from .operations import MUTATING_OPERATIONS, REMOTE_OPERATIONS

KEEPALIVE_SECONDS = 300.0
DEFAULT_ANALYSIS_TIMEOUT_SECONDS = 120.0
DISCARD_TIMEOUT_SECONDS = 30.0
REMOTE_OPS_PATH = Path(__file__).with_name("remote_ops.py")


class NexusSessionError(RuntimeError):
    """An ida-nexus failure translated for idac's application boundary."""

    def __init__(
        self,
        message: str,
        *,
        kind: str = "nexus_error",
        status: int | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.details = dict(details or {})


class NexusUnavailableError(NexusSessionError):
    """The pinned ida-nexus client is not importable."""


class NexusSelectionError(NexusSessionError):
    """A context could not be resolved to exactly one READY Nexus instance."""


@dataclass(frozen=True)
class NexusApi:
    """The public ida-nexus objects used by :class:`NexusSession`."""

    DatabaseHandle: Any
    DatabaseOpenOptions: Any
    RemoteModule: Any
    InstanceState: Any
    NexusError: type[BaseException]
    discover_databases: Callable[..., list[Any]]
    wait_database_released: Callable[..., bool]


def load_nexus_api() -> NexusApi:
    """Load only ida-nexus's supported public Python exports."""

    for distribution, expected in (("ida-nexus", IDA_NEXUS_VERSION), ("ida-domain", IDA_DOMAIN_VERSION)):
        try:
            installed = metadata.version(distribution)
        except metadata.PackageNotFoundError as exc:  # pragma: no cover - packaging normally guarantees it
            raise NexusUnavailableError(
                f"{distribution} is unavailable; install idac's pinned runtime dependencies"
            ) from exc
        if installed != expected:
            raise NexusUnavailableError(
                f"unsupported local {distribution} version {installed}; idac requires exactly {expected}",
                kind="unsupported_local_environment",
                details={"distribution": distribution, "installed": installed, "expected": expected},
            )

    try:
        from ida_nexus import (
            DatabaseHandle,
            DatabaseOpenOptions,
            InstanceState,
            NexusError,
            RemoteModule,
            discover_databases,
            wait_database_released,
        )
    except ImportError as exc:  # pragma: no cover - packaging normally guarantees it
        raise NexusUnavailableError("ida-nexus is unavailable; install idac's pinned runtime dependencies") from exc

    return NexusApi(
        DatabaseHandle=DatabaseHandle,
        DatabaseOpenOptions=DatabaseOpenOptions,
        RemoteModule=RemoteModule,
        InstanceState=InstanceState,
        NexusError=NexusError,
        discover_databases=discover_databases,
        wait_database_released=wait_database_released,
    )


def translate_nexus_error(error: BaseException) -> NexusSessionError:
    """Translate a public Nexus exception without depending on CLI types."""

    code = getattr(error, "code", None)
    kind = str(code) if code else _error_kind(type(error).__name__)
    raw_status = getattr(error, "status", None)
    status = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else None
    raw_details = getattr(error, "details", None)
    details = {str(key): value for key, value in raw_details.items()} if isinstance(raw_details, dict) else {}
    message = str(error).strip() or type(error).__name__
    return NexusSessionError(message, kind=kind, status=status, details=details)


def _note_secondary_error(primary: BaseException, secondary: BaseException | None, context: str) -> None:
    """Preserve the primary failure while recording a distinct cleanup failure."""

    if secondary is not None and secondary is not primary:
        primary.add_note(f"{context}: {str(secondary) or secondary.__class__.__name__}")


def list_targets(timeout: float | None = None) -> list[dict[str, object]]:
    """Discover Nexus databases without opening or leasing one."""

    session = NexusSession(timeout=timeout)
    try:
        return session.list_targets()
    finally:
        session.close()


def _error_kind(class_name: str) -> str:
    pieces: list[str] = []
    current = ""
    for character in class_name:
        if character.isupper() and current:
            pieces.append(current)
            current = character.lower()
        else:
            current += character.lower()
    if current:
        pieces.append(current)
    return "_".join(pieces)


def _target_row(discovered: Any) -> dict[str, object]:
    instance = discovered.instance
    return {
        "record_id": instance.record_id,
        "state": discovered.state.value,
        "detail": discovered.detail,
        "backend": instance.backend,
        "pid": instance.pid,
        "idb_path": instance.idb_path,
        "exe_path": instance.exe_path,
        "managed": instance.managed,
        "started_at": instance.started_at,
    }


def dispatch(db: Any, op: str, params: dict[str, object], preview: bool) -> object:
    """Import-safe declaration matched to ``remote_ops.dispatch`` by Nexus."""

    ...


class NexusSession:
    """One lazily acquired Nexus database lease for a top-level idac command."""

    def __init__(
        self,
        locator: str | Path | None = None,
        instance_id: str | None = None,
        timeout: float | None = None,
        *,
        api: NexusApi | None = None,
        remote_module_path: str | Path = REMOTE_OPS_PATH,
    ) -> None:
        if locator is not None and instance_id is not None:
            raise ValueError("locator and instance_id are mutually exclusive")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number or None")

        locator_text = str(locator).strip() if locator is not None else None
        if locator_text == "":
            raise ValueError("locator must not be empty")
        if locator_text is not None:
            lowered = locator_text.lower()
            if lowered.endswith(".idb"):
                raise ValueError("legacy .idb databases are not supported; use .i64")
            if lowered.startswith(("db:", "pid:", "module:")):
                raise ValueError("legacy db:/pid:/module: context selectors are not supported")

        instance_text = instance_id.strip() if instance_id is not None else None
        if instance_text == "":
            raise ValueError("instance_id must not be empty")

        self.locator = locator_text
        self.instance_id = instance_text
        self.timeout = float(timeout) if timeout is not None else None
        self._api = api
        self._remote_module_path = Path(remote_module_path)
        self._handle: Any | None = None
        self._dispatch: Callable[..., object] | None = None
        self._active_operation_label: str | None = None
        self._dirty = False
        self._discard_required = False
        self._closed = False
        self._terminal_error: BaseException | None = None
        self._save_error: BaseException | None = None

    @property
    def handle(self) -> Any:
        """Return the session's single handle, acquiring it on first use."""

        return self._get_handle()

    def execute_operation(
        self,
        op: str,
        params: dict[str, object],
        *,
        preview: bool = False,
        operation_label: str | None = None,
    ) -> object:
        """Dispatch one JSON-native idac operation through ``RemoteModule``."""

        self._ensure_open()
        if not isinstance(op, str) or not op.strip():
            raise ValueError("op must be a non-empty string")
        if not isinstance(params, dict):
            raise TypeError("params must be a dictionary")
        if not isinstance(preview, bool):
            raise TypeError("preview must be a boolean")
        if op not in REMOTE_OPERATIONS:
            raise ValueError(f"unsupported operation: {op}")

        if self._dirty:
            handle = self._get_handle()
            if handle.instance.backend == "idalib":
                # Checkpoint each completed batch step before starting another
                # remote request. If the next request is interrupted and its RPC
                # connection becomes unusable, discarding that worker will not
                # lose already reported successes.
                self.save_database()

        remote_dispatch = self._get_dispatch()
        self._active_operation_label = operation_label or f"idac: {op}"
        try:
            result = self._call_nexus(lambda: remote_dispatch(self._get_handle(), op, dict(params), preview))
        except KeyboardInterrupt as exc:
            self._poison_uncertain_session(
                exc,
                gui_note=(
                    "the interrupted GUI request may have left unsaved in-memory changes; idac did not save them"
                ),
            )
            raise
        except BaseException as exc:
            # A timeout, disconnect, or remote exception can arrive after
            # IDA changed. A failed preview has an especially uncertain
            # rollback outcome: poison the session and discard a headless
            # worker instead of checkpointing possibly preview-only state.
            if op in MUTATING_OPERATIONS:
                if preview:
                    self._poison_uncertain_session(
                        exc,
                        gui_note=(
                            "the failed GUI preview may have left unsaved in-memory changes; "
                            "inspect or undo them in IDA before saving"
                        ),
                    )
                else:
                    self._dirty = True
            raise
        finally:
            self._active_operation_label = None
        failed_result = isinstance(result, dict) and result.get("success") is False
        if op in MUTATING_OPERATIONS and not preview and not failed_result:
            self._dirty = True
        return result

    def execute_python(
        self,
        code: str,
        *,
        filename: str | None = None,
        operation_label: str | None = None,
    ) -> dict[str, object]:
        """Execute Python in a fresh Nexus namespace and return its result envelope."""

        self._ensure_open()
        if not isinstance(code, str) or not code.strip():
            raise ValueError("code must be a non-empty string")
        if self._dirty:
            handle = self._get_handle()
            if handle.instance.backend == "idalib":
                self.save_database()
        # Arbitrary Python can mutate the IDB before it raises or times out, so
        # a headless session must checkpoint the resulting state even when the
        # execution outcome is an error.
        self._dirty = True
        try:
            result = self._call_nexus(
                lambda: self._get_handle().execute_python(
                    code,
                    timeout=self.timeout,
                    operation_label=operation_label or "idac: py exec",
                    persist_globals=False,
                    filename=filename,
                )
            )
        except KeyboardInterrupt as exc:
            self._poison_uncertain_session(
                exc,
                gui_note=(
                    "the interrupted GUI Python request may have left unsaved in-memory changes; idac did not save them"
                ),
            )
            raise
        return result

    def save_database(self) -> dict[str, object]:
        """Explicitly checkpoint the selected database, including GUI databases."""

        self._ensure_open()
        handle = self._get_handle()
        try:
            return self._save_handle(handle)
        except BaseException as exc:
            # A failed save has an uncertain outcome. Do not issue another save
            # from close() or allow later operations to continue on this session.
            self._save_error = exc
            self._terminal_error = exc
            if handle.instance.backend == "idalib":
                self._discard_required = True
            raise

    def _save_handle(self, handle: Any) -> dict[str, object]:
        result = self._call_nexus(handle.save_database)
        if not isinstance(result, dict) or result.get("saved") is not True:
            raise NexusSessionError("Nexus did not confirm that the database was saved", kind="save_failed")
        idb_path = result.get("idb_path")
        if not isinstance(idb_path, str) or not idb_path:
            raise NexusSessionError(
                "Nexus save response did not include an IDB path",
                kind="save_failed",
            )
        self._dirty = False
        return {"saved": True, "path": idb_path}

    def list_targets(self) -> list[dict[str, object]]:
        """Return sanitized public discovery records without acquiring a lease."""

        self._ensure_open()
        discovered = self._call_nexus(self._discover_databases)
        rows = [_target_row(item) for item in discovered]
        return sorted(rows, key=lambda row: str(row["record_id"]))

    def close(self) -> None:
        """Deterministically finalize and release this session once."""

        if self._closed:
            return
        self._closed = True
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        self._dispatch = None

        if self._discard_required and handle.instance.backend == "idalib":
            discard_error: BaseException | None = None
            try:
                self._discard_headless_handle(handle)
            except BaseException as exc:
                discard_error = exc
            if self._save_error is not None:
                _note_secondary_error(
                    self._save_error,
                    discard_error,
                    "discarding the headless worker after save failure also failed",
                )
                raise self._save_error
            if discard_error is not None:
                raise discard_error
            return

        finalization_error = self._save_error
        release_error: BaseException | None = None
        released_after_save_failure = False
        try:
            if finalization_error is None and self._dirty and handle.instance.backend == "idalib":
                try:
                    self._save_handle(handle)
                except BaseException as exc:
                    finalization_error = exc
                    self._save_error = exc
                    self._terminal_error = exc
                    self._discard_required = True
                    released_after_save_failure = True
                    try:
                        self._discard_headless_handle(handle)
                    except BaseException as discard_error:
                        _note_secondary_error(
                            exc,
                            discard_error,
                            "discarding the headless worker after save failure also failed",
                        )
                    raise
        finally:
            if not released_after_save_failure:
                try:
                    self._call_nexus(handle.close)
                except BaseException as exc:
                    release_error = exc

        if finalization_error is not None:
            _note_secondary_error(finalization_error, release_error, "releasing the Nexus lease also failed")
            raise finalization_error
        if release_error is not None:
            raise release_error

    def _discard_headless_handle(self, handle: Any) -> None:
        """Release one poisoned lease and retire that exact worker without saving."""

        instance = handle.instance
        release_error: BaseException | None = None
        try:
            self._call_nexus(handle.close)
        except BaseException as exc:
            release_error = exc

        discard_error: BaseException | None = None
        discard_handle: Any | None = None
        shutdown_requested = False
        try:
            discard_handle = self._call_nexus(lambda: self._nexus.DatabaseHandle.attach(instance, keepalive=0.0))
            deadline = time.monotonic() + DISCARD_TIMEOUT_SECONDS
            while True:
                try:
                    self._call_nexus(lambda: discard_handle.shutdown_database(save=False))
                    shutdown_requested = True
                    break
                except NexusSessionError as exc:
                    remaining = deadline - time.monotonic()
                    if exc.kind not in {"instance_busy", "instance_shared"} or remaining <= 0:
                        raise
                    time.sleep(min(0.05, remaining))
        except BaseException as exc:
            discard_error = exc
        finally:
            if discard_handle is not None:
                try:
                    self._call_nexus(discard_handle.close)
                except BaseException as exc:
                    if discard_error is None:
                        discard_error = exc
                    else:
                        _note_secondary_error(discard_error, exc, "releasing the discard lease also failed")
        if shutdown_requested:
            try:
                released = self._call_nexus(
                    lambda: self._nexus.wait_database_released(
                        instance,
                        timeout=DISCARD_TIMEOUT_SECONDS,
                    )
                )
                if released is not True:
                    raise NexusSessionError(
                        "Nexus headless worker did not terminate after its uncertain state was discarded",
                        kind="discard_timeout",
                        details={"record_id": instance.record_id},
                    )
            except BaseException as exc:
                if discard_error is None:
                    discard_error = exc
                else:
                    _note_secondary_error(discard_error, exc, "waiting for the discarded Nexus worker also failed")
        if discard_error is not None:
            _note_secondary_error(discard_error, release_error, "releasing the Nexus lease also failed")
            raise discard_error
        if release_error is not None:
            raise release_error

    def _poison_uncertain_session(self, error: BaseException, *, gui_note: str) -> None:
        """Prevent further use and select discard semantics for uncertain state."""

        self._dirty = False
        self._discard_required = True
        self._terminal_error = error
        if self._handle is not None and self._handle.instance.backend == "gui":
            error.add_note(gui_note)

    def __enter__(self) -> NexusSession:
        self._ensure_open()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object | None,
    ) -> None:
        if exc is None:
            self.close()
            return
        try:
            self.close()
        except BaseException as close_error:
            _note_secondary_error(exc, close_error, "Nexus session finalization also failed")

    @property
    def _nexus(self) -> NexusApi:
        if self._api is None:
            self._api = load_nexus_api()
        return self._api

    def _get_handle(self) -> Any:
        self._ensure_open()
        if self._handle is not None:
            return self._handle

        try:
            handle = self._call_nexus(self._open_handle)
        except BaseException as exc:
            self._terminal_error = exc
            raise
        self._handle = handle
        try:
            if handle.instance.backend == "idalib":
                analysis_timeout = self.timeout if self.timeout is not None else DEFAULT_ANALYSIS_TIMEOUT_SECONDS
                analysis = self._call_nexus(lambda: handle.wait_autoanalysis(timeout=analysis_timeout))
                if not isinstance(analysis, dict) or analysis.get("complete") is not True:
                    raise NexusSessionError(
                        "Nexus did not confirm that headless autoanalysis completed",
                        kind="analysis_incomplete",
                    )
            self._validate_remote_environment(handle)
        except BaseException as exc:
            try:
                if handle.instance.backend == "idalib":
                    self._discard_headless_handle(handle)
                else:
                    self._call_nexus(handle.close)
            except BaseException as close_error:
                _note_secondary_error(
                    exc,
                    close_error,
                    "releasing the Nexus lease after initialization failure also failed",
                )
            finally:
                self._handle = None
                self._dispatch = None
                self._terminal_error = exc
            raise
        return handle

    def _validate_remote_environment(self, handle: Any) -> None:
        execution = self._call_nexus(
            lambda: handle.execute_python(
                REMOTE_ENVIRONMENT_CODE,
                timeout=self.timeout,
                operation_label="idac: compatibility check",
                persist_globals=False,
                filename="<idac-compatibility>",
            )
        )
        environment = execution.get("result") if isinstance(execution, dict) else None
        if not isinstance(environment, dict):
            raise NexusSessionError(
                "Nexus returned an invalid remote environment response",
                kind="unsupported_remote_environment",
            )
        mismatches = compatibility_mismatches(environment)
        if mismatches:
            raise NexusSessionError(
                "unsupported remote IDA environment: " + "; ".join(mismatches),
                kind="unsupported_remote_environment",
                details={"environment": environment, "mismatches": mismatches},
            )

    def _open_handle(self) -> Any:
        if self.locator is not None:
            option_values: dict[str, object] = {
                "keepalive": KEEPALIVE_SECONDS,
                "auto_analysis": True,
            }
            if self.timeout is not None:
                option_values["startup_timeout"] = self.timeout
            options = self._nexus.DatabaseOpenOptions(**option_values)
            return self._nexus.DatabaseHandle.open(self.locator, options=options)

        instance = self._select_instance()
        return self._nexus.DatabaseHandle.attach(instance, keepalive=KEEPALIVE_SECONDS)

    def _select_instance(self) -> Any:
        discovered = self._discover_databases()
        ready_state = self._nexus.InstanceState.READY
        if self.instance_id is not None:
            matches = [item for item in discovered if item.instance.record_id == self.instance_id]
            if not matches:
                available = ", ".join(sorted(item.instance.record_id for item in discovered)) or "none"
                raise NexusSelectionError(
                    f"Nexus instance {self.instance_id!r} was not found; available record IDs: {available}",
                    kind="instance_not_found",
                )
            selected = matches[0]
            if selected.state != ready_state:
                detail = f": {selected.detail}" if selected.detail else ""
                state = selected.state.value
                raise NexusSelectionError(
                    f"Nexus instance {self.instance_id!r} is {state}{detail}",
                    kind="instance_not_ready",
                )
            return selected.instance

        ready = [item for item in discovered if item.state == ready_state]
        if len(ready) == 1:
            return ready[0].instance
        if not ready:
            unavailable = ", ".join(f"{item.instance.record_id} ({item.state.value})" for item in discovered)
            suffix = f"; discovered: {unavailable}" if unavailable else ""
            raise NexusSelectionError(
                f"no READY Nexus database instance found{suffix}",
                kind="no_ready_instance",
            )
        records = ", ".join(sorted(item.instance.record_id for item in ready))
        raise NexusSelectionError(
            f"multiple READY Nexus database instances found: {records}; pass --instance or --context",
            kind="ambiguous_instance",
        )

    def _discover_databases(self) -> list[Any]:
        if self.timeout is None:
            return self._nexus.discover_databases()
        return self._nexus.discover_databases(timeout=self.timeout)

    def _get_dispatch(self) -> Callable[..., object]:
        if self._dispatch is not None:
            return self._dispatch
        if not self._remote_module_path.is_file():
            raise NexusSessionError(
                f"idac remote operation bundle is missing: {self._remote_module_path}",
                kind="remote_bundle_missing",
            )
        module = self._nexus.RemoteModule(
            self._remote_module_path,
            codec="json",
            operation_label=lambda: self._active_operation_label,
        )
        self._dispatch = module.function(database=True, timeout=self.timeout)(dispatch)
        return self._dispatch

    def _call_nexus(self, action: Callable[[], Any]) -> Any:
        api = self._nexus
        try:
            return action()
        except api.NexusError as exc:
            raise translate_nexus_error(exc) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise NexusSessionError("Nexus session is closed", kind="session_closed")
        if self._terminal_error is not None:
            raise self._terminal_error


__all__ = [
    "DEFAULT_ANALYSIS_TIMEOUT_SECONDS",
    "DISCARD_TIMEOUT_SECONDS",
    "KEEPALIVE_SECONDS",
    "NexusApi",
    "NexusSelectionError",
    "NexusSession",
    "NexusSessionError",
    "NexusUnavailableError",
    "list_targets",
    "load_nexus_api",
    "translate_nexus_error",
]
