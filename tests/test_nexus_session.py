from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

import idac.nexus as nexus_module
from idac.nexus import (
    KEEPALIVE_SECONDS,
    NexusApi,
    NexusSelectionError,
    NexusSession,
    NexusSessionError,
)


class FakeNexusError(RuntimeError):
    pass


class FakeRemoteError(FakeNexusError):
    def __init__(self, operation: str = "broken") -> None:
        super().__init__("remote operation failed")
        self.code = "operation_failed"
        self.status = 409
        self.details = {"operation": operation}


class FakeTimeoutError(FakeNexusError):
    def __init__(self) -> None:
        super().__init__("operation timed out")
        self.code = "operation_timeout"
        self.status = 408
        self.details = {"kind": "remote_module"}


class FakeState(Enum):
    READY = "ready"
    BLOCKED = "blocked"
    DEAD = "dead"


@dataclass(frozen=True)
class FakeInstance:
    record_id: str
    backend: str
    pid: int = 123
    idb_path: str = "/tmp/sample.i64"
    exe_path: str = "/tmp/sample"
    managed: bool = True
    started_at: float = 42.0


@dataclass(frozen=True)
class FakeDiscovered:
    instance: FakeInstance
    state: FakeState = FakeState.READY
    detail: str | None = None


class FakeOptions:
    def __init__(self, **values: object) -> None:
        self.values = values


class FakeHandle:
    def __init__(self, instance: FakeInstance) -> None:
        self.instance = instance
        self.wait_calls: list[float | None] = []
        self.save_calls = 0
        self.close_calls = 0
        self.wait_error: BaseException | None = None
        self.wait_result: dict[str, object] = {"status": "complete", "complete": True}
        self.python_error: BaseException | None = None
        self.save_error: BaseException | None = None
        self.shutdown_error: BaseException | None = None
        self.close_error: BaseException | None = None
        self.shutdown_observer: Callable[[FakeInstance, bool], None] | None = None
        self.save_result: dict[str, object] = {"saved": True, "idb_path": self.instance.idb_path}
        self.remote_environment: dict[str, object] = {
            "ida_nexus": "0.7.0",
            "ida_domain": "0.5.1",
            "ida": "9.4",
            "python": "3.11.9",
        }

    def wait_autoanalysis(self, timeout: float | None = None) -> dict[str, object]:
        self.wait_calls.append(timeout)
        if self.wait_error is not None:
            raise self.wait_error
        return dict(self.wait_result)

    def execute_python(
        self,
        code: str,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
        operation_label: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
    ) -> dict[str, object]:
        if "importlib.metadata.version" in code and "idaapi.get_kernel_version" in code:
            return {
                "result": dict(self.remote_environment),
                "stdout": "",
                "stderr": "",
            }
        if self.python_error is not None:
            raise self.python_error
        return {"result": 7, "stdout": "hello\n", "stderr": ""}

    def save_database(self) -> dict[str, object]:
        self.save_calls += 1
        if self.save_error is not None:
            raise self.save_error
        return dict(self.save_result)

    def shutdown_database(self, *, save: bool = True) -> dict[str, object]:
        if self.shutdown_observer is not None:
            self.shutdown_observer(self.instance, save)
        if self.shutdown_error is not None:
            raise self.shutdown_error
        return {"shutting_down": True, "save": save}

    def close(self, *, wait_for_database: bool = False, timeout: float = 305.0) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


@dataclass
class FakeRuntime:
    discovered: list[FakeDiscovered] = field(default_factory=list)
    open_handle: FakeHandle | None = None
    attached_handle: FakeHandle | None = None
    open_error: BaseException | None = None
    attach_error: BaseException | None = None
    dispatch_errors: dict[str, BaseException] = field(default_factory=dict)
    dispatch_results: dict[str, object] = field(default_factory=dict)
    open_calls: list[tuple[str, FakeOptions]] = field(default_factory=list)
    attach_calls: list[tuple[FakeInstance, float]] = field(default_factory=list)
    discovery_calls: list[float | None] = field(default_factory=list)
    dispatch_calls: list[dict[str, object]] = field(default_factory=list)
    shutdown_requests: list[tuple[FakeInstance, bool]] = field(default_factory=list)
    release_waits: list[tuple[FakeInstance, float | None]] = field(default_factory=list)
    release_wait_result: bool = True


def fake_api(runtime: FakeRuntime) -> NexusApi:
    def observe_shutdowns(handle: FakeHandle) -> FakeHandle:
        handle.shutdown_observer = lambda instance, save: runtime.shutdown_requests.append((instance, save))
        return handle

    class DatabaseHandle:
        @classmethod
        def open(cls, path: str, *, options: FakeOptions) -> FakeHandle:
            runtime.open_calls.append((path, options))
            if runtime.open_error is not None:
                raise runtime.open_error
            assert runtime.open_handle is not None
            return observe_shutdowns(runtime.open_handle)

        @classmethod
        def attach(cls, instance: FakeInstance, *, keepalive: float) -> FakeHandle:
            runtime.attach_calls.append((instance, keepalive))
            if runtime.attach_error is not None:
                raise runtime.attach_error
            if runtime.attached_handle is None:
                runtime.attached_handle = FakeHandle(instance)
            return observe_shutdowns(runtime.attached_handle)

    class RemoteModule:
        def __init__(
            self,
            path: str | Path,
            *,
            codec: str,
            operation_label: Any,
        ) -> None:
            pass

        def function(self, *, database: bool, timeout: float | None):
            def bind(declaration):
                assert declaration.__name__ == "dispatch"

                def invoke(
                    handle: FakeHandle,
                    op: str,
                    params: dict[str, object],
                    preview: bool,
                ) -> object:
                    runtime.dispatch_calls.append(
                        {
                            "handle": handle,
                            "op": op,
                            "params": params,
                            "preview": preview,
                        }
                    )
                    error = runtime.dispatch_errors.get(op)
                    if error is not None:
                        raise error
                    return runtime.dispatch_results.get(op, {"op": op, "params": params, "preview": preview})

                return invoke

            return bind

    def discover_databases(timeout: float | None = None) -> list[FakeDiscovered]:
        runtime.discovery_calls.append(timeout)
        return list(runtime.discovered)

    def wait_database_released(instance: FakeInstance, timeout: float | None = None) -> bool:
        runtime.release_waits.append((instance, timeout))
        return runtime.release_wait_result

    return NexusApi(
        DatabaseHandle=DatabaseHandle,
        DatabaseOpenOptions=FakeOptions,
        RemoteModule=RemoteModule,
        InstanceState=FakeState,
        NexusError=FakeNexusError,
        discover_databases=discover_databases,
        wait_database_released=wait_database_released,
    )


@pytest.fixture
def remote_module_path(tmp_path: Path) -> Path:
    path = tmp_path / "remote_ops.py"
    path.write_text("def dispatch(db, op, params, preview):\n    return {}\n", encoding="utf-8")
    return path


def assert_equivalent_session_error(actual: NexusSessionError, expected: NexusSessionError) -> None:
    assert (actual.kind, str(actual), actual.status, actual.details) == (
        expected.kind,
        str(expected),
        expected.status,
        expected.details,
    )


def assert_worker_retired_without_save(runtime: FakeRuntime, instance: FakeInstance) -> None:
    assert runtime.shutdown_requests == [(instance, False)]
    assert [released for released, _timeout in runtime.release_waits] == [instance]


def test_headless_session_reuses_one_handle_waits_for_analysis_and_saves_mutations(
    remote_module_path: Path,
) -> None:
    instance = FakeInstance("worker-1", "idalib")
    handle = FakeHandle(instance)
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        timeout=12,
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    assert session.execute_operation("function_list", {"limit": 2}) == {
        "op": "function_list",
        "params": {"limit": 2},
        "preview": False,
    }
    session.execute_operation(
        "name_set",
        {"address": "0x401000", "name": "entry"},
        operation_label="idac: name set",
    )
    session.close()

    assert len(runtime.open_calls) == 1
    path, options = runtime.open_calls[0]
    assert path == "/tmp/sample.i64"
    assert options.values["keepalive"] == KEEPALIVE_SECONDS
    assert options.values["auto_analysis"] is True
    assert options.values["startup_timeout"] == 12.0
    assert handle.wait_calls == [12.0]
    assert handle.save_calls == 1
    assert handle.close_calls == 1


def test_exact_gui_instance_is_attached_without_analysis_or_automatic_save(
    remote_module_path: Path,
) -> None:
    instance = FakeInstance("gui-1", "gui", managed=False)
    handle = FakeHandle(instance)
    runtime = FakeRuntime(
        discovered=[FakeDiscovered(instance)],
        attached_handle=handle,
    )

    with NexusSession(
        instance_id="gui-1",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    ) as session:
        session.execute_operation("comment_set", {})

    assert runtime.attach_calls == [(instance, KEEPALIVE_SECONDS)]
    assert handle.wait_calls == []
    assert handle.save_calls == 0
    assert handle.close_calls == 1


def test_failed_gui_preview_is_not_saved_and_reports_uncertain_in_memory_state(
    remote_module_path: Path,
) -> None:
    instance = FakeInstance("gui-1", "gui", managed=False)
    handle = FakeHandle(instance)
    runtime = FakeRuntime(
        discovered=[FakeDiscovered(instance)],
        attached_handle=handle,
        dispatch_errors={"comment_set": FakeRemoteError("comment_set")},
    )

    with (
        pytest.raises(NexusSessionError) as caught,
        NexusSession(
            instance_id="gui-1",
            api=fake_api(runtime),
            remote_module_path=remote_module_path,
        ) as session,
    ):
        session.execute_operation("comment_set", {}, preview=True)

    assert any("unsaved in-memory changes" in note for note in caught.value.__notes__)
    assert handle.save_calls == 0
    assert runtime.shutdown_requests == []
    assert handle.close_calls == 1


def test_omitted_context_selects_the_only_ready_instance() -> None:
    ready = FakeInstance("ready", "gui")
    blocked = FakeInstance("blocked", "idalib")
    runtime = FakeRuntime(
        discovered=[
            FakeDiscovered(blocked, FakeState.BLOCKED, "protocol mismatch"),
            FakeDiscovered(ready),
        ]
    )
    session = NexusSession(api=fake_api(runtime))

    assert session.handle.instance is ready
    assert runtime.attach_calls == [(ready, KEEPALIVE_SECONDS)]
    session.close()


@pytest.mark.parametrize(
    ("discovered", "instance_id", "kind"),
    [
        ([], None, "no_ready_instance"),
        (
            [
                FakeDiscovered(FakeInstance("one", "gui")),
                FakeDiscovered(FakeInstance("two", "idalib")),
            ],
            None,
            "ambiguous_instance",
        ),
        (
            [FakeDiscovered(FakeInstance("blocked", "gui"), FakeState.BLOCKED, "old protocol")],
            "blocked",
            "instance_not_ready",
        ),
        ([FakeDiscovered(FakeInstance("one", "gui"))], "missing", "instance_not_found"),
    ],
)
def test_context_selection_fails_closed(
    discovered: list[FakeDiscovered],
    instance_id: str | None,
    kind: str,
) -> None:
    runtime = FakeRuntime(discovered=discovered)
    session = NexusSession(instance_id=instance_id, api=fake_api(runtime))

    with pytest.raises(NexusSelectionError) as caught:
        _ = session.handle

    assert caught.value.kind == kind
    assert runtime.attach_calls == []


def test_preview_mutation_does_not_mark_headless_session_dirty(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    session.execute_operation("name_set", {}, preview=True)
    session.close()

    assert handle.save_calls == 0
    assert runtime.shutdown_requests == []


def test_failed_preview_poisons_and_discards_headless_session(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    preview_error = FakeRemoteError("comment_set")
    runtime = FakeRuntime(
        open_handle=handle,
        dispatch_errors={"comment_set": preview_error},
    )
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    with pytest.raises(NexusSessionError) as caught:
        session.execute_operation("comment_set", {}, preview=True)
    with pytest.raises(NexusSessionError) as repeated:
        session.execute_operation("database_info", {})
    session.close()

    assert_equivalent_session_error(repeated.value, caught.value)
    assert len(runtime.dispatch_calls) == 1
    assert handle.save_calls == 0
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_failed_preview_checkpoints_prior_headless_mutations_before_discard(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    runtime = FakeRuntime(
        open_handle=handle,
        dispatch_errors={"comment_set": FakeRemoteError("comment_set")},
    )
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    session.execute_operation("name_set", {})
    with pytest.raises(NexusSessionError):
        session.execute_operation("comment_set", {}, preview=True)
    session.close()

    assert handle.save_calls == 1
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_failed_prepreview_checkpoint_is_terminal_and_not_retried(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    session.execute_operation("name_set", {})
    handle.save_error = FakeRemoteError("save_database")
    with pytest.raises(NexusSessionError) as caught:
        session.execute_operation("comment_set", {}, preview=True)
    with pytest.raises(NexusSessionError) as repeated:
        session.execute_operation("database_info", {})
    with pytest.raises(NexusSessionError) as close_error:
        session.close()

    assert_equivalent_session_error(repeated.value, caught.value)
    assert_equivalent_session_error(close_error.value, caught.value)
    assert handle.save_calls == 1
    assert handle.close_calls == 1
    assert [call["op"] for call in runtime.dispatch_calls] == ["name_set"]
    assert_worker_retired_without_save(runtime, handle.instance)


def test_interrupted_remote_request_discards_headless_worker(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    interrupt = KeyboardInterrupt()
    runtime = FakeRuntime(
        open_handle=handle,
        dispatch_errors={"comment_set": interrupt},
    )
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    with pytest.raises(KeyboardInterrupt) as caught:
        session.execute_operation("comment_set", {}, preview=False)
    with pytest.raises(KeyboardInterrupt) as repeated:
        session.execute_operation("database_info", {})
    session.close()

    assert type(caught.value) is KeyboardInterrupt
    assert type(repeated.value) is KeyboardInterrupt
    assert repeated.value.args == caught.value.args
    assert [call["op"] for call in runtime.dispatch_calls] == ["comment_set"]
    assert handle.save_calls == 0
    assert_worker_retired_without_save(runtime, handle.instance)


def test_discard_timeout_remains_visible_on_the_primary_operation_error(
    remote_module_path: Path,
) -> None:
    instance = FakeInstance("worker", "idalib")
    handle = FakeHandle(instance)
    runtime = FakeRuntime(
        open_handle=handle,
        dispatch_errors={"comment_set": FakeRemoteError("comment_set")},
        release_wait_result=False,
    )

    with (
        pytest.raises(NexusSessionError) as caught,
        NexusSession(
            "/tmp/sample.i64",
            api=fake_api(runtime),
            remote_module_path=remote_module_path,
        ) as session,
    ):
        session.execute_operation("comment_set", {}, preview=True)

    assert caught.value.kind == "operation_failed"
    assert any("did not terminate" in note for note in caught.value.__notes__)
    assert handle.save_calls == 0
    assert_worker_retired_without_save(runtime, instance)


def test_interrupt_during_headless_initialization_discards_worker() -> None:
    instance = FakeInstance("worker", "idalib")
    handle = FakeHandle(instance)
    handle.wait_error = KeyboardInterrupt()
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))

    with pytest.raises(KeyboardInterrupt):
        _ = session.handle
    session.close()

    assert handle.close_calls == 1
    assert handle.save_calls == 0
    assert_worker_retired_without_save(runtime, instance)


def test_failed_transactional_mutation_does_not_mark_headless_session_dirty(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    runtime = FakeRuntime(
        open_handle=handle,
        dispatch_results={"type_declare": {"success": False, "errors": 1}},
    )
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    assert session.execute_operation("type_declare", {}) == {"success": False, "errors": 1}
    session.close()

    assert handle.save_calls == 0


def test_prior_successful_mutation_is_saved_when_later_operation_fails(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    runtime = FakeRuntime(
        open_handle=handle,
        dispatch_errors={"comment_set": FakeRemoteError("comment_set")},
    )

    with (
        pytest.raises(NexusSessionError, match="remote operation failed") as caught,
        NexusSession(
            "/tmp/sample.i64",
            api=fake_api(runtime),
            remote_module_path=remote_module_path,
        ) as session,
    ):
        session.execute_operation("name_set", {})
        session.execute_operation("comment_set", {})

    assert caught.value.kind == "operation_failed"
    assert caught.value.status == 409
    assert caught.value.details == {"operation": "comment_set"}
    assert handle.save_calls >= 1
    assert handle.close_calls == 1


def test_timed_out_mutation_is_treated_as_uncertain_and_saved_before_release(
    remote_module_path: Path,
) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    runtime = FakeRuntime(
        open_handle=handle,
        dispatch_errors={"name_set": FakeTimeoutError()},
    )
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )

    with pytest.raises(NexusSessionError) as caught:
        session.execute_operation("name_set", {}, operation_label="idac: timed rename")
    session.close()

    assert caught.value.kind == "operation_timeout"
    assert caught.value.status == 408
    assert handle.save_calls == 1
    assert handle.close_calls == 1


def test_explicit_save_normalizes_result_and_prevents_resave() -> None:
    instance = FakeInstance("worker", "idalib")
    handle = FakeHandle(instance)
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))

    result = session.execute_python("result = 7")
    saved = session.save_database()
    session.close()

    assert result == {"result": 7, "stdout": "hello\n", "stderr": ""}
    assert saved == {"saved": True, "path": instance.idb_path}
    assert handle.save_calls == 1
    assert handle.close_calls == 1


def test_final_save_failure_discards_headless_worker_without_retry(remote_module_path: Path) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.save_error = FakeRemoteError()
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )
    session.execute_operation("name_set", {})

    with pytest.raises(NexusSessionError) as caught:
        session.close()
    session.close()

    assert caught.value.kind == "operation_failed"
    assert handle.save_calls == 1
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_interrupted_final_save_discards_headless_worker(remote_module_path: Path) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    interrupt = KeyboardInterrupt()
    handle.save_error = interrupt
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )
    session.execute_operation("name_set", {})

    with pytest.raises(KeyboardInterrupt) as caught:
        session.close()

    assert type(caught.value) is KeyboardInterrupt
    assert caught.value.args == interrupt.args
    assert handle.save_calls == 1
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_explicit_save_failure_is_terminal_and_is_not_retried(remote_module_path: Path) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.save_error = FakeRemoteError("save_database")
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )
    session.execute_operation("name_set", {})

    with pytest.raises(NexusSessionError, match="remote operation failed") as save_error:
        session.save_database()
    with pytest.raises(NexusSessionError) as terminal_error:
        session.execute_operation("function_list", {})
    with pytest.raises(NexusSessionError) as close_error:
        session.close()

    assert_equivalent_session_error(terminal_error.value, save_error.value)
    assert_equivalent_session_error(close_error.value, save_error.value)
    assert handle.save_calls == 1
    assert handle.close_calls == 1
    assert [call["op"] for call in runtime.dispatch_calls] == ["name_set"]
    assert_worker_retired_without_save(runtime, handle.instance)


def test_malformed_save_response_is_terminal_and_is_not_retried(remote_module_path: Path) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.save_result = {"saved": False}
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )
    session.execute_operation("name_set", {})

    with pytest.raises(NexusSessionError, match="did not confirm") as save_error:
        session.save_database()
    with pytest.raises(NexusSessionError) as close_error:
        session.close()

    assert save_error.value.kind == "save_failed"
    assert_equivalent_session_error(close_error.value, save_error.value)
    assert handle.save_calls == 1
    assert handle.close_calls == 1
    assert [call["op"] for call in runtime.dispatch_calls] == ["name_set"]
    assert_worker_retired_without_save(runtime, handle.instance)


def test_save_failure_remains_primary_when_lease_release_also_fails(remote_module_path: Path) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.save_error = FakeRemoteError("save_database")
    handle.close_error = FakeNexusError("lease release failed")
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession(
        "/tmp/sample.i64",
        api=fake_api(runtime),
        remote_module_path=remote_module_path,
    )
    session.execute_operation("name_set", {})

    with pytest.raises(NexusSessionError) as caught:
        session.close()

    assert caught.value.kind == "operation_failed"
    assert caught.value.details == {"operation": "save_database"}
    assert any("lease release failed" in note for note in caught.value.__notes__)
    assert handle.save_calls == 1
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_body_error_remains_primary_when_session_finalization_fails(remote_module_path: Path) -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.save_error = FakeRemoteError("save_database")
    runtime = FakeRuntime(open_handle=handle)

    with (
        pytest.raises(ValueError, match="handler failed") as caught,
        NexusSession(
            "/tmp/sample.i64",
            api=fake_api(runtime),
            remote_module_path=remote_module_path,
        ) as session,
    ):
        session.execute_operation("name_set", {})
        raise ValueError("handler failed")

    assert any("remote operation failed" in note for note in caught.value.__notes__)
    assert handle.save_calls == 1
    assert handle.close_calls == 1


def test_failed_python_attempt_is_checkpointed_before_headless_release() -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.python_error = FakeRemoteError("py_exec")
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))

    with pytest.raises(NexusSessionError, match="remote operation failed"):
        session.execute_python("raise RuntimeError('after a possible mutation')")
    session.close()

    assert handle.save_calls == 1
    assert handle.close_calls == 1


def test_open_error_is_translated_without_retry_or_fallback() -> None:
    runtime = FakeRuntime(open_error=FakeRemoteError())
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))

    with pytest.raises(NexusSessionError) as caught:
        _ = session.handle
    with pytest.raises(NexusSessionError) as repeated:
        _ = session.handle

    assert caught.value.kind == "operation_failed"
    assert_equivalent_session_error(repeated.value, caught.value)
    assert len(runtime.open_calls) == 1
    assert runtime.attach_calls == []


def test_attach_error_is_terminal_without_retry_or_target_fallback() -> None:
    selected = FakeInstance("gui", "gui", managed=False)
    fallback = FakeInstance("other", "gui", managed=False)
    runtime = FakeRuntime(
        discovered=[FakeDiscovered(selected), FakeDiscovered(fallback)],
        attach_error=FakeRemoteError("attach"),
    )
    session = NexusSession(instance_id="gui", api=fake_api(runtime))

    with pytest.raises(NexusSessionError) as caught:
        _ = session.handle
    with pytest.raises(NexusSessionError) as repeated:
        _ = session.handle

    assert caught.value.kind == "operation_failed"
    assert_equivalent_session_error(repeated.value, caught.value)
    assert runtime.attach_calls == [(selected, KEEPALIVE_SECONDS)]


def test_analysis_failure_discards_the_new_headless_worker() -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.wait_error = FakeNexusError("analysis failed")
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))

    with pytest.raises(NexusSessionError, match="analysis failed"):
        _ = session.handle

    assert handle.save_calls == 0
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_incomplete_analysis_response_closes_and_poison_session() -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.wait_result = {"status": "running", "complete": False}
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))

    with pytest.raises(NexusSessionError, match="did not confirm") as caught:
        _ = session.handle
    with pytest.raises(NexusSessionError) as repeated:
        _ = session.handle

    assert caught.value.kind == "analysis_incomplete"
    assert_equivalent_session_error(repeated.value, caught.value)
    assert len(runtime.open_calls) == 1
    assert handle.save_calls == 0
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_remote_environment_mismatch_fails_closed_and_releases_handle() -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    handle.remote_environment["ida_nexus"] = "0.6.0"
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))

    with pytest.raises(NexusSessionError, match=r"ida-nexus must be exactly 0\.7\.0") as caught:
        _ = session.handle
    with pytest.raises(NexusSessionError) as repeated:
        _ = session.handle

    assert caught.value.kind == "unsupported_remote_environment"
    assert_equivalent_session_error(repeated.value, caught.value)
    assert len(runtime.open_calls) == 1
    assert handle.save_calls == 0
    assert handle.close_calls == 1
    assert_worker_retired_without_save(runtime, handle.instance)


def test_list_targets_exposes_only_public_normalized_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    instance = FakeInstance("worker", "idalib")
    runtime = FakeRuntime(discovered=[FakeDiscovered(instance, FakeState.BLOCKED, "protocol mismatch")])
    api = fake_api(runtime)
    monkeypatch.setattr(nexus_module, "load_nexus_api", lambda: api)

    assert nexus_module.list_targets(timeout=2) == [
        {
            "record_id": "worker",
            "state": "blocked",
            "detail": "protocol mismatch",
            "backend": "idalib",
            "pid": 123,
            "idb_path": "/tmp/sample.i64",
            "exe_path": "/tmp/sample",
            "managed": True,
            "started_at": 42.0,
        }
    ]
    assert runtime.discovery_calls == [2.0]
    assert runtime.open_calls == []
    assert runtime.attach_calls == []


def test_constructor_rejects_legacy_or_ambiguous_contexts() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        NexusSession("sample.i64", instance_id="record")
    with pytest.raises(ValueError, match=r"\.idb"):
        NexusSession("sample.idb")
    with pytest.raises(ValueError, match="legacy"):
        NexusSession("pid:123")
    with pytest.raises(ValueError, match="legacy"):
        NexusSession("module:sample")
    with pytest.raises(ValueError, match="positive finite"):
        NexusSession(timeout=0)


def test_closed_session_rejects_further_use_without_remote_io() -> None:
    handle = FakeHandle(FakeInstance("worker", "idalib"))
    runtime = FakeRuntime(open_handle=handle)
    session = NexusSession("/tmp/sample.i64", api=fake_api(runtime))
    _ = session.handle
    session.close()

    with pytest.raises(NexusSessionError) as caught:
        _ = session.handle

    assert caught.value.kind == "session_closed"
    assert len(runtime.open_calls) == 1
    assert handle.close_calls == 1


def test_load_nexus_api_rejects_local_version_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        nexus_module.metadata,
        "version",
        lambda distribution: "0.8.0" if distribution == "ida-nexus" else "0.5.1",
    )

    with pytest.raises(NexusSessionError, match=r"requires exactly 0\.7\.0") as caught:
        nexus_module.load_nexus_api()

    assert caught.value.kind == "unsupported_local_environment"
    assert caught.value.details == {
        "distribution": "ida-nexus",
        "installed": "0.8.0",
        "expected": "0.7.0",
    }
